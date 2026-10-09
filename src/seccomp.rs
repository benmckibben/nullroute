//! A small seccomp-bpf filter, plus `no_new_privs`, for the sandboxed command.
//!
//! The network namespace only scopes what lives in it. A few kernel interfaces
//! reach outside it (or into the terminal the command was started from) and
//! have no use in a command that is meant to have no network, so the filter
//! closes them. It is deliberately tiny and conservative, not a syscall
//! sandbox: everything not listed here is allowed.
//!
//! - `socket()` with a family that is not scoped to the network namespace and
//!   talks to the hypervisor or to hardware: `AF_VSOCK` (a channel to the host
//!   or a hypervisor on microVMs, WSL2, Hyper-V, Firecracker, Docker Desktop),
//!   `AF_BLUETOOTH`, `AF_NFC`, `AF_QIPCRTR`. Fails with `EAFNOSUPPORT`, which is
//!   what a kernel without the family says. `AF_UNIX`, `AF_INET`, `AF_INET6`,
//!   `AF_NETLINK`, `AF_PACKET` and everything else stay allowed.
//! - `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)`: push input into a terminal. A
//!   command started from a shell shares its controlling terminal, so on kernels
//!   that still allow `TIOCSTI` (`dev.tty.legacy_tiocsti=1`) it could type into
//!   the user's shell: an escape that the network namespace doesn't touch.
//!   Fails with `EPERM`.
//! - `io_uring_setup()`: io_uring can create sockets (`IORING_OP_SOCKET`) without
//!   going through `socket()`, which would walk around the family list. Fails
//!   with `EPERM`, as with `kernel.io_uring_disabled=2`, so programs that use
//!   io_uring already have to cope.
//! - On x86-64, the x32 ABI (system call numbers with bit 30 set) fails with
//!   `ENOSYS`; 32-bit x86 is filtered like the native ABI, except that
//!   `socketcall()` (which hides the family in user memory) fails with `EPERM`.
//!   AArch64 filters its 32-bit ARM mode the same way. Any other ABI gets `ENOSYS`.
//!
//! `no_new_privs` is set first (it is also what lets an unprivileged process
//! install a filter). It is set even with `--no-seccomp`. Inside the user
//! namespace only the caller's own id is mapped, so a setuid-root binary
//! (`sudo`, `su`) never gained anything there; what `no_new_privs` changes is that
//! setuid, setgid and file capabilities can no longer raise privileges after
//! exec (and a nested `nullroute` or any other child inherits that).
//!
//! The program is built before `fork` (allocation); installing it in the
//! child (see [`Filter::install`]) is two `prctl` calls, so it is safe in
//! `pre_exec`. Hand-written rather than a crate: it is about 60 instructions
//! and a dependency would add more than that to audit.

use std::io;

/// One BPF instruction (`struct sock_filter`).
pub type Insn = libc::sock_filter;

/// Families denied by `socket()`, with their numbers (stable kernel ABI;
/// the `libc` crate doesn't define all of them on every target).
pub const DENIED_FAMILIES: [(u32, &str); 4] = [
    (31, "AF_BLUETOOTH"),
    (39, "AF_NFC"),
    (40, "AF_VSOCK"),
    (42, "AF_QIPCRTR"),
];

/// The ioctl requests denied (terminal input injection).
pub const DENIED_IOCTLS: [(u32, &str); 2] = [(0x5412, "TIOCSTI"), (0x541C, "TIOCLINUX")];

/// `io_uring_setup`: the same number on every architecture that has it.
const NR_IO_URING_SETUP: u32 = 425;

/// What the filter returns for a denied call.
const RET_ALLOW: u32 = 0x7fff_0000;
const fn ret_errno(e: i32) -> u32 {
    0x0005_0000 | (e as u32 & 0xffff)
}

// BPF opcodes (linux/bpf_common.h): LD|W|ABS, JMP|JEQ|K, JMP|JGE|K, RET|K.
const OP_LD_ABS: u16 = 0x20;
const OP_JEQ_K: u16 = 0x15;
const OP_JGE_K: u16 = 0x35;
const OP_RET_K: u16 = 0x06;

// Offsets into `struct seccomp_data`: nr (i32), arch (u32), instruction
// pointer (u64), then six u64 arguments. Arguments are read as their low
// 32-bit word, which is how the kernel reads the `int` and `unsigned int`
// parameters used here; this assumes a little-endian target.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0: u32 = 16;
const OFF_ARG1: u32 = 24;

/// The x32 ABI marks its system calls with this bit.
const X32_BIT: u32 = 0x4000_0000;

/// One system call ABI the filter knows how to read.
struct Abi {
    /// `AUDIT_ARCH_*` value in `seccomp_data.arch`.
    arch: u32,
    nr_socket: u32,
    nr_ioctl: u32,
    /// `socketcall` multiplexer (32-bit x86 only).
    nr_socketcall: Option<u32>,
    /// Reject x32 call numbers (native x86-64 only).
    deny_x32: bool,
}

/// Both tables are always compiled so the tests can check each one on any host.
#[allow(dead_code)]
const X86_64_ABIS: &[Abi] = &[
    Abi {
        arch: 0xC000_003E, // AUDIT_ARCH_X86_64
        nr_socket: 41,
        nr_ioctl: 16,
        nr_socketcall: None,
        deny_x32: true,
    },
    Abi {
        arch: 0x4000_0003, // AUDIT_ARCH_I386
        nr_socket: 359,
        nr_ioctl: 54,
        nr_socketcall: Some(102),
        deny_x32: false,
    },
];

#[allow(dead_code)]
const AARCH64_ABIS: &[Abi] = &[
    Abi {
        arch: 0xC000_00B7, // AUDIT_ARCH_AARCH64
        nr_socket: 198,
        nr_ioctl: 29,
        nr_socketcall: None,
        deny_x32: false,
    },
    Abi {
        arch: 0x4000_0028, // AUDIT_ARCH_ARM (EABI, little-endian)
        nr_socket: 281,
        nr_ioctl: 54,
        nr_socketcall: None,
        deny_x32: false,
    },
];

/// The table for this build. nullroute supports x86-64 and AArch64 (see the
/// README); elsewhere there is no filter.
#[cfg(target_arch = "x86_64")]
const ABIS: &[Abi] = X86_64_ABIS;
#[cfg(target_arch = "aarch64")]
const ABIS: &[Abi] = AARCH64_ABIS;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const ABIS: &[Abi] = &[];

/// A compiled filter, ready to install in the forked child.
pub struct Filter {
    prog: Vec<Insn>,
}

impl Filter {
    /// Compile the filter for this architecture. None where there is no ABI
    /// table (see [`ABIS`]).
    pub fn new() -> Option<Filter> {
        if ABIS.is_empty() {
            return None;
        }
        let prog = assemble(ABIS)?;
        u16::try_from(prog.len()).ok()?; // the kernel's limit is 4096 anyway
        Some(Filter { prog })
    }

    /// Set `no_new_privs` and load the filter. Two `prctl` calls and nothing
    /// else, so it is async-signal-safe (no allocation, no locks).
    pub fn install(&self) -> io::Result<()> {
        let fprog = libc::sock_fprog {
            len: self.prog.len() as u16, // checked in new()
            filter: self.prog.as_ptr() as *mut Insn,
        };
        // SAFETY: `fprog` points at `self.prog`, alive for the call; the kernel
        // copies the program and doesn't write to it.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &fprog as *const libc::sock_fprog,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// Only `no_new_privs`, for `--no-seccomp`. A single `prctl` (async-signal-safe).
pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: plain prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Assembler labels: jump targets are resolved after layout.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Label(usize);

enum Op {
    Ld(u32),
    Jeq(u32, Label, Label),
    Jge(u32, Label, Label),
    Ret(u32),
    Here(Label),
}

#[derive(Default)]
struct Asm {
    ops: Vec<Op>,
    labels: usize,
}

impl Asm {
    fn label(&mut self) -> Label {
        self.labels += 1;
        Label(self.labels - 1)
    }

    /// Resolve labels. None if a jump is backwards or doesn't fit in 8 bits
    /// (neither can happen for the program built below).
    fn finish(self) -> Option<Vec<Insn>> {
        let mut at = vec![None; self.labels];
        let mut n = 0usize;
        for op in &self.ops {
            match op {
                Op::Here(l) => at[l.0] = Some(n),
                _ => n += 1,
            }
        }
        let mut out = Vec::with_capacity(n);
        let off = |from: usize, to: Label| -> Option<u8> {
            u8::try_from(at[to.0]?.checked_sub(from + 1)?).ok()
        };
        for op in &self.ops {
            let i = out.len();
            out.push(match *op {
                Op::Here(_) => continue,
                Op::Ld(k) => insn(OP_LD_ABS, 0, 0, k),
                Op::Ret(k) => insn(OP_RET_K, 0, 0, k),
                Op::Jeq(k, t, f) => insn(OP_JEQ_K, off(i, t)?, off(i, f)?, k),
                Op::Jge(k, t, f) => insn(OP_JGE_K, off(i, t)?, off(i, f)?, k),
            });
        }
        Some(out)
    }
}

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

/// Build the program: dispatch on the ABI, then per ABI check the system call
/// number and, for the few that matter, the argument.
fn assemble(abis: &[Abi]) -> Option<Vec<Insn>> {
    let mut a = Asm::default();
    let (enosys, eperm, eafnosupport) = (a.label(), a.label(), a.label());
    let blocks: Vec<Label> = abis.iter().map(|_| a.label()).collect();

    // Which ABI is this?
    a.ops.push(Op::Ld(OFF_ARCH));
    for (abi, &block) in abis.iter().zip(&blocks) {
        let next = a.label();
        a.ops.push(Op::Jeq(abi.arch, block, next));
        a.ops.push(Op::Here(next));
    }
    a.ops.push(Op::Ret(ret_errno(libc::ENOSYS))); // an ABI we can't read: fail closed

    for (abi, &block) in abis.iter().zip(&blocks) {
        let (sock, ioctl) = (a.label(), a.label());
        a.ops.push(Op::Here(block));
        a.ops.push(Op::Ld(OFF_NR));
        if abi.deny_x32 {
            let next = a.label();
            a.ops.push(Op::Jge(X32_BIT, enosys, next));
            a.ops.push(Op::Here(next));
        }
        let mut checks = vec![(NR_IO_URING_SETUP, eperm)];
        checks.extend(abi.nr_socketcall.map(|nr| (nr, eperm)));
        checks.push((abi.nr_socket, sock));
        checks.push((abi.nr_ioctl, ioctl));
        for (nr, target) in checks {
            let next = a.label();
            a.ops.push(Op::Jeq(nr, target, next));
            a.ops.push(Op::Here(next));
        }
        a.ops.push(Op::Ret(RET_ALLOW));

        a.ops.push(Op::Here(sock));
        a.ops.push(Op::Ld(OFF_ARG0));
        for (family, _) in DENIED_FAMILIES {
            let next = a.label();
            a.ops.push(Op::Jeq(family, eafnosupport, next));
            a.ops.push(Op::Here(next));
        }
        a.ops.push(Op::Ret(RET_ALLOW));

        a.ops.push(Op::Here(ioctl));
        a.ops.push(Op::Ld(OFF_ARG1));
        for (request, _) in DENIED_IOCTLS {
            let next = a.label();
            a.ops.push(Op::Jeq(request, eperm, next));
            a.ops.push(Op::Here(next));
        }
        a.ops.push(Op::Ret(RET_ALLOW));
    }

    // Jump targets shared by every ABI.
    for (label, ret) in [
        (enosys, ret_errno(libc::ENOSYS)),
        (eperm, ret_errno(libc::EPERM)),
        (eafnosupport, ret_errno(libc::EAFNOSUPPORT)),
    ] {
        a.ops.push(Op::Here(label));
        a.ops.push(Op::Ret(ret));
    }
    a.finish()
}

/// A one-line description for `--inspect` and `--dry-run`.
pub fn describe() -> String {
    let families: Vec<&str> = DENIED_FAMILIES.iter().map(|(_, n)| *n).collect();
    let ioctls: Vec<&str> = DENIED_IOCTLS.iter().map(|(_, n)| *n).collect();
    format!(
        "no_new_privs; seccomp denies socket({}), ioctl({}), io_uring_setup",
        families.join("/"),
        ioctls.join("/")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `seccomp_data` as the filter sees it.
    struct Call {
        arch: u32,
        nr: u32,
        args: [u64; 6],
    }

    /// A minimal BPF interpreter for the four opcodes the filter uses. Rejects
    /// anything else, backward jumps, jumps out of range and programs that
    /// run off the end without returning.
    fn run(prog: &[Insn], c: &Call) -> u32 {
        let load = |off: u32| -> u32 {
            match off {
                0 => c.nr,
                4 => c.arch,
                16..=60 => {
                    let arg = c.args[((off - 16) / 8) as usize];
                    match (off - 16) % 8 {
                        0 => arg as u32,
                        4 => (arg >> 32) as u32,
                        _ => panic!("unaligned load at {off}"),
                    }
                }
                _ => panic!("load at {off}"),
            }
        };
        let (mut pc, mut acc) = (0usize, 0u32);
        for _ in 0..prog.len() + 1 {
            let i = prog.get(pc).expect("ran off the end of the program");
            match i.code {
                OP_LD_ABS => {
                    acc = load(i.k);
                    pc += 1;
                }
                OP_JEQ_K => pc += 1 + usize::from(if acc == i.k { i.jt } else { i.jf }),
                OP_JGE_K => pc += 1 + usize::from(if acc >= i.k { i.jt } else { i.jf }),
                OP_RET_K => return i.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
        panic!("program does not terminate");
    }

    /// Every ABI table with its compiled program (both architectures, whatever
    /// this test binary runs on).
    fn tables() -> Vec<(&'static [Abi], Vec<Insn>)> {
        [X86_64_ABIS, AARCH64_ABIS]
            .into_iter()
            .map(|abis| (abis, assemble(abis).expect("assembles")))
            .collect()
    }

    fn native() -> &'static Abi {
        &X86_64_ABIS[0]
    }

    fn call(abi: &Abi, nr: u32, args: [u64; 6]) -> Call {
        Call {
            arch: abi.arch,
            nr,
            args,
        }
    }

    #[test]
    fn program_is_well_formed() {
        for (_, prog) in tables() {
            assert!(prog.len() < 200, "{} instructions", prog.len());
            for (i, ins) in prog.iter().enumerate() {
                match ins.code {
                    OP_LD_ABS => assert!(matches!(ins.k, 0 | 4 | 16 | 24), "load of {}", ins.k),
                    OP_RET_K => {}
                    OP_JEQ_K | OP_JGE_K => {
                        // Forward jumps that land inside the program.
                        for off in [ins.jt, ins.jf] {
                            assert!(
                                i + 1 + usize::from(off) < prog.len(),
                                "jump out of range at {i}"
                            );
                        }
                    }
                    other => panic!("unexpected opcode {other:#x} at {i}"),
                }
            }
            assert_eq!(prog.last().map(|i| i.code), Some(OP_RET_K));
            // The first instruction reads the architecture, so nothing is
            // decided on a system call number without knowing which ABI it
            // belongs to.
            assert_eq!((prog[0].code, prog[0].k), (OP_LD_ABS, OFF_ARCH));
            // The kernel accepts at most 4096 instructions.
            assert!(prog.len() <= 4096);
        }
        // The one that gets installed is the one for this build.
        if let Some(f) = Filter::new() {
            assert!(f.prog.len() <= 4096);
        } else {
            assert!(ABIS.is_empty());
        }
    }

    #[test]
    fn denied_socket_families_fail_with_eafnosupport() {
        for (abis, prog) in tables() {
            for abi in abis {
                for (family, name) in DENIED_FAMILIES {
                    let c = call(abi, abi.nr_socket, [u64::from(family), 1, 0, 0, 0, 0]);
                    assert_eq!(
                        run(&prog, &c),
                        ret_errno(libc::EAFNOSUPPORT),
                        "{name} on arch {:#x}",
                        abi.arch
                    );
                    // The kernel reads an int: garbage in the upper half of
                    // the register doesn't make a denied family allowed.
                    let high = 0xdead_beef_0000_0000 | u64::from(family);
                    let c = call(abi, abi.nr_socket, [high, 0, 0, 0, 0, 0]);
                    assert_eq!(run(&prog, &c), ret_errno(libc::EAFNOSUPPORT), "{name} high");
                }
            }
        }
    }

    #[test]
    fn ordinary_socket_families_stay_allowed() {
        for (abis, prog) in tables() {
            for abi in abis {
                for family in [
                    libc::AF_UNIX,
                    libc::AF_INET,
                    libc::AF_INET6,
                    libc::AF_NETLINK,
                    libc::AF_PACKET,
                    libc::AF_ALG,
                    0,
                    100,
                ] {
                    let c = call(abi, abi.nr_socket, [family as u64, 1, 0, 0, 0, 0]);
                    assert_eq!(run(&prog, &c), RET_ALLOW, "family {family}");
                }
            }
        }
    }

    #[test]
    fn terminal_injection_ioctls_fail_with_eperm_others_pass() {
        for (abis, prog) in tables() {
            for abi in abis {
                for (request, name) in DENIED_IOCTLS {
                    let c = call(abi, abi.nr_ioctl, [0, u64::from(request), 0, 0, 0, 0]);
                    assert_eq!(run(&prog, &c), ret_errno(libc::EPERM), "{name}");
                    // Only the low 32 bits are the request.
                    let high = 0xffff_ffff_0000_0000 | u64::from(request);
                    let c = call(abi, abi.nr_ioctl, [0, high, 0, 0, 0, 0]);
                    assert_eq!(run(&prog, &c), ret_errno(libc::EPERM), "{name} high");
                }
                // TIOCGWINSZ, FIONREAD, TCGETS, and zero.
                for request in [0x5413u64, 0x541B, 0x5401, 0] {
                    let c = call(abi, abi.nr_ioctl, [0, request, 0, 0, 0, 0]);
                    assert_eq!(run(&prog, &c), RET_ALLOW, "request {request:#x}");
                }
            }
        }
    }

    #[test]
    fn io_uring_setup_is_denied() {
        for (abis, prog) in tables() {
            for abi in abis {
                let c = call(abi, NR_IO_URING_SETUP, [0; 6]);
                assert_eq!(run(&prog, &c), ret_errno(libc::EPERM));
            }
        }
    }

    #[test]
    fn unrelated_system_calls_are_allowed() {
        for (abis, prog) in tables() {
            for abi in abis {
                // read, write, openat, execve, close...: arbitrary low
                // numbers other than the ones the ABI table names.
                for nr in 0..400u32 {
                    if [abi.nr_socket, abi.nr_ioctl].contains(&nr) || abi.nr_socketcall == Some(nr)
                    {
                        continue;
                    }
                    let c = call(abi, nr, [40, 0x5412, 0, 0, 0, 0]);
                    assert_eq!(run(&prog, &c), RET_ALLOW, "nr {nr} arch {:#x}", abi.arch);
                }
            }
        }
    }

    #[test]
    fn unknown_abis_and_x32_fail_closed() {
        for (_, prog) in tables() {
            let c = Call {
                arch: 0x1234_5678,
                nr: 0,
                args: [0; 6],
            };
            assert_eq!(run(&prog, &c), ret_errno(libc::ENOSYS));
        }
        let (abis, prog) = &tables()[0]; // x86-64
        let c = call(
            native(),
            X32_BIT | 41,
            [libc::AF_VSOCK as u64, 0, 0, 0, 0, 0],
        );
        assert_eq!(run(prog, &c), ret_errno(libc::ENOSYS));
        // socketcall (which hides the family in memory) only exists on i386.
        let i386 = &abis[1];
        let c = call(i386, 102, [1, 0, 0, 0, 0, 0]);
        assert_eq!(run(prog, &c), ret_errno(libc::EPERM));
        assert_eq!(native().nr_socketcall, None);
        // aarch64 has no x32 bit to speak of: a high syscall number is allowed
        // (the kernel answers ENOSYS itself).
        let (abis, prog) = &tables()[1];
        let c = call(&abis[0], X32_BIT | 198, [0; 6]);
        assert_eq!(run(prog, &c), RET_ALLOW);
    }

    #[test]
    fn denied_families_match_the_kernel_numbers() {
        // linux/socket.h
        assert_eq!(libc::AF_BLUETOOTH as u32, 31);
        assert_eq!(libc::AF_VSOCK as u32, 40);
        assert_eq!(DENIED_FAMILIES[0].0, libc::AF_BLUETOOTH as u32);
        assert_eq!(DENIED_FAMILIES[2].0, libc::AF_VSOCK as u32);
        assert_eq!(DENIED_IOCTLS[0].0, libc::TIOCSTI as u32);
    }

    #[test]
    fn describe_names_what_is_denied() {
        let d = describe();
        for want in ["AF_VSOCK", "TIOCSTI", "io_uring_setup", "no_new_privs"] {
            assert!(d.contains(want), "{d}");
        }
    }
}
