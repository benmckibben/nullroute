//! --dry-run must not say "fine" for a configuration the real run rejects, and
//! setup failures must not be reported as the command failing to run.

use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};

fn nullroute(args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    // Close inherited fds above 2 so the harness's own sockets don't
    // leak into nullroute's stderr as "inherited from the caller" warnings.
    unsafe {
        c.pre_exec(|| {
            libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
            Ok(())
        });
    }
    c.arg("run")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// 32 pool addresses x 40 ports + the resolver: 1284 listeners, over the limit.
fn too_many_ports() -> String {
    (0..40)
        .map(|i| format!("*.example.com:{}", 8000 + i))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn dry_run_rejects_what_the_real_run_rejects() {
    let allow = too_many_ports();
    let dry = nullroute(&["--dry-run", "--allow", &allow, "--", "true"]);
    let real = nullroute(&["--allow", &allow, "--", "true"]);
    assert_eq!(real.status.code(), Some(125), "{real:?}");
    assert_eq!(dry.status.code(), Some(125), "{dry:?}");
    let (d, r) = (text(&dry.stderr), text(&real.stderr));
    assert!(d.contains("too many listeners (1284 > 1024)"), "{d}");
    assert_eq!(d, r, "dry run and real run explain it differently");
    // Nothing is listed as if it were going to work.
    assert!(text(&dry.stdout).is_empty(), "{}", text(&dry.stdout));
}

#[test]
fn dry_run_checks_the_descriptor_budget_too() {
    // 83 listeners need about 147 descriptors; allow 100.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nullroute"));
    cmd.args(["run", "--dry-run", "--allow"])
        .arg(format!(
            "a.example.com:{}",
            (1..=40)
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ))
        .args(["--", "true"])
        .stdin(Stdio::null());
    // SAFETY: only setrlimit, which is async-signal-safe.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
            let l = libc::rlimit {
                rlim_cur: 100,
                rlim_max: 100,
            };
            libc::setrlimit(libc::RLIMIT_NOFILE, &l);
            Ok(())
        });
    }
    let o = cmd.output().unwrap();
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(125), "{err}");
    assert!(err.contains("file descriptor limit"), "{err}");
}

#[test]
fn a_fine_configuration_still_passes_a_dry_run() {
    let o = nullroute(&[
        "--dry-run",
        "--allow",
        "example.com",
        "--port",
        "5432",
        "--",
        "true",
    ]);
    assert!(o.status.success(), "{o:?}");
    let out = text(&o.stdout);
    assert!(out.contains("forwarded port: 5432"), "{out}");
    assert!(out.contains("allowed host: example.com"), "{out}");
}

#[test]
fn check_sandbox_probes_namespaces_and_leaves_nothing_behind() {
    let o = nullroute(&["--dry-run", "--check-sandbox", "--", "true"]);
    assert!(o.status.success(), "{o:?}");
    // It only makes sense together with --dry-run.
    let o = nullroute(&["--check-sandbox", "--", "true"]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
}

#[test]
fn setup_failures_are_not_reported_as_the_command_failing_to_run() {
    let allow = too_many_ports();
    let o = nullroute(&["--allow", &allow, "--", "true"]);
    let err = text(&o.stderr);
    assert!(
        err.starts_with("nullroute: could not set up the sandbox: "),
        "{err}"
    );
    assert!(!err.contains("failed to run"), "{err}");
    // A command that really can't be started still says so.
    let o = nullroute(&["--", "/definitely/not/a/command"]);
    assert!(text(&o.stderr).contains("failed to run \"/definitely/not/a/command\""));
    assert_eq!(o.status.code(), Some(127));
}
