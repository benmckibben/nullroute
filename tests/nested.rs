//! A nullroute started inside a nullroute: the inner one bind-mounts its decoys
//! and resolver files over the outer one's, which only works while the files
//! the outer mounts came from still exist (the kernel refuses to mount over a
//! mount whose file was unlinked: `ENOENT`). So the outer one must not delete
//! them early.

use std::process::{Command, Stdio};

fn run(args: &[&str], script: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .arg("run")
        .args(args)
        .arg("--")
        .args(["sh", "-c", script])
        .env("NR", env!("CARGO_BIN_EXE_nullroute"))
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn assert_ok(out: &std::process::Output, want: &str) {
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == want,
        "status {:?}, stdout {:?}, stderr {:?}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_nullroute_inside_a_nullroute_starts() {
    assert_ok(&run(&[], "\"$NR\" run -- echo inner-ok"), "inner-ok");
}

#[test]
fn nesting_works_with_the_resolver_files_too_and_three_deep() {
    // --allow mounts a generated resolv.conf at every level.
    let inner = "\"$NR\" run --allow example.com -- sh -c '\"$NR\" run -- echo deep-ok'";
    assert_ok(&run(&["--allow", "example.com"], inner), "deep-ok");
}
