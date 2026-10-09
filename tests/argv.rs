//! Command arguments that aren't UTF-8 must reach the command untouched: file
//! names on Linux are bytes, and a build that globs one can't be run through
//! nullroute if nullroute refuses the argument.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::{Command, Stdio};

const BAD: &[u8] = b"\xff\xfe-not-utf8-\x80";

#[test]
fn a_non_utf8_argument_reaches_the_command_intact() {
    let bad = OsString::from_vec(BAD.to_vec());
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "printf %s \"$1\" | od -An -v -tx1",
            "sh",
        ])
        .arg(&bad)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    let hex: Vec<u8> = String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect();
    assert_eq!(hex, BAD);
}

#[test]
fn a_non_utf8_program_name_is_run_and_reported_not_rejected() {
    let mut name = b"/definitely/not/a/command-".to_vec();
    name.extend_from_slice(b"\xff");
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--"])
        .arg(OsString::from_vec(name))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // Not clap's "invalid UTF-8" (2): it was looked up and not found.
    assert_eq!(o.status.code(), Some(127), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("failed to run"), "{err}");
}

#[test]
fn the_report_json_carries_a_non_utf8_argument_as_replacement_characters() {
    let dir = std::env::temp_dir().join(format!("nr-argv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let json = dir.join("r.json");
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(["run", "--report-json"])
        .arg(&json)
        .args(["--", "true"])
        .arg(OsString::from_vec(BAD.to_vec()))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    let body = std::fs::read(&json).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    // Valid UTF-8 JSON, the bad bytes as U+FFFD.
    let text = String::from_utf8(body).expect("the report must be valid UTF-8");
    assert!(
        text.contains("\u{fffd}\u{fffd}-not-utf8-\u{fffd}"),
        "{text}"
    );
}
