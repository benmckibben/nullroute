//! The code that runs in the forked child between fork and exec (pre_exec, the
//! signal sentinel) may only make async-signal-safe calls: in particular it
//! must not allocate or take a lock, because another thread of the parent could
//! have held the allocator's lock at the moment of the fork. `io::Error::other`
//! and `io::Error::new` with a message allocate; `from_raw_os_error` and
//! `last_os_error` don't.
//!
//! This scans the bodies of the functions on that path for the usual
//! allocating or locking constructs. It is a guard against regressions, not a
//! proof: review changes to these functions with the invariant in mind (the
//! SAFETY comment at the pre_exec call in sandbox.rs lists it).

use std::path::Path;

/// (source file, function) pairs that run in the child.
const CHILD_PATH: &[(&str, &str)] = &[
    ("dns.rs", "add_pool_address"),
    ("hide.rs", "apply_in_child"),
    ("forward.rs", "listen_and_send"),
    ("forward.rs", "send_chunk"),
    ("forward.rs", "create"),
    ("lifecycle.rs", "die_with_parent"),
    ("signals.rs", "open_parent_status"),
    ("signals.rs", "restore"),
    ("signals.rs", "parent_pending"),
    ("signals.rs", "feed"),
    ("signals.rs", "finish"),
    ("signals.rs", "sentinel_main"),
    ("tmpdir.rs", "run"),
    ("sandbox.rs", "write_file"),
    ("sandbox.rs", "loopback_up"),
];

const FORBIDDEN: &[&str] = &[
    "io::Error::other(",
    "io::Error::new(",
    "Error::new(",
    "format!(",
    ".to_string()",
    ".to_owned()",
    "String::",
    "vec!",
    "Vec::",
    "Box::",
    "CString::new",
    ".collect",
    ".lock()",
    "Mutex",
    "diagln!",
    "diag!",
    "std::fs::",
    "println!",
];

/// The body (between the outermost braces) of `fn name` in `src`, without
/// comments.
fn body_of(src: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}(");
    let start = src.find(&needle)?;
    let open = start + src[start..].find('{')?;
    let mut depth = 0usize;
    let mut end = None;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &src[open..=end?];
    Some(
        body.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn offences(body: &str) -> Vec<&'static str> {
    FORBIDDEN
        .iter()
        .copied()
        .filter(|f| body.contains(f))
        .collect()
}

#[test]
fn the_child_side_functions_contain_no_allocating_or_locking_constructs() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut bad = Vec::new();
    for (file, func) in CHILD_PATH {
        let text = std::fs::read_to_string(src.join(file)).unwrap();
        // Only the non-test part of the file.
        let text = text.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let body = body_of(text, func)
            .unwrap_or_else(|| panic!("function {func} not found in {file}: update CHILD_PATH"));
        for f in offences(&body) {
            bad.push(format!("{file}: fn {func} uses {f}"));
        }
    }
    assert!(
        bad.is_empty(),
        "the code between fork and exec must not allocate or lock:\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_scanner_finds_what_it_is_looking_for() {
    let src = "fn bad() -> io::Result<()> {\n    // io::Error::other(\"in a comment\")\n    Err(io::Error::other(\"x\"))\n}\nfn good() -> io::Result<()> {\n    Err(io::Error::from_raw_os_error(5))\n}\n";
    assert_eq!(
        offences(&body_of(src, "bad").unwrap()),
        ["io::Error::other("]
    );
    assert!(offences(&body_of(src, "good").unwrap()).is_empty());
    assert!(body_of(src, "missing").is_none());
}
