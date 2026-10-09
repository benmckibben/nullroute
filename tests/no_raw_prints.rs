//! Guard: non-test code in src/ must not use the raw print macros.
//!
//! `eprintln!` and friends panic when their stream can't be written (a closed
//! pipe, a full disk), which turned a command's exit code into 101 and killed
//! worker threads. Diagnostics go through `diag!` / `diagln!` (src/diag.rs),
//! which ignore write errors. (clippy's print_stderr / print_stdout lints,
//! denied in main.rs, say the same for anyone who runs clippy; this runs with
//! plain `cargo test`.)

use std::path::Path;

const FORBIDDEN: [&str; 5] = ["eprintln!", "eprint!", "println!", "print!", "dbg!"];

/// The part of a source file before its trailing `#[cfg(test)] mod tests`.
fn non_test_part(src: &str) -> &str {
    match src.find("\n#[cfg(test)]\nmod tests") {
        Some(i) => &src[..i],
        None => src,
    }
}

fn offenders(src: &str) -> Vec<(usize, String)> {
    non_test_part(src)
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            let code = l.trim_start();
            !code.starts_with("//") && FORBIDDEN.iter().any(|m| code.contains(m))
        })
        .map(|(i, l)| (i + 1, l.trim().to_string()))
        .collect()
}

#[test]
fn no_raw_print_macros_outside_tests() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut bad = Vec::new();
    let mut files = 0;
    for entry in std::fs::read_dir(&src_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&path).unwrap();
        for (line, code) in offenders(&text) {
            bad.push(format!("{}:{line}: {code}", path.display()));
        }
    }
    assert!(
        files >= 10,
        "found only {files} source files in {src_dir:?}"
    );
    assert!(
        bad.is_empty(),
        "raw print macros in non-test code; use diag!/diagln! (src/diag.rs):\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_guard_itself_catches_offenders_and_skips_test_code() {
    let src = "fn a() {\n    eprintln!(\"x\");\n}\n// println!(\"comment\")\n#[cfg(test)]\nmod tests {\n    fn t() { println!(\"fine\"); }\n}\n";
    assert_eq!(offenders(src), vec![(2, "eprintln!(\"x\");".to_string())]);
    assert!(offenders("fn a() { diagln!(\"x\"); }\n").is_empty());
}
