//! Diagnostics: the messages nullroute writes for a human (warnings, the live
//! "blocked ..." lines, the summary, error messages, `--inspect`).
//!
//! They must never be able to change what a run does. `eprintln!` panics when
//! stderr can't be written (a pipe whose reader is gone, a full disk, a closed
//! descriptor), and Rust ignores SIGPIPE, so a CI step that closed its log pipe
//! early turned a command that had exited 7 into a nullroute that exited 101;
//! in a worker thread the same panic silently killed the DNS sinkhole or proxy
//! the command depends on. Everything goes through [`diag!`] / [`diagln!`]
//! instead, which drop the message if it can't be written. A lint-style test
//! (tests/no_raw_prints.rs) and a clippy lint (main.rs) keep raw print macros
//! out of the non-test code.
//!
//! The only deliberate exception is the `--dry-run` listing on stdout, which is
//! the command's *result*: it dies by SIGPIPE like `ls` if its reader goes away
//! and reports other write errors with exit 74 (see main.rs).

use std::fmt;
use std::io::Write;

/// Write `args` to stderr, in one `write` so lines from different threads
/// don't interleave, ignoring any error.
pub fn write(args: fmt::Arguments<'_>, newline: bool) {
    let mut s = fmt::format(args);
    if newline {
        s.push('\n');
    }
    let _ = std::io::stderr().lock().write_all(s.as_bytes());
}

/// Like `eprint!`, but ignores write errors.
macro_rules! diag {
    ($($arg:tt)*) => {
        $crate::diag::write(format_args!($($arg)*), false)
    };
}

/// Like `eprintln!`, but ignores write errors.
macro_rules! diagln {
    ($($arg:tt)*) => {
        $crate::diag::write(format_args!($($arg)*), true)
    };
}

pub(crate) use {diag, diagln};
