//! The --help text: what it promises has to be what the program does.

use std::process::Command;

fn help(args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_nullroute"))
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn the_command_argument_has_one_name_in_usage_and_arguments() {
    for flag in ["--help", "-h"] {
        let h = help(&["run", flag]);
        assert!(h.contains("-- <COMMAND>..."), "{flag}: {h}");
        assert!(!h.contains("ARGV") && !h.contains("[ARGS]"), "{flag}: {h}");
    }
    assert!(help(&["run", "--help"]).contains("Arguments:\n  <COMMAND>..."));
}

#[test]
fn long_help_is_paragraphs_not_a_wall_of_text() {
    let h = help(&["run", "--help"]);
    // clap wraps to the terminal; what matters is that no flag crams several
    // things into one paragraph.
    let longest = h.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    assert!(longest < 400, "a {longest}-character line in:\n{h}");
    let headings = [
        "\n  -a, --allow <HOST>\n",
        "\n      --strict\n",
        "\n      --report-json <FILE>\n",
        "\n      --dry-run\n",
    ];
    for flag in headings {
        let section = h.split(flag).nth(1).unwrap_or_else(|| panic!("no {flag}"));
        let section = section.split("\n\n      -").next().unwrap_or(section);
        let breaks = section.matches("\n          \n").count();
        assert!(breaks >= 1, "{flag:?} has no paragraph break: {section}");
    }
}

#[test]
fn strict_help_says_what_it_cannot_see() {
    let h = help(&["run", "--help"]);
    assert!(
        h.contains("can't see a connection straight to an IP address"),
        "{h}"
    );
}
