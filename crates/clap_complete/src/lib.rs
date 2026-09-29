use std::io::Write;
use clap::{Command, ValueEnum};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
}

pub trait Generator {
    fn file_name(&self, name: &str) -> String;
    fn generate(&self, cmd: &Command, buf: &mut dyn Write);
}

impl Generator for Shell {
    fn file_name(&self, name: &str) -> String {
        match self {
            Shell::Bash => format!("{}.bash", name),
            Shell::Elvish => format!("{}.elv", name),
            Shell::Fish => format!("{}.fish", name),
            Shell::PowerShell => format!("_{}.ps1", name),
            Shell::Zsh => format!("_{}", name),
        }
    }

    fn generate(&self, cmd: &Command, buf: &mut dyn Write) {
        let bin_name = cmd.get_name();
        let subcmds: Vec<String> = cmd.get_subcommands().map(|sc| sc.get_name().to_string()).collect();
        let opts: Vec<String> = cmd.get_opts().filter_map(|o| o.get_long().map(|l| format!("--{}", l))).collect();
        let all_tokens: Vec<String> = subcmds.iter().cloned().chain(opts.into_iter()).collect();
        let token_list = all_tokens.join(" ");

        match self {
            Shell::Bash => {
                let _ = writeln!(buf, "#!/usr/bin/env bash");
                let _ = writeln!(buf, "_{}() {{", bin_name);
                let _ = writeln!(buf, "    local cur prev words cword");
                let _ = writeln!(buf, "    _init_completion || return");
                let _ = writeln!(buf, "    COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") )", token_list);
                let _ = writeln!(buf, "}}");
                let _ = writeln!(buf, "complete -F _{} {}", bin_name, bin_name);
            }
            Shell::Zsh => {
                let _ = writeln!(buf, "#compdef {}", bin_name);
                let _ = writeln!(buf, "_{}() {{", bin_name);
                let _ = writeln!(buf, "    local -a commands");
                let _ = writeln!(buf, "    commands=({})", token_list);
                let _ = writeln!(buf, "    _describe 'command' commands");
                let _ = writeln!(buf, "}}");
                let _ = writeln!(buf, "_{} \"$@\"", bin_name);
            }
            Shell::Fish => {
                let _ = writeln!(buf, "# fish completion for {}", bin_name);
                for sub in &subcmds {
                    let _ = writeln!(buf, "complete -c {} -a {} -d 'subcommand'", bin_name, sub);
                }
            }
            Shell::PowerShell => {
                let _ = writeln!(buf, "Register-ArgumentCompleter -Native -CommandName {} -ScriptBlock {{", bin_name);
                let _ = writeln!(buf, "    param($wordToComplete, $commandAst, $cursorPosition)");
                let _ = writeln!(buf, "    @({}) | Where-Object {{ $_ -like \"$wordToComplete*\" }}",
                    all_tokens.iter().map(|t| format!("'{}'", t)).collect::<Vec<_>>().join(", "));
                let _ = writeln!(buf, "}}");
            }
            Shell::Elvish => {
                let _ = writeln!(buf, "set edit:completion:arg-completer[{}] = {{|@words|", bin_name);
                let _ = writeln!(buf, "    put {}", all_tokens.iter().map(|t| format!("'{}'", t)).collect::<Vec<_>>().join(" "));
                let _ = writeln!(buf, "}}");
            }
        }
    }
}

pub fn generate<G: Generator, S: Into<String>>(
    generator: G,
    cmd: &mut Command,
    _name: S,
    buf: &mut dyn Write,
) {
    generator.generate(cmd, buf);
}
