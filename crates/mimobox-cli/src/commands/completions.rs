use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{Shell as ClapShell, generate};

use crate::Cli;

#[derive(Debug, Args)]
pub(crate) struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub(crate) shell: Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

pub(crate) fn handle_completions(args: CompletionsArgs) {
    let mut command = Cli::command();
    let shell = match args.shell {
        Shell::Bash => ClapShell::Bash,
        Shell::Zsh => ClapShell::Zsh,
        Shell::Fish => ClapShell::Fish,
        Shell::Powershell => ClapShell::PowerShell,
    };

    generate(shell, &mut command, "mimobox", &mut std::io::stdout());
}
