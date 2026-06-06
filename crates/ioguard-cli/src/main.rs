use clap::{Parser, Subcommand, ValueEnum};
use ioguard_core::{scan, Direction, ScanOptions, Verdict};
use std::io::{self, Read};
use std::process;

#[derive(Parser)]
#[command(
    name = "ioguard",
    version,
    about = "LLM I/O safety and secret scanning"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan stdin for secrets and safety violations.
    Scan {
        /// Direction of the text (input from user, or output from LLM).
        #[arg(long, default_value = "input")]
        direction: DirectionArg,

        /// Output format (only json is supported).
        #[arg(long, default_value = "json")]
        format: FormatArg,

        /// BCP 47 locale tag (e.g. "ar", "he", "fa", "ur"). RTL locales exempt bidi controls.
        #[arg(long)]
        locale: Option<String>,
    },
}

#[derive(ValueEnum, Clone)]
enum DirectionArg {
    Input,
    Output,
}

#[derive(ValueEnum, Clone)]
enum FormatArg {
    Json,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            direction, locale, ..
        } => {
            let dir = match direction {
                DirectionArg::Input => Direction::Input,
                DirectionArg::Output => Direction::Output,
            };

            let mut input = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut input) {
                let err = serde_json::json!({
                    "error": format!("failed to read stdin: {e}")
                });
                eprintln!("{}", serde_json::to_string(&err).unwrap_or_default());
                process::exit(101);
            }

            let opts = ScanOptions {
                direction: dir,
                locale,
                ..ScanOptions::default()
            };

            let result = scan(&input, &opts);
            let exit_code = match result.verdict {
                Verdict::Allow => 0,
                Verdict::Warn => 10,
                Verdict::Block => 20,
            };

            let json = serde_json::to_string(&result)
                .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {e}"}}"#));
            println!("{json}");
            process::exit(exit_code);
        }
    }
}
