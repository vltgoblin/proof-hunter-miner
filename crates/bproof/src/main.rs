#![forbid(unsafe_code)]

mod chain;
mod classification;
mod cli;
mod continuous;
mod mining;
mod output;
mod parse;
mod power;
mod submit;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli::run(cli) {
        Ok(result) => {
            println!("{}", result.output.as_str());
            ExitCode::from(result.exit_code)
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}
