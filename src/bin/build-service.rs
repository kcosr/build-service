use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use build_service::config::Config;
use build_service::daemon;
use build_service::logging::LoggingSettings;

#[derive(Debug, Parser)]
#[command(author, version, about = "Host-side build daemon")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let config = match Config::load_from_sources(args.config.as_deref()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("failed to load config: {err}");
            return ExitCode::from(1);
        }
    };

    let logging_settings = match LoggingSettings::from_config(&config.logging) {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("failed to validate logging config: {err}");
            return ExitCode::from(1);
        }
    };

    let _guards = match logging_settings.init_tracing() {
        Ok(guards) => guards,
        Err(err) => {
            eprintln!("failed to init logging: {err}");
            return ExitCode::from(1);
        }
    };

    tracing::info!("build-service starting");

    if let Err(err) = daemon::run(config) {
        eprintln!("build-service failed: {err}");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}
