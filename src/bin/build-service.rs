use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;

use clap::Parser;

use build_service::artifacts;
use build_service::config::Config;
use build_service::logging::LoggingSettings;
use build_service::{daemon, http};

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

    artifacts::spawn_gc_task(config.clone());

    if config.service.http.enabled {
        let shared = Arc::new(config);
        if shared.service.socket.enabled {
            let socket_config = (*shared).clone();
            thread::spawn(move || {
                if let Err(err) = daemon::run(socket_config) {
                    eprintln!("build-service socket failed: {err}");
                }
            });
        }

        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("failed to start runtime: {err}");
                return ExitCode::from(1);
            }
        };

        if let Err(err) = runtime.block_on(http::run(shared)) {
            eprintln!("build-service http failed: {err}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    if config.service.socket.enabled {
        if let Err(err) = daemon::run(config) {
            eprintln!("build-service socket failed: {err}");
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}
