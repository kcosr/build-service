use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use build_service::artifacts::spawn_gc_task;
use build_service::config::Config;
use build_service::http;
use build_service::logging::LoggingSettings;
use build_service::workspace::{spawn_gc_task as spawn_workspace_gc_task, WorkspaceState};

#[derive(Debug, Parser)]
#[command(author, version, about = "Host-side build daemon")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
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

    let workspace_state = Arc::new(WorkspaceState::new(
        config.build.workspace_root.clone(),
        config.build.workspace.clone(),
    ));

    spawn_gc_task(config.clone());
    spawn_workspace_gc_task(Arc::clone(&workspace_state));

    let config = Arc::new(config);

    if let Err(err) = http::run(config, workspace_state).await {
        eprintln!("build-service failed: {err}");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}
