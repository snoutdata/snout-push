//! snout-push: the server, one per project, in that project's pod. Configuration is the
//! environment (`config.rs` lists every setting).

use std::sync::Arc;

use snout_push::api::public_router;
use snout_push::config::Config;
use snout_push::net::Policy;
use snout_push::project::{self, Project};

#[tokio::main]
async fn main() {
	let json = std::env::var("PUSH_LOG_FORMAT").is_ok_and(|v| v == "json");
	let filter =
		tracing_subscriber::EnvFilter::try_from_env("PUSH_LOG").unwrap_or_else(|_| "info".into());
	if json {
		tracing_subscriber::fmt()
			.json()
			.with_env_filter(filter)
			.init();
	} else {
		tracing_subscriber::fmt().with_env_filter(filter).init();
	}

	let config = match Config::from_env() {
		Ok(config) => config,
		Err(error) => {
			eprintln!("snout-push: {error}");
			std::process::exit(2);
		}
	};
	let project = match Project::new(
		&config.database_url,
		config.jwt_secret.clone(),
		config.plan,
		config.vapid_subject.clone(),
		config.roles.clone(),
		Policy::strict(),
	) {
		Ok(project) => Arc::new(project),
		Err(error) => {
			eprintln!("snout-push: {error}");
			std::process::exit(2);
		}
	};
	let listener = match tokio::net::TcpListener::bind(config.public_addr).await {
		Ok(listener) => listener,
		Err(error) => {
			eprintln!(
				"snout-push: cannot listen on {}: {error}",
				config.public_addr
			);
			std::process::exit(1);
		}
	};
	tracing::info!(addr = %config.public_addr, version = env!("CARGO_PKG_VERSION"), "snout-push listening");
	tokio::spawn(project::run(project.clone(), config.database_url.clone()));
	if let Err(error) = axum::serve(listener, public_router(project))
		.with_graceful_shutdown(shutdown())
		.await
	{
		eprintln!("snout-push: {error}");
		std::process::exit(1);
	}
}

async fn shutdown() {
	let interrupt = tokio::signal::ctrl_c();
	#[cfg(unix)]
	{
		let mut terminate =
			tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
				.expect("a SIGTERM handler");
		tokio::select! {
			_ = interrupt => {}
			_ = terminate.recv() => {}
		}
	}
	#[cfg(not(unix))]
	{
		let _ = interrupt.await;
	}
}
