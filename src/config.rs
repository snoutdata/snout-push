//! The server's configuration, from the environment. Every setting is listed here with its default
//! and whether it is secret; the README's configuration reference is this list (X12).
//!
//! One server serves one project, from inside that project's pod, so there is no admin API and no
//! tenant to pick out of a host name. There are no demo secrets (X13): without its database, its
//! JWT secret and a VAPID contact the server refuses to start, and says which one is missing.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::drain::Plan;
use crate::migrations::Roles;

#[derive(Clone)]
pub struct Config {
	/// `PUSH_PUBLIC_ADDR`, default `0.0.0.0:5200`: the `/push/v1` API, reached through the front door.
	pub public_addr: SocketAddr,
	/// `PUSH_DATABASE_URL` (secret, required): the project's database, as `snout_push_admin`.
	pub database_url: String,
	/// `PUSH_JWT_SECRET` (secret, required): the project's JWT secret, which callers' tokens are
	/// verified with.
	pub jwt_secret: String,
	/// `PUSH_VAPID_SUBJECT` (required): the operator's contact every Web Push request names
	/// (RFC 8292), a `mailto:` or `https:` URL. Never a default of ours.
	pub vapid_subject: String,
	/// `PUSH_POD_MEMORY_MB` (default 512) and `PUSH_SCHEDULING` (default false): the plan.
	/// Concurrency follows the memory (P5); scheduling is for plans that never pause (P4).
	pub plan: Plan,
	/// `PUSH_ANON_ROLE`, `PUSH_AUTHENTICATED_ROLE`, `PUSH_SERVICE_ROLE`: the API roles, defaulting to
	/// `anon`, `authenticated` and `service_role`. `PUSH_INSTALL_ROLES=true` creates them when
	/// missing (self-hosting and tests only).
	pub roles: Roles,
}

/// Never the secrets, not even in a debug print.
impl std::fmt::Debug for Config {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Config")
			.field("public_addr", &self.public_addr)
			.field("vapid_subject", &self.vapid_subject)
			.field("plan", &self.plan)
			.finish_non_exhaustive()
	}
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

impl Config {
	pub fn from_env() -> Result<Self, ConfigError> {
		Self::from_map(&std::env::vars().collect())
	}

	pub fn from_map(env: &HashMap<String, String>) -> Result<Self, ConfigError> {
		let get = |name: &str| {
			env.get(name)
				.map(|v| v.trim().to_string())
				.filter(|v| !v.is_empty())
		};
		let require = |name: &str, what: &str| {
			get(name).ok_or_else(|| {
				ConfigError(format!(
					"{name} is not set: {what}. Snout Push has no default for it."
				))
			})
		};

		let database_url = require("PUSH_DATABASE_URL", "the project's database")?;
		if !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")) {
			return Err(ConfigError(
				"PUSH_DATABASE_URL is a postgres:// URL.".into(),
			));
		}
		let jwt_secret = require(
			"PUSH_JWT_SECRET",
			"the project's JWT secret, which callers' tokens are verified with",
		)?;
		if jwt_secret.len() < 32 {
			return Err(ConfigError(
				"PUSH_JWT_SECRET is at least 32 characters.".into(),
			));
		}
		let vapid_subject = require(
			"PUSH_VAPID_SUBJECT",
			"the contact every Web Push request names",
		)?;
		if !(vapid_subject.starts_with("mailto:") || vapid_subject.starts_with("https://")) {
			return Err(ConfigError(
				"PUSH_VAPID_SUBJECT is a mailto: or https: URL.".into(),
			));
		}
		let public_addr = get("PUSH_PUBLIC_ADDR").unwrap_or_else(|| "0.0.0.0:5200".into());
		let public_addr = public_addr.parse::<SocketAddr>().map_err(|_| {
			ConfigError(format!(
				"PUSH_PUBLIC_ADDR is not an address and port: {public_addr}"
			))
		})?;
		let pod_memory_mb = match get("PUSH_POD_MEMORY_MB") {
			None => 512,
			Some(text) => text.parse::<u32>().map_err(|_| {
				ConfigError(format!(
					"PUSH_POD_MEMORY_MB is a number of megabytes, not {text}"
				))
			})?,
		};
		let scheduling = match get("PUSH_SCHEDULING").as_deref() {
			None | Some("false") => false,
			Some("true") => true,
			Some(other) => {
				return Err(ConfigError(format!(
					"PUSH_SCHEDULING is true or false, not {other}"
				)));
			}
		};
		let defaults = Roles::default();
		Ok(Self {
			public_addr,
			database_url,
			jwt_secret,
			vapid_subject,
			plan: Plan::from_pod(pod_memory_mb, scheduling),
			roles: Roles {
				install_roles: get("PUSH_INSTALL_ROLES").as_deref() == Some("true"),
				anon: get("PUSH_ANON_ROLE").unwrap_or(defaults.anon),
				authenticated: get("PUSH_AUTHENTICATED_ROLE").unwrap_or(defaults.authenticated),
				service: get("PUSH_SERVICE_ROLE").unwrap_or(defaults.service),
			},
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pod() -> HashMap<String, String> {
		[
			(
				"PUSH_DATABASE_URL",
				"postgres://snout_push_admin:pw@127.0.0.1:5432/abcdefghijklm",
			),
			("PUSH_JWT_SECRET", "a-project-secret-of-at-least-32-chars"),
			("PUSH_VAPID_SUBJECT", "mailto:push@snoutdata.com"),
		]
		.into_iter()
		.map(|(k, v)| (k.to_string(), v.to_string()))
		.collect()
	}

	#[test]
	fn a_pod_starts_and_the_defaults_hold() {
		let config = Config::from_map(&pod()).unwrap();
		assert_eq!(config.public_addr.to_string(), "0.0.0.0:5200");
		assert_eq!(config.plan, Plan::from_pod(512, false));
		assert_eq!(config.roles.service, "service_role");
		assert!(!config.roles.install_roles);
	}

	#[test]
	fn nothing_secret_has_a_default() {
		for missing in ["PUSH_DATABASE_URL", "PUSH_JWT_SECRET", "PUSH_VAPID_SUBJECT"] {
			let mut env = pod();
			env.remove(missing);
			let error = Config::from_map(&env).unwrap_err();
			assert!(error.0.contains(missing), "{error}");
		}
		let mut short = pod();
		short.insert("PUSH_JWT_SECRET".into(), "short".into());
		assert!(Config::from_map(&short).is_err());
	}

	#[test]
	fn the_plan_comes_from_the_pod() {
		let mut env = pod();
		env.insert("PUSH_POD_MEMORY_MB".into(), "1024".into());
		env.insert("PUSH_SCHEDULING".into(), "true".into());
		assert_eq!(
			Config::from_map(&env).unwrap().plan,
			Plan::from_pod(1024, true)
		);
		env.insert("PUSH_SCHEDULING".into(), "yes".into());
		assert!(Config::from_map(&env).is_err());
	}

	#[test]
	fn debug_never_prints_a_secret() {
		let printed = format!("{:?}", Config::from_map(&pod()).unwrap());
		assert!(
			!printed.contains("pw@") && !printed.contains("a-project-secret"),
			"{printed}"
		);
	}
}
