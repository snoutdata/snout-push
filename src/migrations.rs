//! The `push` schema in a project's database: run what has not run, refuse what has changed.
//!
//! The same ledger rule as snout-storage's runner (a `migrations` table in the schema, each file's
//! SHA-256, one transaction per file with its ledger row, an advisory lock around the whole run),
//! written for the `push` schema. Both belong in snout-common once a third component needs one;
//! until then this is the copy, kept in step by reading storage's when either changes.

use tokio_postgres::Client;

pub struct Migration {
	pub id: i32,
	pub name: &'static str,
	pub sql: &'static str,
	/// The hashes this file had when an earlier release applied it, from before a reword of its
	/// COMMENTS. Still accepted, so a database migrated then is not refused; the statements in
	/// the file never change.
	pub released_as: &'static [&'static str],
}

impl Migration {
	pub fn hash(&self) -> String {
		let digest = ring::digest::digest(&ring::digest::SHA256, self.sql.as_bytes());
		digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
	}

	/// Whether a ledger row's hash is this migration: today's file, or the file as released before
	/// its comments were reworded.
	pub fn accepts(&self, hash: &str) -> bool {
		hash == self.hash() || self.released_as.contains(&hash)
	}
}

/// A migration's statements are never edited once released: a change is a new file with the next
/// id. Rewording a comment changes the hash, so the old hash goes in `released_as`.
pub const TENANT: &[Migration] = &[
	Migration {
		id: 1,
		name: "push",
		sql: include_str!("../migrations/tenant/0001-push.sql"),
		// 0.1.0-0.1.2, before its comments stopped pointing at internal documents.
		released_as: &["50e9add430dcd22948e9e145223484414bbcee15d7f1cc1313d63daad4e41331"],
	},
	Migration {
		id: 2,
		name: "owner-and-auth-link",
		sql: include_str!("../migrations/tenant/0002-owner-and-auth-link.sql"),
		released_as: &[],
	},
];

/// "snout-pu", so it collides with no other advisory lock by accident.
const LOCK_KEY: i64 = 0x736e_6f75_742d_7075;

#[derive(Debug, Clone)]
pub struct Roles {
	pub install_roles: bool,
	pub anon: String,
	pub authenticated: String,
	pub service: String,
}

impl Default for Roles {
	fn default() -> Self {
		Self {
			install_roles: false,
			anon: "anon".into(),
			authenticated: "authenticated".into(),
			service: "service_role".into(),
		}
	}
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
	#[error("database: {}", .0.as_db_error().map_or_else(|| .0.to_string(), |e| e.message().to_string()))]
	Database(#[from] tokio_postgres::Error),
	#[error(
		"migration {id} was applied as '{applied_name}' with hash {applied}, and this server's migration {id} is '{name}' with hash {expected}: the schema was made by something else, or a migration file changed after it ran"
	)]
	Mismatch {
		id: i32,
		name: String,
		applied_name: String,
		applied: String,
		expected: String,
	},
	#[error("migration {id} ({name}) failed and was rolled back; nothing after it ran: {reason}")]
	Failed {
		id: i32,
		name: String,
		reason: String,
	},
}

fn literal(value: &str) -> String {
	format!("'{}'", value.replace('\'', "''"))
}

/// Runs whatever of `migrations` this database has not run, and returns the ids it ran.
pub async fn migrate(
	client: &mut Client,
	migrations: &[Migration],
	roles: &Roles,
) -> Result<Vec<i32>, MigrationError> {
	loop {
		let row = client
			.query_one("SELECT pg_try_advisory_lock($1)", &[&LOCK_KEY])
			.await?;
		if row.get::<_, bool>(0) {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
	}
	let outcome = run_locked(client, migrations, roles).await;
	let _ = client
		.execute("SELECT pg_advisory_unlock($1)", &[&LOCK_KEY])
		.await;
	outcome
}

async fn run_locked(
	client: &mut Client,
	migrations: &[Migration],
	roles: &Roles,
) -> Result<Vec<i32>, MigrationError> {
	// Looked up first: `CREATE SCHEMA IF NOT EXISTS` checks CREATE on the database before it checks
	// existence, and a pod makes the schema in advance, owned by the role that connects.
	let exists: bool = client
		.query_one(
			"SELECT EXISTS (SELECT FROM pg_namespace WHERE nspname = 'push')",
			&[],
		)
		.await?
		.get(0);
	if !exists {
		client.batch_execute("CREATE SCHEMA push").await?;
	}
	client
		.batch_execute(
			"CREATE TABLE IF NOT EXISTS push.migrations (\
			 id integer PRIMARY KEY, name text NOT NULL, hash text NOT NULL, \
			 executed_at timestamptz NOT NULL DEFAULT now())",
		)
		.await?;

	let mut applied: Vec<(i32, String, String)> = Vec::new();
	for row in client
		.query(
			"SELECT id, name, hash FROM push.migrations ORDER BY id",
			&[],
		)
		.await?
	{
		applied.push((row.get(0), row.get(1), row.get(2)));
	}
	for migration in migrations {
		if let Some((id, name, hash)) = applied.iter().find(|(id, _, _)| *id == migration.id) {
			let expected = migration.hash();
			if !migration.accepts(hash) || name != migration.name {
				return Err(MigrationError::Mismatch {
					id: *id,
					name: migration.name.to_string(),
					applied_name: name.clone(),
					applied: hash.clone(),
					expected,
				});
			}
		}
	}
	let pending: Vec<&Migration> = migrations
		.iter()
		.filter(|m| !applied.iter().any(|(id, _, _)| *id == m.id))
		.collect();
	if pending.is_empty() {
		return Ok(Vec::new());
	}
	client
		.batch_execute(&format!(
			"SELECT set_config('push.install_roles', {}, false), set_config('push.anon_role', {}, false), \
			 set_config('push.authenticated_role', {}, false), set_config('push.service_role', {}, false)",
			literal(if roles.install_roles { "true" } else { "false" }),
			literal(&roles.anon),
			literal(&roles.authenticated),
			literal(&roles.service),
		))
		.await?;

	let mut ran = Vec::new();
	for migration in pending {
		let result: Result<(), tokio_postgres::Error> = async {
			client.batch_execute("START TRANSACTION").await?;
			client.batch_execute(migration.sql).await?;
			client
				.execute(
					"INSERT INTO push.migrations (id, name, hash) VALUES ($1, $2, $3)",
					&[&migration.id, &migration.name, &migration.hash()],
				)
				.await?;
			client.batch_execute("COMMIT").await?;
			Ok(())
		}
		.await;
		if let Err(error) = result {
			let _ = client.batch_execute("ROLLBACK").await;
			let reason = error
				.as_db_error()
				.map_or_else(|| error.to_string(), |e| e.message().to_string());
			return Err(MigrationError::Failed {
				id: migration.id,
				name: migration.name.to_string(),
				reason,
			});
		}
		ran.push(migration.id);
	}
	Ok(ran)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_list_is_ordered_and_unique_and_lf() {
		assert!(TENANT.windows(2).all(|w| w[0].id < w[1].id));
		// The ledger hashes the bytes: a CRLF checkout would make every database look changed.
		assert!(TENANT.iter().all(|m| !m.sql.contains('\r')));
		assert_eq!(TENANT[0].hash().len(), 64);
	}

	#[test]
	fn a_released_hash_is_still_accepted() {
		let first = &TENANT[0];
		assert!(first.accepts(&first.hash()));
		// What 0.1.0-0.1.2 recorded in every database they migrated.
		assert!(first.accepts("50e9add430dcd22948e9e145223484414bbcee15d7f1cc1313d63daad4e41331"));
		assert!(!first.accepts(&"0".repeat(64)));
		// A released hash is an old version of THIS file, never today's.
		assert!(TENANT.iter().all(|m| !m.released_as.contains(&m.hash().as_str())));
		assert!(TENANT.iter().flat_map(|m| m.released_as).all(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())));
	}
}
