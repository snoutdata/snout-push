//! The `push` schema in a project's database: run what has not run, refuse what has changed.
//!
//! The same ledger rule as snout-storage's runner (a `migrations` table in the schema, each file's
//! SHA-256, one transaction per file with its ledger row, an advisory lock around the whole run),
//! written for the `push` schema. Both belong in snout-common once a third component needs one;
//! until then this is the copy, kept in step by reading storage's when either changes.
//!
//! The files are written in the own layout's names (`snout_identity.people`, the `snout_*` roles
//! their settings fall back to), and a database still in the old layout is given them in its own
//! names by `layout::sql_from_new`, statement for statement what it was given before.

use std::borrow::Cow;

use tokio_postgres::Client;

pub struct Migration {
	pub id: i32,
	pub name: &'static str,
	pub sql: &'static str,
	/// The hashes this file had when an earlier release applied it, from before a reword of its
	/// COMMENTS or before it was written in the own layout's names. Still accepted, so a database
	/// migrated then is not refused; the statements in the file never change.
	pub released_as: &'static [&'static str],
	/// Written to run as it is in either layout (it asks the database which one it is), so it is
	/// never spelled back.
	pub either_layout: bool,
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

	/// The statements to run in a database in the new (`true`) or old layout.
	pub fn sql_for(&self, new: bool) -> Cow<'static, str> {
		if self.either_layout {
			return Cow::Borrowed(self.sql);
		}
		crate::layout::sql_from_new(self.sql, new, MIGRATIONS)
	}
}

/// What a migration file is spelled back for: the role names its settings fall back to
/// (`coalesce(..., 'snout_app')`) and the people table it links to.
const MIGRATIONS: crate::layout::Rewrite<'static> = crate::layout::Rewrite {
	bare: &[],
	roles: true,
};

/// A migration's statements are never edited once released: a change is a new file with the next
/// id. Rewording a comment changes the hash, so the old hash goes in `released_as`.
pub const TENANT: &[Migration] = &[
	Migration {
		id: 1,
		name: "push",
		sql: include_str!("../migrations/tenant/0001-push.sql"),
		released_as: &[
			// 0.1.0-0.1.2, before its comments stopped pointing at internal documents.
			"50e9add430dcd22948e9e145223484414bbcee15d7f1cc1313d63daad4e41331",
			// From 2026-10-05, in the old layout's names (in no release; a local build may have it).
			"f527cc87dc96fd98c643aca3eff183b77433b1b4cabb8f988565cab8267dd852",
		],
		either_layout: false,
	},
	Migration {
		id: 2,
		name: "owner-and-auth-link",
		sql: include_str!("../migrations/tenant/0002-owner-and-auth-link.sql"),
		// 0.1.1-0.1.2, written in the old layout's names.
		released_as: &["2720c6f4425bf724ab7008c431b747ce4e0f32b241be02f60396870e50e90afd"],
		either_layout: false,
	},
	Migration {
		id: 3,
		name: "auth-link-in-either-layout",
		sql: include_str!("../migrations/tenant/0003-auth-link-in-either-layout.sql"),
		released_as: &[],
		either_layout: true,
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

impl Roles {
	/// The roles as a database names them (`layout.rs`): the new names where it has them, where
	/// grants go to them and never to the old names it keeps as aliases. A role of the operator's
	/// own is kept as it is.
	pub fn in_database(&self, has_new: bool) -> Roles {
		let named = |role: &str| crate::layout::role_in_database(role, has_new).to_string();
		Roles {
			install_roles: self.install_roles,
			anon: named(&self.anon),
			authenticated: named(&self.authenticated),
			service: named(&self.service),
		}
	}
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

/// Runs whatever of `migrations` this database has not run, and returns the ids it ran. `new`: the
/// database is in the own layout (it has the new role names).
pub async fn migrate(
	client: &mut Client,
	migrations: &[Migration],
	roles: &Roles,
	new: bool,
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
	let outcome = run_locked(client, migrations, roles, new).await;
	let _ = client
		.execute("SELECT pg_advisory_unlock($1)", &[&LOCK_KEY])
		.await;
	outcome
}

async fn run_locked(
	client: &mut Client,
	migrations: &[Migration],
	roles: &Roles,
	new: bool,
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
			client.batch_execute(&migration.sql_for(new)).await?;
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
		assert!(
			TENANT
				.iter()
				.all(|m| !m.released_as.contains(&m.hash().as_str()))
		);
		assert!(
			TENANT
				.iter()
				.flat_map(|m| m.released_as)
				.all(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
		);
	}

	#[test]
	fn the_files_are_in_the_new_names_and_spelled_back_for_an_old_database() {
		for m in TENANT {
			assert!(matches!(m.sql_for(true), Cow::Borrowed(_)), "{}", m.name);
		}
		let first = TENANT[0].sql;
		for made in [
			"current_setting('push.anon_role', true), ''), 'snout_app')",
			"to_regclass('snout_identity.people') IS NULL",
			"REFERENCES snout_identity.people (id) ON DELETE CASCADE",
		] {
			assert!(first.contains(made), "{made}");
		}
		let old = TENANT[0].sql_for(false);
		for made in [
			"current_setting('push.anon_role', true), ''), 'anon')",
			"current_setting('push.service_role', true), ''), 'service_role')",
			"to_regclass('auth.users') IS NULL",
			"REFERENCES auth.users (id) ON DELETE CASCADE",
		] {
			assert!(old.contains(made), "{made}");
		}
		for m in TENANT.iter().filter(|m| !m.either_layout) {
			// Spelled back and over again, the file is itself.
			assert_eq!(
				crate::layout::sql_in_layout(&m.sql_for(false), true, MIGRATIONS),
				m.sql,
				"{}",
				m.name
			);
		}
		// The link in either layout asks the database, and runs as written in both.
		let either = TENANT.iter().find(|m| m.either_layout).map(|m| m.id);
		assert_eq!(either, Some(3));
		assert!(matches!(TENANT[2].sql_for(false), Cow::Borrowed(_)));
	}

	/// Against a real Postgres (`tests/db.sh`): a database in the new layout is migrated in its
	/// names, and one an earlier release migrated, in either layout, is neither refused nor migrated
	/// again.
	#[tokio::test]
	async fn either_layout_and_an_earlier_release() {
		let Some((client, url)) = crate::testing::fresh_database("released").await else {
			return;
		};
		drop(client);
		let admin_url = std::env::var("PUSH_TEST_DATABASE_URL").unwrap_or_default();
		let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls)
			.await
			.unwrap();
		tokio::spawn(connection);
		admin
			.batch_execute(
				"DO $$ BEGIN
				   IF to_regrole('snout_app') IS NULL THEN CREATE ROLE snout_app NOLOGIN NOINHERIT; END IF;
				   IF to_regrole('snout_member') IS NULL THEN CREATE ROLE snout_member NOLOGIN NOINHERIT; END IF;
				   IF to_regrole('snout_server') IS NULL THEN CREATE ROLE snout_server NOLOGIN NOINHERIT BYPASSRLS; END IF;
				 END $$;",
			)
			.await
			.unwrap();
		let base = url
			.rsplit_once('/')
			.map(|(b, _)| b.to_string())
			.unwrap_or_default();
		let pid = std::process::id();
		for (layout, new) in [
			("new", true),
			("old_released", false),
			("new_released", true),
		] {
			let name = format!("push_layout_{layout}_{pid}");
			for statement in [
				format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
				format!("CREATE DATABASE {name}"),
			] {
				admin.batch_execute(&statement).await.unwrap();
			}
			let (mut client, connection) =
				tokio_postgres::connect(&format!("{base}/{name}"), tokio_postgres::NoTls)
					.await
					.unwrap();
			tokio::spawn(connection);
			let roles = Roles::default().in_database(new);
			if layout.ends_with("released") {
				// What an earlier release did: the same statements, and the hashes it recorded.
				client
					.batch_execute(
						"CREATE SCHEMA push; CREATE TABLE push.migrations (\
						 id integer PRIMARY KEY, name text NOT NULL, hash text NOT NULL, \
						 executed_at timestamptz NOT NULL DEFAULT now())",
					)
					.await
					.unwrap();
				for m in TENANT {
					client.batch_execute(&m.sql_for(new)).await.unwrap();
					let recorded = m
						.released_as
						.first()
						.map_or_else(|| m.hash(), |h| h.to_string());
					client
						.execute(
							"INSERT INTO push.migrations (id, name, hash) VALUES ($1, $2, $3)",
							&[&m.id, &m.name, &recorded],
						)
						.await
						.unwrap();
				}
				let ran = migrate(&mut client, TENANT, &roles, new)
					.await
					.unwrap_or_else(|e| panic!("{layout}: {e}"));
				assert!(ran.is_empty(), "{layout}: ran {ran:?} again");
			} else {
				let ran = migrate(&mut client, TENANT, &roles, new).await.unwrap();
				assert_eq!(ran, [1, 2, 3], "{layout}");
				let granted: bool = client
					.query_one(
						"SELECT has_schema_privilege('snout_member', 'push', 'USAGE') \
						 AND NOT has_schema_privilege('authenticated', 'push', 'USAGE')",
						&[],
					)
					.await
					.unwrap()
					.get(0);
				assert!(granted, "{layout}: granted to the new names");
			}
			drop(client);
			admin
				.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
				.await
				.unwrap();
		}
	}

	#[test]
	fn roles_are_passed_as_the_database_names_them() {
		let roles = Roles {
			install_roles: true,
			service: "my_server".into(),
			..Roles::default()
		};
		let new = roles.in_database(true);
		assert_eq!(
			(
				new.anon.as_str(),
				new.authenticated.as_str(),
				new.service.as_str()
			),
			("snout_app", "snout_member", "my_server")
		);
		assert!(new.install_roles);
		let old = Roles::default().in_database(false);
		assert_eq!(
			(
				old.anon.as_str(),
				old.authenticated.as_str(),
				old.service.as_str()
			),
			("anon", "authenticated", "service_role")
		);
		assert_eq!(Roles::default().in_database(true).service, "snout_server");
	}

	#[test]
	fn the_auth_link_finds_people_in_either_layout() {
		let link = TENANT
			.iter()
			.find(|m| m.id == 3)
			.map(|m| m.sql)
			.unwrap_or("");
		for part in [
			"CREATE OR REPLACE FUNCTION push.link_auth()",
			"'snout_identity.people'",
			"'auth.users'",
			"NOT VALID', target)",
			"VALIDATE CONSTRAINT devices_user_fk",
		] {
			assert!(link.contains(part), "{part}");
		}
	}

	/// Against a real Postgres (`tests/db.sh`): the link is made to whichever table the database
	/// keeps its people in, and not at all where there is none.
	#[tokio::test]
	async fn the_auth_link_is_made_in_either_layout() {
		for (name, setup, target) in [
			(
				"link_old",
				"CREATE SCHEMA auth; CREATE TABLE auth.users (id uuid PRIMARY KEY)",
				"auth.users",
			),
			(
				"link_new",
				"CREATE SCHEMA snout_identity; CREATE TABLE snout_identity.people (id uuid PRIMARY KEY)",
				"snout_identity.people",
			),
			("link_none", "", ""),
		] {
			let Some((client, _)) = crate::testing::fresh_database(name).await else {
				return;
			};
			client.batch_execute(setup).await.unwrap();
			client
				.batch_execute("SELECT push.link_auth()")
				.await
				.unwrap();
			let referenced: Vec<String> = client
				.query(
					"SELECT confrelid::regclass::text FROM pg_constraint \
					 WHERE conname IN ('devices_user_fk', 'topic_members_user_fk') AND convalidated",
					&[],
				)
				.await
				.unwrap()
				.iter()
				.map(|r| r.get(0))
				.collect();
			if target.is_empty() {
				assert!(referenced.is_empty(), "{name}");
			} else {
				assert_eq!(referenced, [target, target], "{name}");
			}
		}
	}
}
