//! Test support shared by the modules' live tests. Compiled only for tests.

use tokio_postgres::{Client, NoTls};

use crate::migrations::{Roles, TENANT, migrate};

/// Roles are cluster-wide and the advisory lock is per database, so two tests migrating their own
/// databases at once race to create `anon`; one at a time here.
static MIGRATING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A fresh, migrated database of its own for one test, or `None` when `PUSH_TEST_DATABASE_URL`
/// is not set (tests/db.sh sets it). Returns the client and the database's URL.
pub async fn fresh_database(name: &str) -> Option<(Client, String)> {
	let admin_url = std::env::var("PUSH_TEST_DATABASE_URL").ok()?;
	let (admin, connection) = tokio_postgres::connect(&admin_url, NoTls).await.unwrap();
	tokio::spawn(connection);
	let database = format!("push_{name}_{}", std::process::id());
	admin
		.batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
		.await
		.unwrap();
	admin
		.batch_execute(&format!("CREATE DATABASE {database}"))
		.await
		.unwrap();
	let url = format!("{}/{database}", admin_url.rsplit_once('/').unwrap().0);
	let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
	tokio::spawn(connection);
	let _one_at_a_time = MIGRATING.lock().await;
	let roles = Roles {
		install_roles: true,
		..Roles::default()
	};
	assert_eq!(
		migrate(&mut client, TENANT, &roles).await.unwrap(),
		TENANT.iter().map(|m| m.id).collect::<Vec<_>>()
	);
	assert!(
		migrate(&mut client, TENANT, &roles)
			.await
			.unwrap()
			.is_empty(),
		"a second run runs nothing"
	);
	Some((client, url))
}
