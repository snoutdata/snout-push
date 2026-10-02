//! The one project this server serves, from inside that project's own pod (docs/cloud/PUSH.md,
//! P2 as reversed): everything about its push, keys included, stays in its pod.
//!
//! The runner holds one connection that LISTENs on `snout_push` (a message to send) and
//! `snout_push_credentials` (a key changed), makes a pass on every notification, whenever the API
//! queues something, and when the queue next has something due (a paid project's scheduled send,
//! a retry), at the latest every [`TICK`], and prunes hourly. Its providers are built from the project's own `push.credentials` rows and are
//! rebuilt when those change, so a new APNs key restarts nothing. A database that is not up yet
//! refuses the connection and the runner tries again every [`RECONNECT_MAX`] at most.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Notify, RwLock};
use tokio_postgres::{AsyncMessage, Client, NoTls};

use crate::apns::{self, Environment};
use crate::drain::{self, Plan};
use crate::fcm;
use crate::keys::{EsKey, pem_to_der};
use crate::migrations::{self, Roles};
use crate::net::{Http, Policy};
use crate::notification::NotificationError;
use crate::providers::{Apns, Fcm, Providers, Web};

pub const TICK: Duration = Duration::from_secs(30);
pub const MIN_WAIT: Duration = Duration::from_millis(200);
pub const RECONNECT_MAX: Duration = Duration::from_secs(10);
pub const PRUNE_EVERY: Duration = Duration::from_secs(3600);

/// `push.credentials` for `apns`: the bundle id a device without its own `app` is sent as, and
/// one key for both environments or one per environment (A6).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsBody {
	pub topic: String,
	pub keys: Vec<ApnsKeyBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsKeyBody {
	pub p8: String,
	pub key_id: String,
	pub team_id: String,
	/// `production`, `sandbox`, or absent for a key that serves both.
	#[serde(default)]
	pub environment: Option<String>,
}

/// `push.credentials` for `fcm`: the service-account JSON file, as downloaded.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FcmBody {
	pub service_account: String,
}

/// `push.credentials` for `vapid`: private keys by id (PKCS#8, base64), never rotated in place (A8).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebBody {
	pub keys: HashMap<String, String>,
	pub current: String,
}

pub fn apns_provider(body: &ApnsBody, policy: &Policy) -> Result<Apns, NotificationError> {
	let mut keys = Vec::new();
	for key in &body.keys {
		let environment = match key.environment.as_deref() {
			None => None,
			Some(text) => Some(Environment::parse(text)?),
		};
		keys.push((
			environment,
			apns::Credentials::new(&key.p8, &key.key_id, &key.team_id)?,
		));
	}
	let http = Http::new(policy.clone()).map_err(|e| NotificationError(e.to_string()))?;
	Apns::new(keys, &body.topic, http)
}

pub fn fcm_provider(body: &FcmBody, policy: &Policy) -> Result<Fcm, NotificationError> {
	let http = Http::new(policy.clone()).map_err(|e| NotificationError(e.to_string()))?;
	Ok(Fcm::new(
		fcm::Credentials::from_json(&body.service_account)?,
		http,
	))
}

pub fn web_provider(
	body: &WebBody,
	subject: &str,
	policy: &Policy,
) -> Result<Web, NotificationError> {
	let mut keys = HashMap::new();
	for (id, text) in &body.keys {
		let der = pem_to_der(text).map_err(|e| NotificationError(e.0))?;
		keys.insert(
			id.clone(),
			EsKey::from_pkcs8_der(&der)
				.map_err(|e| NotificationError(format!("VAPID key {id}: {}", e.0)))?,
		);
	}
	let http = Http::new(policy.clone()).map_err(|e| NotificationError(e.to_string()))?;
	Web::new(keys, &body.current, subject, http)
}

/// The providers from the rows of `push.credentials`. A row that no longer builds (a revoked
/// format, a hand edit) leaves its transport unset and says why in the log, rather than taking
/// the other two down with it.
pub fn providers_from(rows: &[(String, Value)], subject: &str, policy: &Policy) -> Providers {
	let mut providers = Providers::default();
	for (kind, value) in rows {
		let built = match kind.as_str() {
			"apns" => serde_json::from_value::<ApnsBody>(value.clone())
				.map_err(|e| NotificationError(e.to_string()))
				.and_then(|b| apns_provider(&b, policy))
				.map(|p| providers.apns = Some(p)),
			"fcm" => serde_json::from_value::<FcmBody>(value.clone())
				.map_err(|e| NotificationError(e.to_string()))
				.and_then(|b| fcm_provider(&b, policy))
				.map(|p| providers.fcm = Some(p)),
			"vapid" => serde_json::from_value::<WebBody>(value.clone())
				.map_err(|e| NotificationError(e.to_string()))
				.and_then(|b| web_provider(&b, subject, policy))
				.map(|p| providers.web = Some(p)),
			_ => Ok(()),
		};
		if let Err(error) = built {
			tracing::warn!(kind = %kind, reason = %error, "stored credentials do not build; that transport is off");
		}
	}
	providers
}

/// The project, as the API and the runner share it.
pub struct Project {
	pub jwt_secret: String,
	pub plan: Plan,
	pub vapid_subject: String,
	pub roles: Roles,
	pub policy: Policy,
	/// Short transactions for the API, as the caller or as the sender's own role.
	pub pool: deadpool_postgres::Pool,
	/// Rebuilt whenever `push.credentials` changes.
	pub providers: RwLock<Arc<Providers>>,
	/// Woken by the API when it queues a message or changes a key.
	pub nudge: Notify,
}

impl Project {
	pub fn new(
		database_url: &str,
		jwt_secret: String,
		plan: Plan,
		vapid_subject: String,
		roles: Roles,
		policy: Policy,
	) -> Result<Self, String> {
		let mut config = deadpool_postgres::Config::new();
		config.url = Some(database_url.to_string());
		config.pool = Some(deadpool_postgres::PoolConfig::new(4));
		let pool = config
			.create_pool(Some(deadpool_postgres::Runtime::Tokio1), NoTls)
			.map_err(|e| format!("the database URL is not usable: {e}"))?;
		Ok(Self {
			jwt_secret,
			plan,
			vapid_subject,
			roles,
			policy,
			pool,
			providers: RwLock::new(Arc::new(Providers::default())),
			nudge: Notify::new(),
		})
	}

	pub async fn providers(&self) -> Arc<Providers> {
		self.providers.read().await.clone()
	}

	/// Reads `push.credentials` and swaps the providers in.
	pub async fn reload(&self, client: &Client) -> Result<(), tokio_postgres::Error> {
		let rows: Vec<(String, Value)> = client
			.query("SELECT kind, value FROM push.credentials", &[])
			.await?
			.iter()
			.map(|row| (row.get(0), row.get(1)))
			.collect();
		let providers = providers_from(&rows, &self.vapid_subject, &self.policy);
		*self.providers.write().await = Arc::new(providers);
		Ok(())
	}
}

/// Makes the project's VAPID keys the first time the sender meets its database. Two senders
/// racing (a restart overlapping itself) both insert, and the first one wins.
pub async fn ensure_vapid(client: &Client) -> Result<(), String> {
	let present: bool = client
		.query_one(
			"SELECT EXISTS (SELECT FROM push.credentials WHERE kind = 'vapid')",
			&[],
		)
		.await
		.map_err(|e| e.to_string())?
		.get(0);
	if present {
		return Ok(());
	}
	let (key, der) = EsKey::generate().map_err(|e| e.0)?;
	let seconds = drain::now_secs();
	let id = format!("v{seconds}");
	use base64::Engine;
	let value = json!({"keys": {&id: base64::engine::general_purpose::STANDARD.encode(der)}, "current": id});
	let summary = json!({"current": id, "public_key": crate::b64url(key.public_key())});
	client
		.execute(
			"INSERT INTO push.credentials (kind, value, summary) VALUES ('vapid', $1, $2) ON CONFLICT (kind) DO NOTHING",
			&[&value, &summary],
		)
		.await
		.map_err(|e| e.to_string())?;
	Ok(())
}

/// The runner, forever: connect, migrate, make the VAPID keys, load the providers, LISTEN, drain.
pub async fn run(project: Arc<Project>, database_url: String) {
	let mut backoff = Duration::from_millis(500);
	loop {
		if let Err(error) = serve(&project, &database_url).await {
			tracing::debug!(%error, "runner waiting for the database");
		}
		tokio::select! {
			_ = tokio::time::sleep(backoff) => {}
			_ = project.nudge.notified() => {}
		}
		backoff = (backoff * 2).min(RECONNECT_MAX);
	}
}

fn db_message(error: &tokio_postgres::Error) -> String {
	error
		.as_db_error()
		.map_or_else(|| error.to_string(), |e| e.message().to_string())
}

/// Links devices to auth.users when it can; not fatal, since without the link only the cascade
/// on a deleted user waits.
async fn link_auth(client: &Client) {
	if let Err(error) = client.batch_execute("SELECT push.link_auth()").await {
		tracing::warn!(reason = %db_message(&error), "devices are not linked to auth.users yet");
	}
}

#[derive(Debug, PartialEq, Eq)]
enum Wake {
	Message,
	Credentials,
}

async fn serve(project: &Project, database_url: &str) -> Result<(), String> {
	let (mut client, mut connection) = tokio_postgres::connect(database_url, NoTls)
		.await
		.map_err(|e| e.to_string())?;
	let (notified, mut notifications) = tokio::sync::mpsc::unbounded_channel::<Wake>();
	let driver = tokio::spawn(async move {
		let mut messages = futures_util::stream::poll_fn(move |cx| connection.poll_message(cx));
		while let Some(message) = messages.next().await {
			match message {
				Ok(AsyncMessage::Notification(n)) => {
					let wake = if n.channel() == "snout_push_credentials" {
						Wake::Credentials
					} else {
						Wake::Message
					};
					let _ = notified.send(wake);
				}
				Ok(_) => {}
				Err(_) => break,
			}
		}
	});
	let result = async {
		migrations::migrate(&mut client, migrations::TENANT, &project.roles)
			.await
			.map_err(|e| e.to_string())?;
		// Neither is fatal: the owner reading push data and the cascade from auth.users are
		// conveniences, and sending must not wait for them.
		if let Err(error) = client
			.batch_execute("SELECT push.share_with_members()")
			.await
		{
			tracing::warn!(reason = %db_message(&error), "the project's owner cannot read push data");
		}
		link_auth(&client).await;
		ensure_vapid(&client).await?;
		project.reload(&client).await.map_err(|e| e.to_string())?;
		client
			.batch_execute("LISTEN snout_push; LISTEN snout_push_credentials")
			.await
			.map_err(|e| e.to_string())?;
		tracing::info!("draining");
		let mut last_prune = tokio::time::Instant::now() - PRUNE_EVERY;
		loop {
			let providers = project.providers().await;
			let report = drain::pass(&client, &providers, project.plan)
				.await
				.map_err(|e| e.to_string())?;
			if report != drain::Report::default() {
				tracing::info!(?report, "pass");
			}
			// Wake when the next thing is due: a scheduled send that waited out the tick went up
			// to 30 s late. The floor keeps a row another sender holds from spinning this loop.
			let wait = drain::next_due(&client)
				.await
				.map_err(|e| e.to_string())?
				.map_or(TICK, |secs| {
					Duration::from_secs_f64(secs.clamp(MIN_WAIT.as_secs_f64(), TICK.as_secs_f64()))
				});
			if last_prune.elapsed() >= PRUNE_EVERY {
				let (messages, devices) = drain::prune(&client).await.map_err(|e| e.to_string())?;
				if messages + devices > 0 {
					tracing::info!(messages, devices, "pruned");
				}
				// Auth may be switched on after push, and its table is made after this started.
				link_auth(&client).await;
				last_prune = tokio::time::Instant::now();
			}
			tokio::select! {
				got = notifications.recv() => {
					let Some(first) = got else {
						return Err("the connection closed".to_string());
					};
					// Coalesce a burst into one pass, reloading keys if any of it was a key.
					let mut credentials = first == Wake::Credentials;
					while let Ok(more) = notifications.try_recv() {
						credentials |= more == Wake::Credentials;
					}
					if credentials {
						project.reload(&client).await.map_err(|e| e.to_string())?;
						tracing::info!("credentials reloaded");
					}
				}
				_ = project.nudge.notified() => {}
				_ = tokio::time::sleep(wait) => {}
			}
		}
	}
	.await;
	driver.abort();
	result
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn stored_credentials_build_their_transport_and_a_bad_row_leaves_only_its_own_off() {
		let (_, der) = EsKey::generate().unwrap();
		use base64::Engine;
		let vapid = base64::engine::general_purpose::STANDARD.encode(der);
		let rows = vec![
			(
				"vapid".to_string(),
				json!({"keys": {"v1": vapid}, "current": "v1"}),
			),
			(
				"apns".to_string(),
				json!({"topic": "com.example.app", "keys": [{"p8": "nope", "key_id": "ABC123DEFG", "team_id": "TEAM123456"}]}),
			),
		];
		let providers = providers_from(&rows, "mailto:push@snoutdata.com", &Policy::strict());
		assert!(providers.web.is_some());
		assert!(
			providers.apns.is_none(),
			"a key that does not parse leaves APNs off"
		);
	}

	#[test]
	fn a_misspelled_field_does_not_build() {
		assert!(
			serde_json::from_value::<ApnsBody>(json!({"topic": "a.b", "keys": [], "extra": 1}))
				.is_err()
		);
	}
}
