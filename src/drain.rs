//! Draining one project's queue: claim what is due, turn each message into one row per device,
//! deliver, write down what each provider said, and close the message when nothing is pending.
//!
//! Everything is a single statement against the project's database, so a sender that dies at
//! any point leaves rows another pass can pick up: a claimed message not yet expanded is taken
//! again after [`STALE_CLAIM_SECS`], expansion is idempotent (one delivery per message and
//! device), and a delivery is pushed [`CLAIM_HOLD_SECS`] into the future when claimed, so it is
//! retried if its outcome is never written. A device can therefore, rarely, get a notification
//! twice; it never silently gets none.
//!
//! The sender connects as the schema's owner, so row-level security does not apply here: every
//! access decision was made when the message was inserted.

use std::sync::Arc;

use futures_util::StreamExt;
use serde_json::Value;
use tokio_postgres::Client;

use crate::notification::{Envelope, Notification, Outcome, Priority};
use crate::providers::{Device, Providers, Transport};

/// A claimed, unexpanded message this old belongs to a sender that died.
pub const STALE_CLAIM_SECS: i64 = 300;
/// How far a claimed delivery is pushed out, in case its outcome is never written.
pub const CLAIM_HOLD_SECS: i64 = 300;
/// On a free project, a future `send_at` within this much of now is "now" rather than refused:
/// clocks disagree. A paid project's `send_at` is kept, never sent early.
pub const SCHEDULING_GRACE_SECS: i64 = 60;
/// Deliveries claimed per round of a pass.
pub const BATCH: i64 = 200;

/// What one project may do, from its plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
	/// Whether a future `send_at`, and retrying past the free window, is allowed (a free project can pause).
	pub scheduling: bool,
	/// In-flight provider requests at once (from the pod's size).
	pub concurrency: usize,
}

impl Plan {
	/// A project's concurrency follows its pod's memory, 1 per 32 MB, between 4 and 64.
	pub fn from_pod(pod_memory_mb: u32, scheduling: bool) -> Self {
		Self {
			scheduling,
			concurrency: (pod_memory_mb / 32).clamp(4, 64) as usize,
		}
	}

	/// How long after its first attempt a delivery may still be retried.
	pub fn retry_window_secs(self) -> u64 {
		if self.scheduling {
			24 * 60 * 60
		} else {
			5 * 60
		}
	}
}

/// The sentence a free project's future `send_at` is refused with.
pub const SCHEDULING_REFUSED: &str = "Scheduled and delayed sends are on paid plans: a free project can pause, and a paused project has nothing to send it on time. Send without send_at, or upgrade.";

/// The most attempts a delivery gets, whatever the window.
pub const MAX_ATTEMPTS: i32 = 12;

/// When to try again, in seconds from now, or `None` to give up. `retry_after` is what the
/// provider asked for; `attempts` includes the one that just failed; `age` is seconds since the
/// delivery row was made. `jitter` is in 0..1 (a fixed value in tests). The floor per provider is
/// FCM's 10 seconds, Apple's advice to wait for a 5xx, and Retry-After always honoured.
pub fn next_attempt(
	retry_after: Option<u64>,
	attempts: i32,
	age: u64,
	transport: Transport,
	plan: Plan,
	jitter: f64,
) -> Option<u64> {
	let asked = retry_after?;
	if attempts >= MAX_ATTEMPTS {
		return None;
	}
	let floor = match transport {
		Transport::Fcm => 10,
		Transport::Apns | Transport::Web => 5,
	};
	let exponent = u32::try_from(attempts.saturating_sub(1))
		.unwrap_or(0)
		.min(12);
	let backoff = (floor * 2u64.pow(exponent)).min(3600);
	let spread = 0.8 + 0.4 * jitter.clamp(0.0, 1.0);
	let delay = ((asked.max(backoff) as f64) * spread).round() as u64;
	if age + delay > plan.retry_window_secs() {
		None
	} else {
		Some(delay.max(1))
	}
}

/// A delivery as a pass works on it.
#[derive(Debug, Clone)]
pub struct Work {
	pub delivery_id: i64,
	pub attempts: i32,
	pub age_secs: u64,
	pub device: Option<Device>,
	pub device_disabled: bool,
	/// `last_seen_at` in milliseconds, for APNs' 410 timestamp.
	pub device_seen_ms: Option<i64>,
	pub notification: Value,
	pub envelope: Envelope,
}

/// What a pass did, for the log and the tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
	pub refused_scheduled: u64,
	pub claimed_messages: u64,
	pub expanded: u64,
	pub accepted: u64,
	pub retrying: u64,
	pub failed: u64,
	pub unregistered: u64,
	pub refused: u64,
	pub finished_messages: u64,
}

pub fn now_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |d| d.as_secs())
}

/// One pass over a project's queue.
pub async fn pass(
	client: &Client,
	providers: &Providers,
	plan: Plan,
) -> Result<Report, tokio_postgres::Error> {
	let mut report = Report::default();

	if !plan.scheduling {
		report.refused_scheduled = client
			.execute(
				"UPDATE push.messages SET status = 'refused', status_detail = $1, finished_at = now() \
				 WHERE status = 'queued' AND send_at > now() + make_interval(secs => $2)",
				&[&SCHEDULING_REFUSED, &(SCHEDULING_GRACE_SECS as f64)],
			)
			.await?;
	}

	let grace = if plan.scheduling {
		0.0
	} else {
		SCHEDULING_GRACE_SECS as f64
	};
	let claimed = client
		.query(
			"UPDATE push.messages m SET status = 'sending', claimed_at = now() \
			 WHERE m.id IN (SELECT id FROM push.messages \
			   WHERE (status = 'queued' AND send_at <= now() + make_interval(secs => $2)) \
			      OR (status = 'sending' AND expanded_at IS NULL AND claimed_at < now() - make_interval(secs => $3)) \
			   ORDER BY send_at LIMIT $1 FOR UPDATE SKIP LOCKED) \
			 RETURNING m.id",
			&[&BATCH, &grace, &(STALE_CLAIM_SECS as f64)],
		)
		.await?;
	report.claimed_messages = claimed.len() as u64;
	for row in claimed {
		let id: i64 = row.get(0);
		report.expanded += expand(client, id).await?;
	}

	loop {
		let batch = claim_deliveries(client).await?;
		if batch.is_empty() {
			break;
		}
		let now = now_secs();
		let outcomes: Vec<(Work, Outcome)> = futures_util::stream::iter(batch)
			.map(|work| async move {
				let outcome = deliver(providers, &work, now).await;
				(work, outcome)
			})
			.buffer_unordered(plan.concurrency)
			.collect()
			.await;
		for (work, outcome) in outcomes {
			record(client, &work, outcome, plan, &mut report).await?;
		}
	}

	report.finished_messages = finish(client).await?;
	Ok(report)
}

/// Seconds until the queue next has something due (a scheduled message or a retry), or `None`
/// when nothing is waiting, so the runner wakes then rather than on its next tick.
pub async fn next_due(client: &Client) -> Result<Option<f64>, tokio_postgres::Error> {
	let row = client
		.query_one(
			"SELECT extract(epoch FROM least( \
			   (SELECT min(send_at) FROM push.messages WHERE status = 'queued'), \
			   (SELECT min(l.next_attempt_at) FROM push.deliveries l JOIN push.messages m ON m.id = l.message_id \
			     WHERE l.status = 'pending' AND m.status = 'sending')) - clock_timestamp())::float8",
			&[],
		)
		.await?;
	Ok(row.get(0))
}

/// Turns one message's target into one pending delivery per live device. Idempotent.
async fn expand(client: &Client, message_id: i64) -> Result<u64, tokio_postgres::Error> {
	let made = client
		.execute(
			"INSERT INTO push.deliveries (message_id, device_id, transport, next_attempt_at) \
			 SELECT m.id, d.id, d.transport, now() \
			 FROM push.messages m JOIN push.devices d ON d.disabled_at IS NULL \
			 WHERE m.id = $1 \
			   AND (d.kind = 'device' OR m.target_device_ids IS NOT NULL) \
			   AND ( d.user_id = ANY (m.target_user_ids) \
			      OR d.id = ANY (m.target_device_ids) \
			      OR (m.target_topic IS NOT NULL AND ( \
			           d.user_id IN (SELECT t.user_id FROM push.topic_members t WHERE t.topic = m.target_topic AND t.user_id IS NOT NULL) \
			        OR d.id IN (SELECT t.device_id FROM push.topic_members t WHERE t.topic = m.target_topic AND t.device_id IS NOT NULL)))) \
			 ON CONFLICT (message_id, device_id) DO NOTHING",
			&[&message_id],
		)
		.await?;
	client
		.execute(
			"UPDATE push.messages SET expanded_at = now() WHERE id = $1",
			&[&message_id],
		)
		.await?;
	Ok(made)
}

/// Claims a batch of due deliveries: each is pushed [`CLAIM_HOLD_SECS`] out and counted as an
/// attempt in the same statement, so an overlapping pass cannot take it too.
async fn claim_deliveries(client: &Client) -> Result<Vec<Work>, tokio_postgres::Error> {
	let rows = client
		.query(
			"WITH claimed AS ( \
			   UPDATE push.deliveries l SET next_attempt_at = now() + make_interval(secs => $2), attempts = l.attempts + 1 \
			   WHERE l.id IN (SELECT l2.id FROM push.deliveries l2 JOIN push.messages m2 ON m2.id = l2.message_id \
			     WHERE l2.status = 'pending' AND l2.next_attempt_at <= now() AND m2.status = 'sending' \
			     ORDER BY l2.next_attempt_at LIMIT $1 FOR UPDATE OF l2 SKIP LOCKED) \
			   RETURNING l.id, l.message_id, l.device_id, l.attempts, l.created_at) \
			 SELECT c.id, c.attempts, greatest(0, extract(epoch FROM now() - c.created_at))::bigint, \
			   d.id::text, d.transport, d.token, d.web_p256dh, d.web_auth, d.vapid_key_id, d.apns_environment, d.app, \
			   d.disabled_at IS NOT NULL, (extract(epoch FROM d.last_seen_at) * 1000)::bigint, \
			   m.notification, m.ttl, m.priority, m.collapse_key \
			 FROM claimed c JOIN push.messages m ON m.id = c.message_id LEFT JOIN push.devices d ON d.id = c.device_id",
			&[&BATCH, &(CLAIM_HOLD_SECS as f64)],
		)
		.await?;
	Ok(rows
		.iter()
		.map(|row| {
			let device_id: Option<String> = row.get(3);
			let device = device_id.and_then(|id| {
				Some(Device {
					id,
					transport: Transport::parse(row.get::<_, &str>(4))?,
					token: row.get(5),
					web_p256dh: row.get(6),
					web_auth: row.get(7),
					vapid_key_id: row.get(8),
					apns_environment: row.get(9),
					app: row.get(10),
				})
			});
			let ttl: Option<i32> = row.get(14);
			Work {
				delivery_id: row.get(0),
				attempts: row.get(1),
				age_secs: u64::try_from(row.get::<_, i64>(2)).unwrap_or(0),
				device_disabled: row.get::<_, Option<bool>>(11).unwrap_or(false),
				device_seen_ms: row.get(12),
				device,
				notification: row.get(13),
				envelope: Envelope {
					ttl: ttl.and_then(|t| u32::try_from(t).ok()),
					priority: if row.get::<_, &str>(15) == "normal" {
						Priority::Normal
					} else {
						Priority::High
					},
					collapse_key: row.get(16),
				},
			}
		})
		.collect())
}

async fn deliver(providers: &Providers, work: &Work, now: u64) -> Outcome {
	let Some(device) = &work.device else {
		return Outcome::Refused {
			reason: "The device was removed before this was sent.".into(),
		};
	};
	if work.device_disabled {
		return Outcome::Refused {
			reason: "The device was disabled before this was sent.".into(),
		};
	}
	// Validated again here: a row inserted from SQL was never seen by the API's check.
	let mut notification = match Notification::from_json(&work.notification) {
		Ok(notification) => notification,
		Err(error) => return Outcome::Refused { reason: error.0 },
	};
	if let Err(error) = notification.validate(&work.envelope) {
		return Outcome::Refused { reason: error.0 };
	}
	// After validation, which refuses the key from a customer: the app reads it back to report
	// the notification received or opened.
	notification.data.insert(
		crate::notification::DELIVERY_KEY.into(),
		serde_json::json!(work.delivery_id),
	);
	providers
		.deliver(&notification, &work.envelope, device, now)
		.await
}

async fn record(
	client: &Client,
	work: &Work,
	outcome: Outcome,
	plan: Plan,
	report: &mut Report,
) -> Result<(), tokio_postgres::Error> {
	let id = work.delivery_id;
	match outcome {
		Outcome::Accepted { provider_id } => {
			report.accepted += 1;
			client
				.execute(
					"UPDATE push.deliveries SET status = 'accepted', provider_id = $2, accepted_at = now(), error = NULL, next_attempt_at = NULL WHERE id = $1",
					&[&id, &provider_id],
				)
				.await?;
		}
		Outcome::Failed {
			reason,
			retry_after,
		} => {
			let transport = work.device.as_ref().map_or(Transport::Web, |d| d.transport);
			let jitter = f64::from((id as u32).wrapping_mul(2_654_435_761) >> 16) / 65536.0;
			match next_attempt(
				retry_after,
				work.attempts,
				work.age_secs,
				transport,
				plan,
				jitter,
			) {
				Some(delay) => {
					report.retrying += 1;
					client
						.execute(
							"UPDATE push.deliveries SET error = $2, next_attempt_at = now() + make_interval(secs => $3) WHERE id = $1",
							&[&id, &reason, &(delay as f64)],
						)
						.await?;
				}
				None => {
					report.failed += 1;
					let reason = if retry_after.is_some() {
						format!("{reason} (gave up after {} attempts)", work.attempts)
					} else {
						reason
					};
					client
						.execute(
							"UPDATE push.deliveries SET status = 'failed', error = $2, next_attempt_at = NULL WHERE id = $1",
							&[&id, &reason],
						)
						.await?;
				}
			}
		}
		Outcome::Credentials { reason } => {
			report.failed += 1;
			tracing::warn!(delivery = id, %reason, "credentials refused");
			client
				.execute(
					"UPDATE push.deliveries SET status = 'failed', error = $2, next_attempt_at = NULL WHERE id = $1",
					&[&id, &reason],
				)
				.await?;
		}
		Outcome::Refused { reason } => {
			report.refused += 1;
			client
				.execute(
					"UPDATE push.deliveries SET status = 'refused', error = $2, next_attempt_at = NULL WHERE id = $1",
					&[&id, &reason],
				)
				.await?;
		}
		Outcome::Unregistered { reason, since_ms } => {
			report.unregistered += 1;
			client
				.execute(
					"UPDATE push.deliveries SET status = 'unregistered', error = $2, next_attempt_at = NULL WHERE id = $1",
					&[&id, &reason],
				)
				.await?;
			// A device that registered again after the provider's timestamp is alive.
			let stale = match (since_ms, work.device_seen_ms) {
				(Some(since), Some(seen)) => u64::try_from(seen).unwrap_or(0) < since,
				_ => true,
			};
			if stale && let Some(device) = &work.device {
				client
					.execute(
						"UPDATE push.devices SET disabled_at = now(), disabled_reason = $2 WHERE id = $1::text::uuid AND disabled_at IS NULL",
						&[&device.id, &reason],
					)
					.await?;
			}
		}
	}
	Ok(())
}

/// Closes every expanded message with nothing pending: sent (every device accepted), partial
/// (some), failed (none, or no device matched).
async fn finish(client: &Client) -> Result<u64, tokio_postgres::Error> {
	client
		.execute(
			"UPDATE push.messages m SET \
			   status = CASE WHEN s.accepted = s.total AND s.total > 0 THEN 'sent' \
			                 WHEN s.accepted = 0 THEN 'failed' ELSE 'partial' END, \
			   status_detail = CASE WHEN s.total = 0 THEN 'No registered device matched this message''s target.' \
			                        ELSE format('%s of %s devices accepted.', s.accepted, s.total) END, \
			   finished_at = now() \
			 FROM (SELECT m2.id, count(l.id) AS total, \
			         count(l.id) FILTER (WHERE l.status = 'accepted') AS accepted, \
			         count(l.id) FILTER (WHERE l.status = 'pending') AS pending \
			       FROM push.messages m2 LEFT JOIN push.deliveries l ON l.message_id = m2.id \
			       WHERE m2.status = 'sending' AND m2.expanded_at IS NOT NULL GROUP BY m2.id) s \
			 WHERE m.id = s.id AND s.pending = 0",
			&[],
		)
		.await
}

/// The hourly housekeeping: the log past its retention, and devices not seen for the
/// project's staleness period.
pub async fn prune(client: &Client) -> Result<(u64, u64), tokio_postgres::Error> {
	let messages = client
		.execute(
			"DELETE FROM push.messages WHERE finished_at < now() - make_interval(days => (SELECT retention_days FROM push.settings))",
			&[],
		)
		.await?;
	let devices = client
		.execute(
			"UPDATE push.devices SET disabled_at = now(), \
			   disabled_reason = format('Not seen for %s days.', (SELECT stale_device_days FROM push.settings)) \
			 WHERE disabled_at IS NULL AND last_seen_at < now() - make_interval(days => (SELECT stale_device_days FROM push.settings))",
			&[],
		)
		.await?;
	Ok((messages, devices))
}

/// Keeps `Arc<Providers>` usable where a pass is spawned.
pub type SharedProviders = Arc<Providers>;

#[cfg(test)]
mod tests {
	use super::*;

	const FREE: Plan = Plan {
		scheduling: false,
		concurrency: 4,
	};
	const PAID: Plan = Plan {
		scheduling: true,
		concurrency: 4,
	};

	#[test]
	fn concurrency_follows_the_pod() {
		assert_eq!(Plan::from_pod(64, false).concurrency, 4);
		assert_eq!(Plan::from_pod(512, true).concurrency, 16);
		assert_eq!(Plan::from_pod(100_000, true).concurrency, 64);
	}

	#[test]
	fn never_retry_what_the_provider_said_not_to() {
		assert_eq!(next_attempt(None, 1, 0, Transport::Fcm, PAID, 0.5), None);
	}

	#[test]
	fn retry_after_is_honoured_and_the_floor_holds() {
		// FCM's floor is 10 s; the provider asked for 60.
		assert_eq!(
			next_attempt(Some(60), 1, 0, Transport::Fcm, PAID, 0.5),
			Some(60)
		);
		assert_eq!(
			next_attempt(Some(0), 1, 0, Transport::Fcm, PAID, 0.5),
			Some(10)
		);
		// Backoff doubles per attempt.
		assert_eq!(
			next_attempt(Some(1), 3, 0, Transport::Apns, PAID, 0.5),
			Some(20)
		);
		// Jitter spreads it by ±20%.
		assert_eq!(
			next_attempt(Some(100), 1, 0, Transport::Web, PAID, 0.0),
			Some(80)
		);
		assert_eq!(
			next_attempt(Some(100), 1, 0, Transport::Web, PAID, 1.0),
			Some(120)
		);
	}

	#[test]
	fn free_gives_up_after_five_minutes_and_paid_after_a_day() {
		assert_eq!(
			next_attempt(Some(60), 2, 250, Transport::Apns, FREE, 0.5),
			None
		);
		assert!(next_attempt(Some(60), 2, 250, Transport::Apns, PAID, 0.5).is_some());
		assert_eq!(
			next_attempt(Some(3600), 5, 86_000, Transport::Apns, PAID, 0.5),
			None
		);
		assert_eq!(
			next_attempt(Some(1), MAX_ATTEMPTS, 0, Transport::Apns, PAID, 0.5),
			None
		);
	}

	/// The drain against a real Postgres, gated on `PUSH_TEST_DATABASE_URL` (tests/db.sh sets it).
	/// Each run makes its own database, so runs never see each other's rows.
	mod live {
		use super::*;
		use crate::apns::{self, Environment};
		use crate::keys::EsKey;
		use crate::net::tests::stand_in_with;
		use crate::net::{Http, Policy};
		use crate::providers::Apns;

		const ALICE: &str = "00000000-0000-4000-8000-00000000000a";
		const BOB: &str = "00000000-0000-4000-8000-00000000000b";
		const LIVE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
		const DEAD: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
		const FLAKY: &str = "f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5";

		async fn device(client: &Client, user: &str, token: &str) -> String {
			client
				.query_one(
					"INSERT INTO push.devices (user_id, transport, token, apns_environment) VALUES ($1::text::uuid, 'apns', $2, 'production') RETURNING id::text",
					&[&user, &token],
				)
				.await
				.unwrap()
				.get(0)
		}

		fn key() -> apns::Credentials {
			let (_, der) = EsKey::generate().unwrap();
			use base64::Engine;
			let p8 = crate::keys::test_pem(&base64::engine::general_purpose::STANDARD.encode(der));
			apns::Credentials::new(&p8, "KEY0000001", "TEAM123456").unwrap()
		}

		#[tokio::test]
		async fn a_message_through_the_whole_drain() {
			let Some((client, _)) = crate::testing::fresh_database("drain").await else {
				eprintln!("skipped: PUSH_TEST_DATABASE_URL is not set (tests/db.sh sets it)");
				return;
			};
			device(&client, ALICE, LIVE).await;
			let bobs = device(&client, BOB, DEAD).await;
			let (origin, _seen) = stand_in_with(|path: &str| {
				if path.ends_with(DEAD) {
					(
						410,
						vec![],
						br#"{"reason":"Unregistered","timestamp":4102444800000}"#.to_vec(),
					)
				} else if path.ends_with(FLAKY) {
					(503, vec![], br#"{"reason":"ServiceUnavailable"}"#.to_vec())
				} else {
					(200, vec![("apns-id", "accepted-1")], vec![])
				}
			})
			.await;
			let providers = Providers {
				apns: Some(
					Apns::new(
						vec![(Some(Environment::Production), key())],
						"com.example.app",
						Http::new(Policy::local(&origin)).unwrap(),
					)
					.unwrap(),
				),
				..Providers::default()
			};

			// One message to both: Apple takes Alice's device and says Bob's is gone.
			let message: i64 = client
				.query_one(
					"SELECT push.send('{\"title\":\"Hello\"}', user_ids => ARRAY[$1::text::uuid, $2::text::uuid])",
					&[&ALICE, &BOB],
				)
				.await
				.unwrap()
				.get(0);
			let report = pass(&client, &providers, FREE).await.unwrap();
			assert_eq!(
				(
					report.claimed_messages,
					report.expanded,
					report.accepted,
					report.unregistered
				),
				(1, 2, 1, 1),
				"{report:?}"
			);
			assert_eq!(report.finished_messages, 1);
			let row = client
				.query_one(
					"SELECT status, status_detail FROM push.messages WHERE id = $1",
					&[&message],
				)
				.await
				.unwrap();
			assert_eq!(row.get::<_, &str>(0), "partial");
			assert_eq!(row.get::<_, &str>(1), "1 of 2 devices accepted.");
			let disabled: Option<String> = client
				.query_one(
					"SELECT disabled_reason FROM push.devices WHERE id = $1::text::uuid",
					&[&bobs],
				)
				.await
				.unwrap()
				.get(0);
			assert_eq!(
				disabled.as_deref(),
				Some("APNs: Unregistered"),
				"bob's device is disabled"
			);
			let provider_id: Option<String> = client
				.query_one(
					"SELECT provider_id FROM push.deliveries WHERE status = 'accepted'",
					&[],
				)
				.await
				.unwrap()
				.get(0);
			assert_eq!(provider_id.as_deref(), Some("accepted-1"));

			// A second pass has nothing to do: nothing is sent twice.
			let again = pass(&client, &providers, FREE).await.unwrap();
			assert_eq!(again, Report::default());

			// A free project's scheduled send is refused with the sentence; a paid one waits.
			let scheduled: i64 = client
				.query_one(
					"SELECT push.send('{\"title\":\"Later\"}', user_ids => ARRAY[$1::text::uuid], send_at => now() + interval '1 hour')",
					&[&ALICE],
				)
				.await
				.unwrap()
				.get(0);
			let report = pass(&client, &providers, PAID).await.unwrap();
			assert_eq!(report.claimed_messages, 0, "not due yet");
			let due = next_due(&client)
				.await
				.unwrap()
				.expect("something is waiting");
			assert!(
				(3500.0..=3600.0).contains(&due),
				"due in an hour, not {due}"
			);
			let report = pass(&client, &providers, FREE).await.unwrap();
			assert_eq!(report.refused_scheduled, 1);
			let row = client
				.query_one(
					"SELECT status, status_detail FROM push.messages WHERE id = $1",
					&[&scheduled],
				)
				.await
				.unwrap();
			assert_eq!(row.get::<_, &str>(0), "refused");
			assert_eq!(row.get::<_, &str>(1), SCHEDULING_REFUSED);

			// Half a minute out: a paid project waits for it (the grace sent it at once, up to a
			// minute early), and a free one sends it now rather than refusing it.
			client
				.query_one(
					"SELECT push.send('{\"title\":\"Soon\"}', user_ids => ARRAY[$1::text::uuid], send_at => now() + interval '30 seconds')",
					&[&ALICE],
				)
				.await
				.unwrap();
			let report = pass(&client, &providers, PAID).await.unwrap();
			assert_eq!(report.claimed_messages, 0, "a paid send_at is kept");
			let due = next_due(&client)
				.await
				.unwrap()
				.expect("something is waiting");
			assert!(
				(25.0..=30.0).contains(&due),
				"due in half a minute, not {due}"
			);
			let report = pass(&client, &providers, FREE).await.unwrap();
			assert_eq!(
				(report.refused_scheduled, report.claimed_messages),
				(0, 1),
				"{report:?}"
			);

			// A 503 is retried later, not failed, and the message stays open.
			device(&client, ALICE, FLAKY).await;
			let flaky: i64 = client
				.query_one(
					"SELECT push.send('{\"title\":\"Flaky\"}', user_ids => ARRAY[$1::text::uuid])",
					&[&ALICE],
				)
				.await
				.unwrap()
				.get(0);
			let report = pass(&client, &providers, PAID).await.unwrap();
			assert_eq!((report.accepted, report.retrying), (1, 1), "{report:?}");
			let row = client
				.query_one(
					"SELECT l.status, l.error, l.next_attempt_at > now(), m.status FROM push.deliveries l JOIN push.messages m ON m.id = l.message_id \
					 WHERE l.message_id = $1 AND l.status <> 'accepted'",
					&[&flaky],
				)
				.await
				.unwrap();
			assert_eq!(row.get::<_, &str>(0), "pending");
			assert_eq!(row.get::<_, &str>(1), "APNs: ServiceUnavailable");
			assert!(row.get::<_, bool>(2), "retried in the future");
			assert_eq!(
				row.get::<_, &str>(3),
				"sending",
				"the message stays open while a delivery is pending"
			);

			// No device matched: failed, with a sentence that says why.
			let nobody: i64 = client
				.query_one(
					"SELECT push.send('{\"title\":\"x\"}', user_ids => ARRAY[gen_random_uuid()])",
					&[],
				)
				.await
				.unwrap()
				.get(0);
			pass(&client, &providers, PAID).await.unwrap();
			let row = client
				.query_one(
					"SELECT status, status_detail FROM push.messages WHERE id = $1",
					&[&nobody],
				)
				.await
				.unwrap();
			assert_eq!(row.get::<_, &str>(0), "failed");
			assert!(row.get::<_, &str>(1).contains("No registered device"));

			// A bad notification inserted straight from SQL is refused per delivery, not sent.
			let bad: i64 = client
				.query_one(
					"SELECT push.send('{\"tittle\":\"typo\"}', user_ids => ARRAY[$1::text::uuid])",
					&[&ALICE],
				)
				.await
				.unwrap()
				.get(0);
			let report = pass(&client, &providers, PAID).await.unwrap();
			assert!(report.refused >= 1, "{report:?}");
			let status: String = client
				.query_one("SELECT status FROM push.messages WHERE id = $1", &[&bad])
				.await
				.unwrap()
				.get(0);
			assert_eq!(status, "failed");
		}
	}
}
