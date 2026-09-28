//! `/push/v1`: apps and servers, through the front door, to the one project this server serves.
//!
//! `/push/v1` exists because the data API is a paid feature (STACK.md, S16): a free project's app
//! must still be able to register a device. Every call runs in the project's database AS THE
//! CALLER (the role and the JWT claims set for the transaction), so the project's own policies
//! decide; this server checks shapes, never access.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use serde::Deserialize;
use serde_json::{Value, json};

use tokio_postgres::types::ToSql;

use crate::drain::{SCHEDULING_GRACE_SECS, SCHEDULING_REFUSED, now_secs};
use crate::jwt::{self, Caller};
use crate::notification::{Envelope, Notification, Priority};
use crate::project::{self, ApnsBody, FcmBody, Project};
use crate::providers::Transport;
use crate::{apns, fcm, webpush};

pub type AppState = Arc<Project>;

/// A refusal: a status and one sentence, as `{"error": "..."}`.
#[derive(Debug)]
pub struct ApiError {
	pub status: StatusCode,
	pub message: String,
}

impl ApiError {
	pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
		Self {
			status,
			message: message.into(),
		}
	}
}

impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		let mut response =
			(self.status, axum::Json(json!({"error": self.message}))).into_response();
		if self.status == StatusCode::SERVICE_UNAVAILABLE {
			response
				.headers_mut()
				.insert("retry-after", "2".parse().expect("a valid header"));
		}
		response
	}
}

/// What the database said, as a sentence for the caller. A policy's refusal is ours to word,
/// since Postgres names tables; a sentence the push schema raised itself is passed through.
impl From<tokio_postgres::Error> for ApiError {
	fn from(error: tokio_postgres::Error) -> Self {
		let Some(db) = error.as_db_error() else {
			return ApiError::new(
				StatusCode::SERVICE_UNAVAILABLE,
				"The project's database is not answering; try again in a moment.",
			);
		};
		let message = db.message();
		match db.code().code() {
			"42501"
				if message.starts_with("new row violates")
					|| message.starts_with("permission denied") =>
			{
				ApiError::new(
					StatusCode::FORBIDDEN,
					"The project's policies do not allow this caller to do that.",
				)
			}
			"42501" => ApiError::new(StatusCode::FORBIDDEN, message),
			"23514" => ApiError::new(
				StatusCode::BAD_REQUEST,
				format!(
					"That breaks a rule of the push schema ({}).",
					db.constraint().unwrap_or("a check")
				),
			),
			"23503" => ApiError::new(StatusCode::NOT_FOUND, "There is no such topic."),
			"22P02" => ApiError::new(StatusCode::BAD_REQUEST, "That is not a valid id."),
			"P0001" | "22023" => ApiError::new(StatusCode::BAD_REQUEST, message),
			_ => {
				tracing::warn!(code = db.code().code(), %message, "database refused a request");
				ApiError::new(
					StatusCode::INTERNAL_SERVER_ERROR,
					"The project's database refused this.",
				)
			}
		}
	}
}

impl From<deadpool_postgres::PoolError> for ApiError {
	fn from(_: deadpool_postgres::PoolError) -> Self {
		ApiError::new(
			StatusCode::SERVICE_UNAVAILABLE,
			"The project's database is starting; try again in a moment.",
		)
	}
}

type Answer = Result<Response, ApiError>;

pub fn public_router(state: AppState) -> Router {
	Router::new()
		.route("/push/v1/vapid-public-key", get(vapid_public_key))
		.route("/push/v1/devices", post(register_device))
		.route("/push/v1/devices/{id}", delete(remove_device))
		.route(
			"/push/v1/topics/{name}/members",
			put(join_topic).delete(leave_topic),
		)
		.route("/push/v1/send", post(send))
		.route("/push/v1/messages/{id}", get(message))
		.route("/push/v1/receipts", post(receipt))
		.route("/push/v1/credentials", get(credential_summaries))
		.route(
			"/push/v1/credentials/{kind}",
			put(set_credentials).delete(remove_credentials),
		)
		.route("/health", get(|| async { "ok" }))
		.with_state(state)
}

/// The verified caller. The front door turns an `apikey` into a bearer token, so a missing
/// `Authorization` is a request that did not come through it.
fn context(app: &Project, headers: &HeaderMap) -> Result<Caller, ApiError> {
	let token = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.and_then(|v| {
			v.strip_prefix("Bearer ")
				.or_else(|| v.strip_prefix("bearer "))
		})
		.ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "A bearer token is required."))?;
	jwt::verify(token, &app.jwt_secret, &app.roles, now_secs())
		.map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, e.0))
}

/// Opens a transaction as the caller: their role, their claims, for this transaction only.
async fn as_caller<'a>(
	client: &'a mut deadpool_postgres::Object,
	caller: &Caller,
) -> Result<deadpool_postgres::Transaction<'a>, ApiError> {
	let transaction = client.transaction().await?;
	let claims = Value::Object(caller.claims.clone()).to_string();
	transaction
		.execute(
			"SELECT set_config('role', $1, true), set_config('request.jwt.claims', $2, true)",
			&[&caller.role, &claims],
		)
		.await?;
	Ok(transaction)
}

fn json_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, ApiError> {
	serde_json::from_slice(body).map_err(|e| {
		ApiError::new(
			StatusCode::BAD_REQUEST,
			format!("The request body is not valid: {e}."),
		)
	})
}

async fn vapid_public_key(State(app): State<AppState>) -> Answer {
	let providers = app.providers().await;
	let web = providers.web.as_ref().ok_or_else(|| {
		ApiError::new(
			StatusCode::SERVICE_UNAVAILABLE,
			"Web Push is starting; try again in a moment.",
		)
	})?;
	Ok(
		axum::Json(json!({"id": web.current_id(), "key": crate::b64url(web.public_key())}))
			.into_response(),
	)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRequest {
	transport: String,
	/// The APNs device token, the FCM registration token, or the Web Push endpoint.
	token: String,
	#[serde(default)]
	p256dh: Option<String>,
	#[serde(default)]
	auth: Option<String>,
	/// APNs: `production` or `sandbox`.
	#[serde(default)]
	environment: Option<String>,
	#[serde(default)]
	app: Option<String>,
	#[serde(default)]
	locale: Option<String>,
	#[serde(default)]
	kind: Option<String>,
}

async fn register_device(
	State(app): State<AppState>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> Answer {
	let caller = context(&app, &headers)?;
	let tenant = &app;
	let request: DeviceRequest = json_body(&body)?;
	let bad = |e: String| ApiError::new(StatusCode::BAD_REQUEST, e);
	let transport = Transport::parse(&request.transport).ok_or_else(|| {
		bad(format!(
			"transport is apns, fcm or web, not \"{}\".",
			request.transport
		))
	})?;
	let (token, p256dh, auth, vapid_key_id, environment) = match transport {
		Transport::Apns => {
			let environment = request.environment.as_deref().unwrap_or("production");
			apns::Environment::parse(environment).map_err(|e| bad(e.0))?;
			if let Some(app_id) = &request.app {
				apns::check_topic(app_id).map_err(|e| bad(e.0))?;
			}
			(
				apns::check_device_token(&request.token).map_err(|e| bad(e.0))?,
				None,
				None,
				None,
				Some(environment.to_string()),
			)
		}
		Transport::Fcm => (
			fcm::check_device_token(&request.token).map_err(|e| bad(e.0))?,
			None,
			None,
			None,
			None,
		),
		Transport::Web => {
			let providers = tenant.providers().await;
			let key_id = providers
				.web
				.as_ref()
				.map(|w| w.current_id().to_string())
				.ok_or_else(|| bad("Web Push is starting; try again in a moment.".into()))?;
			let p256dh = request.p256dh.clone().unwrap_or_default();
			let auth = request.auth.clone().unwrap_or_default();
			webpush::Subscription::parse(&request.token, &p256dh, &auth).map_err(|e| bad(e.0))?;
			(
				request.token.clone(),
				Some(p256dh),
				Some(auth),
				Some(key_id.to_string()),
				None,
			)
		}
	};
	let kind = request.kind.unwrap_or_else(|| "device".into());
	let mut client = tenant.pool.get().await?;
	let transaction = as_caller(&mut client, &caller).await?;
	let row = transaction
		.query_one(
			"SELECT push.register_device($1, $2, $3, $4, $5, $6, $7, $8, $9)::text",
			&[
				&transport.as_str() as &(dyn ToSql + Sync),
				&token,
				&p256dh,
				&auth,
				&vapid_key_id,
				&environment,
				&request.app,
				&request.locale,
				&kind,
			],
		)
		.await?;
	transaction.commit().await?;
	let id: String = row.get(0);
	Ok((StatusCode::CREATED, axum::Json(json!({"id": id}))).into_response())
}

async fn remove_device(
	State(app): State<AppState>,
	headers: HeaderMap,
	Path(id): Path<String>,
) -> Answer {
	let caller = context(&app, &headers)?;
	let tenant = &app;
	let mut client = tenant.pool.get().await?;
	let transaction = as_caller(&mut client, &caller).await?;
	let removed = transaction
		.execute("DELETE FROM push.devices WHERE id = $1::text::uuid", &[&id])
		.await?;
	transaction.commit().await?;
	if removed == 0 {
		return Err(ApiError::new(
			StatusCode::NOT_FOUND,
			"No such device of yours.",
		));
	}
	Ok(StatusCode::NO_CONTENT.into_response())
}

fn signed_in(caller: &Caller) -> Result<(), ApiError> {
	if caller
		.claims
		.get("sub")
		.and_then(Value::as_str)
		.is_some_and(|s| !s.is_empty())
	{
		Ok(())
	} else {
		Err(ApiError::new(
			StatusCode::UNAUTHORIZED,
			"Sign in to join or leave a topic.",
		))
	}
}

async fn join_topic(
	State(app): State<AppState>,
	headers: HeaderMap,
	Path(name): Path<String>,
) -> Answer {
	let caller = context(&app, &headers)?;
	let tenant = &app;
	signed_in(&caller)?;
	let mut client = tenant.pool.get().await?;
	let transaction = as_caller(&mut client, &caller).await?;
	transaction
		.execute(
			"INSERT INTO push.topic_members (topic, user_id) VALUES ($1, push.uid()) \
			 ON CONFLICT (topic, user_id) WHERE user_id IS NOT NULL DO NOTHING",
			&[&name],
		)
		.await?;
	transaction.commit().await?;
	Ok(StatusCode::NO_CONTENT.into_response())
}

async fn leave_topic(
	State(app): State<AppState>,
	headers: HeaderMap,
	Path(name): Path<String>,
) -> Answer {
	let caller = context(&app, &headers)?;
	let tenant = &app;
	signed_in(&caller)?;
	let mut client = tenant.pool.get().await?;
	let transaction = as_caller(&mut client, &caller).await?;
	transaction
		.execute(
			"DELETE FROM push.topic_members WHERE topic = $1 AND user_id = push.uid()",
			&[&name],
		)
		.await?;
	transaction.commit().await?;
	Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequest {
	notification: Value,
	#[serde(default)]
	user_ids: Option<Vec<String>>,
	#[serde(default)]
	topic: Option<String>,
	#[serde(default)]
	device_ids: Option<Vec<String>>,
	#[serde(default)]
	send_at: Option<String>,
	#[serde(default)]
	ttl: Option<u32>,
	#[serde(default)]
	priority: Option<String>,
	#[serde(default)]
	collapse_key: Option<String>,
}

/// The size a notification comes to on each transport, refused before it is queued when any is
/// over (an oversized message would otherwise fail per device, later).
fn check_sizes(notification: &Notification, envelope: &Envelope) -> Result<(), ApiError> {
	let apns = Value::Object(apns::payload(notification)).to_string().len();
	if apns > apns::MAX_PAYLOAD {
		return Err(ApiError::new(
			StatusCode::BAD_REQUEST,
			format!(
				"The notification is {apns} bytes for APNs, which carries at most {}.",
				apns::MAX_PAYLOAD
			),
		));
	}
	let message = fcm::message(notification, envelope, "token");
	let carried = json!({"notification": message.get("notification"), "data": message.get("data")})
		.to_string()
		.len();
	if carried > fcm::MAX_PAYLOAD {
		return Err(ApiError::new(
			StatusCode::BAD_REQUEST,
			format!(
				"The notification is {carried} bytes for FCM, which carries at most {}.",
				fcm::MAX_PAYLOAD
			),
		));
	}
	let web = Value::Object(webpush::payload(notification))
		.to_string()
		.len();
	if web > webpush::MAX_PLAINTEXT {
		return Err(ApiError::new(
			StatusCode::BAD_REQUEST,
			format!(
				"The notification is {web} bytes for Web Push, which carries at most {}.",
				webpush::MAX_PLAINTEXT
			),
		));
	}
	Ok(())
}

async fn send(State(app): State<AppState>, headers: HeaderMap, body: axum::body::Bytes) -> Answer {
	let caller = context(&app, &headers)?;
	let tenant = &app;
	let request: SendRequest = json_body(&body)?;
	let bad = |e: String| ApiError::new(StatusCode::BAD_REQUEST, e);
	let priority =
		Priority::parse(request.priority.as_deref().unwrap_or("high")).map_err(|e| bad(e.0))?;
	let envelope = Envelope {
		ttl: request.ttl,
		priority,
		collapse_key: request.collapse_key.clone(),
	};
	let notification = Notification::from_json(&request.notification).map_err(|e| bad(e.0))?;
	notification.validate(&envelope).map_err(|e| bad(e.0))?;
	check_sizes(&notification, &envelope)?;

	let mut client = tenant.pool.get().await?;
	let transaction = as_caller(&mut client, &caller).await?;
	if let Some(send_at) = &request.send_at {
		let future: bool = transaction
			.query_one(
				"SELECT $1::text::timestamptz > now() + make_interval(secs => $2)",
				&[
					send_at as &(dyn ToSql + Sync),
					&(SCHEDULING_GRACE_SECS as f64),
				],
			)
			.await?
			.get(0);
		if future && !tenant.plan.scheduling {
			return Err(ApiError::new(StatusCode::FORBIDDEN, SCHEDULING_REFUSED));
		}
	}
	let priority_text = if priority == Priority::Normal {
		"normal"
	} else {
		"high"
	};
	let ttl = request.ttl.map(|t| i32::try_from(t).unwrap_or(i32::MAX));
	let row = transaction
		.query_one(
			"SELECT push.send($1::jsonb, $2::text[]::uuid[], $3, $4::text[]::uuid[], \
			 coalesce($5::text::timestamptz, now()), $6, $7, $8)",
			&[
				&request.notification as &(dyn ToSql + Sync),
				&request.user_ids,
				&request.topic,
				&request.device_ids,
				&request.send_at,
				&ttl,
				&priority_text,
				&request.collapse_key,
			],
		)
		.await?;
	transaction.commit().await?;
	tenant.nudge.notify_one();
	let id: i64 = row.get(0);
	Ok((StatusCode::ACCEPTED, axum::Json(json!({"id": id}))).into_response())
}

async fn message(State(app): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> Answer {
	let caller = context(&app, &headers)?;
	let tenant = &app;
	let mut client = tenant.pool.get().await?;
	let transaction = as_caller(&mut client, &caller).await?;
	let row = transaction
		.query_opt(
			"SELECT id, status, status_detail, send_at::text, created_at::text, finished_at::text FROM push.messages WHERE id = $1",
			&[&id],
		)
		.await?
		.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "No such message of yours."))?;
	transaction.commit().await?;
	Ok(axum::Json(json!({
		"id": row.get::<_, i64>(0),
		"status": row.get::<_, &str>(1),
		"detail": row.get::<_, Option<&str>>(2),
		"send_at": row.get::<_, Option<&str>>(3),
		"created_at": row.get::<_, Option<&str>>(4),
		"finished_at": row.get::<_, Option<&str>>(5),
	}))
	.into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRequest {
	delivery_id: i64,
	event: String,
}

async fn receipt(
	State(app): State<AppState>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> Answer {
	let caller = context(&app, &headers)?;
	let tenant = &app;
	let request: ReceiptRequest = json_body(&body)?;
	let mut client = tenant.pool.get().await?;
	let transaction = as_caller(&mut client, &caller).await?;
	let found: bool = transaction
		.query_one(
			"SELECT push.report_receipt($1, $2)",
			&[&request.delivery_id as &(dyn ToSql + Sync), &request.event],
		)
		.await?
		.get(0);
	transaction.commit().await?;
	if !found {
		return Err(ApiError::new(
			StatusCode::NOT_FOUND,
			"No such delivery to one of your devices.",
		));
	}
	Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- credentials -------------------------------------------------------------------------

/// Keys are the project's to set, so only the service key may: a user's token, however valid, is
/// refused here before anything is read.
fn service_only(app: &Project, caller: &Caller) -> Result<(), ApiError> {
	if caller.role == app.roles.service {
		Ok(())
	} else {
		Err(ApiError::new(
			StatusCode::FORBIDDEN,
			"Push credentials are set with the project's service key.",
		))
	}
}

async fn credential_summaries(State(app): State<AppState>, headers: HeaderMap) -> Answer {
	let caller = context(&app, &headers)?;
	service_only(&app, &caller)?;
	let client = app.pool.get().await?;
	let rows = client
		.query(
			"SELECT kind, summary, updated_at::text FROM push.credential_summaries()",
			&[],
		)
		.await?;
	let mut out = serde_json::Map::new();
	for row in rows {
		let mut summary: Value = row.get(1);
		summary["updated_at"] = json!(row.get::<_, &str>(2));
		out.insert(row.get::<_, String>(0), summary);
	}
	Ok(axum::Json(Value::Object(out)).into_response())
}

/// Sets APNs or FCM credentials, PROVEN first (PUSH.md, A3): an APNs key must sign a provider
/// token, and a service account must mint a real token from Google. What fails is refused with
/// its sentence and nothing is stored.
async fn set_credentials(
	State(app): State<AppState>,
	headers: HeaderMap,
	Path(kind): Path<String>,
	body: axum::body::Bytes,
) -> Answer {
	let caller = context(&app, &headers)?;
	service_only(&app, &caller)?;
	let bad = |e: String| ApiError::new(StatusCode::BAD_REQUEST, e);
	let (value, summary) = match kind.as_str() {
		"apns" => {
			let parsed: ApnsBody = json_body(&body)?;
			let provider = project::apns_provider(&parsed, &app.policy).map_err(|e| bad(e.0))?;
			provider.prove(now_secs()).map_err(|e| bad(e.0))?;
			let value: Value = serde_json::from_slice(&body).map_err(|e| bad(e.to_string()))?;
			let summary = json!({
				"topic": parsed.topic,
				"keys": parsed.keys.iter().map(|k| json!({"key_id": k.key_id, "team_id": k.team_id, "environment": k.environment})).collect::<Vec<_>>(),
			});
			(value, summary)
		}
		"fcm" => {
			let parsed: FcmBody = json_body(&body)?;
			let provider = project::fcm_provider(&parsed, &app.policy).map_err(|e| bad(e.0))?;
			if let Err(outcome) = provider.prove(now_secs()).await {
				let reason = match outcome {
					crate::notification::Outcome::Credentials { reason }
					| crate::notification::Outcome::Refused { reason }
					| crate::notification::Outcome::Failed { reason, .. } => reason,
					other => format!("{other:?}"),
				};
				return Err(bad(reason));
			}
			let summary = json!({"project_id": provider.project_id(), "client_email": provider.client_email()});
			(json!({"service_account": parsed.service_account}), summary)
		}
		"vapid" => {
			return Err(bad(
				"VAPID keys are made by the server and never replaced in place.".into(),
			));
		}
		_ => {
			return Err(ApiError::new(
				StatusCode::NOT_FOUND,
				"Credentials are apns or fcm.",
			));
		}
	};
	let client = app.pool.get().await?;
	client
		.execute(
			"INSERT INTO push.credentials (kind, value, summary, updated_at) VALUES ($1, $2, $3, now()) \
			 ON CONFLICT (kind) DO UPDATE SET value = excluded.value, summary = excluded.summary, updated_at = now()",
			&[&kind as &(dyn ToSql + Sync), &value, &summary],
		)
		.await?;
	tracing::info!(%kind, "credentials set");
	Ok(axum::Json(summary).into_response())
}

async fn remove_credentials(
	State(app): State<AppState>,
	headers: HeaderMap,
	Path(kind): Path<String>,
) -> Answer {
	let caller = context(&app, &headers)?;
	service_only(&app, &caller)?;
	if kind != "apns" && kind != "fcm" {
		return Err(ApiError::new(
			StatusCode::BAD_REQUEST,
			"Only apns and fcm credentials can be removed.",
		));
	}
	let client = app.pool.get().await?;
	let removed = client
		.execute("DELETE FROM push.credentials WHERE kind = $1", &[&kind])
		.await?;
	if removed == 0 {
		return Err(ApiError::new(
			StatusCode::NOT_FOUND,
			"There are none of those to remove.",
		));
	}
	Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::drain::Plan;
	use crate::migrations::Roles;
	use crate::net::Policy;

	/// The whole product, as it runs in a pod, against a real Postgres (tests/db.sh) and a stand-in
	/// Apple: the sender makes its VAPID keys, the service key sets an APNs key it has proven, an
	/// app registers a device, a server sends, the drain delivers, the app reports it opened.
	#[tokio::test]
	async fn the_whole_product() {
		let Some((_db, url)) = crate::testing::fresh_database("api").await else {
			eprintln!("skipped: PUSH_TEST_DATABASE_URL is not set (tests/db.sh sets it)");
			return;
		};
		const SECRET: &str = "a-project-secret-of-at-least-32-chars";
		const ALICE: &str = "00000000-0000-4000-8000-00000000000a";
		const BOB: &str = "00000000-0000-4000-8000-00000000000b";
		let (origin, mut apple) =
			crate::net::tests::stand_in(200, vec![("apns-id", "accepted-1")], vec![]).await;
		let project = Arc::new(
			Project::new(
				&url,
				SECRET.into(),
				Plan::from_pod(256, false),
				"mailto:push@example.com".into(),
				Roles {
					install_roles: true,
					..Roles::default()
				},
				Policy::local(&origin),
			)
			.unwrap(),
		);
		tokio::spawn(project::run(project.clone(), url.clone()));
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let public = format!("http://{}", listener.local_addr().unwrap());
		let router = public_router(project.clone());
		tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
		let http = reqwest::Client::new();

		let now = now_secs();
		let alice = jwt::sign(
			&json!({"sub": ALICE, "role": "authenticated", "exp": now + 3600}),
			SECRET,
		);
		let bob = jwt::sign(
			&json!({"sub": BOB, "role": "authenticated", "exp": now + 3600}),
			SECRET,
		);
		let server = jwt::sign(&json!({"role": "service_role", "exp": now + 3600}), SECRET);
		let call = |method: reqwest::Method, path: &str, token: &str| {
			http.request(method, format!("{public}{path}"))
				.header("authorization", format!("Bearer {token}"))
		};

		// The sender makes the project's VAPID keys itself on first start.
		let mut vapid = Value::Null;
		for _ in 0..100 {
			let answer = call(reqwest::Method::GET, "/push/v1/vapid-public-key", &alice)
				.send()
				.await
				.unwrap();
			if answer.status() == 200 {
				vapid = answer.json().await.unwrap();
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
		}
		assert_eq!(vapid["key"].as_str().map(str::len), Some(87), "{vapid}");

		// Keys are the service key's to set; a user is refused, a bad key is refused with its sentence.
		let (_, der) = crate::keys::EsKey::generate().unwrap();
		use base64::Engine;
		let p8 = crate::keys::test_pem(&base64::engine::general_purpose::STANDARD.encode(der));
		let apns = json!({"topic": "com.example.app", "keys": [{"p8": p8, "key_id": "KEY0000001", "team_id": "TEAM123456"}]});
		assert_eq!(
			call(reqwest::Method::PUT, "/push/v1/credentials/apns", &alice)
				.json(&apns)
				.send()
				.await
				.unwrap()
				.status(),
			403
		);
		let bad = json!({"topic": "com.example.app", "keys": [{"p8": "nope", "key_id": "KEY0000001", "team_id": "TEAM123456"}]});
		let refused = call(reqwest::Method::PUT, "/push/v1/credentials/apns", &server)
			.json(&bad)
			.send()
			.await
			.unwrap();
		assert_eq!(refused.status(), 400);
		let set = call(reqwest::Method::PUT, "/push/v1/credentials/apns", &server)
			.json(&apns)
			.send()
			.await
			.unwrap();
		assert_eq!(set.status(), 200, "{}", set.text().await.unwrap());
		let summaries: Value = call(reqwest::Method::GET, "/push/v1/credentials", &server)
			.send()
			.await
			.unwrap()
			.json()
			.await
			.unwrap();
		assert_eq!(summaries["apns"]["keys"][0]["key_id"], "KEY0000001");
		assert!(summaries["vapid"]["public_key"].is_string());
		assert!(
			!summaries.to_string().contains("PRIVATE"),
			"no key comes back out"
		);

		// Alice's phone registers.
		let token = "a1".repeat(32);
		let device = call(reqwest::Method::POST, "/push/v1/devices", &alice)
			.json(&json!({"transport": "apns", "token": token, "environment": "production"}))
			.send()
			.await
			.unwrap();
		assert_eq!(device.status(), 201);
		let device_id = device.json::<Value>().await.unwrap()["id"]
			.as_str()
			.unwrap()
			.to_string();

		// P8: a user may not send without a policy. P4 on free: a future send_at is refused.
		let refused = call(reqwest::Method::POST, "/push/v1/send", &alice)
			.json(&json!({"notification": {"title": "hi"}, "user_ids": [BOB]}))
			.send()
			.await
			.unwrap();
		assert_eq!(refused.status(), 403);
		let later = call(reqwest::Method::POST, "/push/v1/send", &server)
			.json(&json!({"notification": {"title": "later"}, "user_ids": [ALICE], "send_at": "2999-01-01T00:00:00Z"}))
			.send()
			.await
			.unwrap();
		assert_eq!(later.status(), 403);
		assert_eq!(
			later.json::<Value>().await.unwrap()["error"],
			SCHEDULING_REFUSED
		);

		// The APNs key reached the running sender without a restart: the send is delivered.
		let sent = call(reqwest::Method::POST, "/push/v1/send", &server)
			.json(&json!({"notification": {"title": "Your order shipped", "data": {"order": 42}}, "user_ids": [ALICE]}))
			.send()
			.await
			.unwrap();
		assert_eq!(sent.status(), 202);
		let id = sent.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
		let (path, _, payload) =
			tokio::time::timeout(std::time::Duration::from_secs(15), apple.recv())
				.await
				.expect("the drain delivered within 15 seconds")
				.unwrap();
		assert_eq!(path, format!("/3/device/{token}"));
		let payload: Value = serde_json::from_slice(&payload).unwrap();
		assert_eq!(payload["aps"]["alert"]["title"], "Your order shipped");
		let delivery = payload[crate::notification::DELIVERY_KEY]
			.as_i64()
			.expect("the delivery id rides along");
		let mut status = Value::Null;
		for _ in 0..50 {
			status = call(
				reqwest::Method::GET,
				&format!("/push/v1/messages/{id}"),
				&server,
			)
			.send()
			.await
			.unwrap()
			.json()
			.await
			.unwrap();
			if status["status"] == "sent" {
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
		}
		assert_eq!(status["status"], "sent", "{status}");

		// The receipt is Alice's to give, and only Alice removes Alice's device.
		let receipt = |token: &str| {
			call(reqwest::Method::POST, "/push/v1/receipts", token)
				.json(&json!({"delivery_id": delivery, "event": "opened"}))
		};
		assert_eq!(receipt(&bob).send().await.unwrap().status(), 404);
		assert_eq!(receipt(&alice).send().await.unwrap().status(), 204);
		let path = format!("/push/v1/devices/{device_id}");
		assert_eq!(
			call(reqwest::Method::DELETE, &path, &bob)
				.send()
				.await
				.unwrap()
				.status(),
			404
		);
		assert_eq!(
			call(reqwest::Method::DELETE, &path, &alice)
				.send()
				.await
				.unwrap()
				.status(),
			204
		);

		// Removing the key turns APNs off in the running sender.
		assert_eq!(
			call(
				reqwest::Method::DELETE,
				"/push/v1/credentials/apns",
				&server
			)
			.send()
			.await
			.unwrap()
			.status(),
			204
		);
		assert_eq!(
			call(
				reqwest::Method::DELETE,
				"/push/v1/credentials/vapid",
				&server
			)
			.send()
			.await
			.unwrap()
			.status(),
			400
		);
	}
}
