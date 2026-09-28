//! One project's way to each transport: its credentials, the tokens minted from them, and the
//! HTTP client they travel on. The drain hands a device and a notification to
//! [`Providers::deliver`] and gets back an [`Outcome`]; everything between is here.
//!
//! What each provider remembers:
//!  - **APNs**: a provider token per key, renewed after 40 minutes (Apple: no sooner than 20, no
//!    later than 60), and renewed early exactly once if Apple says it expired. Its own HTTP client,
//!    because Apple binds a connection to one team (PUSH.md, A6).
//!  - **FCM**: an access token, renewed five minutes before Google's `expires_in`, and once if
//!    Google says it is no longer valid.
//!  - **Web Push**: the project's VAPID keys by id, since a subscription only ever takes the key it
//!    was made with (A8).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::apns::{self, Environment};
use crate::fcm;
use crate::keys::EsKey;
use crate::net::{Http, NetError};
use crate::notification::{Envelope, Notification, NotificationError, Outcome};
use crate::webpush;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
	Apns,
	Fcm,
	Web,
}

impl Transport {
	pub fn parse(text: &str) -> Option<Self> {
		match text {
			"apns" => Some(Self::Apns),
			"fcm" => Some(Self::Fcm),
			"web" => Some(Self::Web),
			_ => None,
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Self::Apns => "apns",
			Self::Fcm => "fcm",
			Self::Web => "web",
		}
	}
}

/// A row of `push.devices`, as much of it as sending needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
	pub id: String,
	pub transport: Transport,
	pub token: String,
	pub web_p256dh: Option<String>,
	pub web_auth: Option<String>,
	pub vapid_key_id: Option<String>,
	pub apns_environment: Option<String>,
	pub app: Option<String>,
}

fn refused(error: NotificationError) -> Outcome {
	Outcome::Refused { reason: error.0 }
}

/// A network failure: a refusal by our own rules never succeeds on retry; anything else may.
fn network(error: NetError, who: &str) -> Outcome {
	match error {
		NetError::Refused(reason) => Outcome::Refused {
			reason: format!("{who}: {reason}"),
		},
		NetError::Transport(reason) => Outcome::Failed {
			reason: format!("{who}: {reason}"),
			retry_after: Some(5),
		},
	}
}

/// A project's APNs keys: one for both environments, or one per environment (A6).
pub struct Apns {
	keys: Vec<(Option<Environment>, apns::Credentials)>,
	default_topic: String,
	http: Http,
	tokens: Mutex<HashMap<String, (String, u64)>>,
}

impl Apns {
	/// `keys` pairs each key with the environment it is restricted to, or `None` for both.
	pub fn new(
		keys: Vec<(Option<Environment>, apns::Credentials)>,
		default_topic: &str,
		http: Http,
	) -> Result<Self, NotificationError> {
		apns::check_topic(default_topic)?;
		if keys.is_empty() {
			return Err(NotificationError(
				"An APNs setup needs at least one key.".into(),
			));
		}
		Ok(Self {
			keys,
			default_topic: default_topic.to_string(),
			http,
			tokens: Mutex::new(HashMap::new()),
		})
	}

	fn key_for(&self, environment: Environment) -> Option<&apns::Credentials> {
		self.keys
			.iter()
			.find(|(only, _)| *only == Some(environment))
			.or_else(|| self.keys.iter().find(|(only, _)| only.is_none()))
			.map(|(_, key)| key)
	}

	fn token(
		&self,
		key: &apns::Credentials,
		now: u64,
		renew: bool,
	) -> Result<String, NotificationError> {
		let mut tokens = self.tokens.lock().unwrap_or_else(|p| p.into_inner());
		if !renew
			&& let Some((token, issued)) = tokens.get(&key.key_id)
			&& now.saturating_sub(*issued) < apns::TOKEN_REFRESH_SECS
		{
			return Ok(token.clone());
		}
		let token = key.provider_token(now)?;
		tokens.insert(key.key_id.clone(), (token.clone(), now));
		Ok(token)
	}

	/// Proves every key signs a provider token (PUSH.md, A3), before any of them is stored.
	pub fn prove(&self, now: u64) -> Result<(), NotificationError> {
		for (_, key) in &self.keys {
			key.provider_token(now)?;
		}
		Ok(())
	}

	pub async fn deliver(
		&self,
		notification: &Notification,
		envelope: &Envelope,
		device: &Device,
		now: u64,
	) -> Outcome {
		let environment = match Environment::parse(device.apns_environment.as_deref().unwrap_or(""))
		{
			Ok(environment) => environment,
			Err(error) => return refused(error),
		};
		let Some(key) = self.key_for(environment) else {
			let which = if environment == Environment::Sandbox {
				"sandbox"
			} else {
				"production"
			};
			return Outcome::Credentials {
				reason: format!("This project has no APNs key for the {which} environment."),
			};
		};
		let topic = device.app.as_deref().unwrap_or(&self.default_topic);
		for renew in [false, true] {
			let token = match self.token(key, now, renew) {
				Ok(token) => token,
				Err(error) => return Outcome::Credentials { reason: error.0 },
			};
			let request = match apns::request(
				notification,
				envelope,
				&device.token,
				environment,
				topic,
				&token,
				now,
			) {
				Ok(request) => request,
				Err(error) => return refused(error),
			};
			let response = match self.http.send(&request).await {
				Ok(response) => response,
				Err(error) => return network(error, "APNs"),
			};
			let outcome = apns::classify(
				response.status,
				response.header("apns-id"),
				response.header("retry-after"),
				&response.body,
			);
			// ExpiredProviderToken: renew once, now, and try again.
			if !renew
				&& matches!(
					outcome,
					Outcome::Failed {
						retry_after: Some(0),
						..
					}
				) {
				continue;
			}
			return outcome;
		}
		unreachable!("the loop returns on its second pass")
	}
}

/// A project's Firebase service account.
pub struct Fcm {
	credentials: fcm::Credentials,
	http: Http,
	token: tokio::sync::Mutex<Option<(String, u64)>>,
}

/// Renew an access token this long before Google says it expires.
const FCM_TOKEN_MARGIN_SECS: u64 = 300;

impl Fcm {
	pub fn new(credentials: fcm::Credentials, http: Http) -> Self {
		Self {
			credentials,
			http,
			token: tokio::sync::Mutex::new(None),
		}
	}

	/// The access token. Held under an async lock so a burst of sends mints one token, not one each.
	async fn access_token(&self, now: u64, renew: bool) -> Result<String, Outcome> {
		let mut cached = self.token.lock().await;
		if !renew
			&& let Some((token, expires)) = cached.as_ref()
			&& now + FCM_TOKEN_MARGIN_SECS < *expires
		{
			return Ok(token.clone());
		}
		let request = self
			.credentials
			.token_request(now)
			.map_err(|e| Outcome::Credentials { reason: e.0 })?;
		let response = self
			.http
			.send(&request)
			.await
			.map_err(|e| network(e, "Google's token endpoint"))?;
		let (token, lifetime) = fcm::parse_token_response(response.status, &response.body)?;
		*cached = Some((token.clone(), now + lifetime));
		Ok(token)
	}

	pub fn project_id(&self) -> &str {
		&self.credentials.project_id
	}

	pub fn client_email(&self) -> &str {
		&self.credentials.client_email
	}

	/// Proves the credentials work by minting a real token (A3: nothing that fails is stored).
	pub async fn prove(&self, now: u64) -> Result<(), Outcome> {
		self.access_token(now, true).await.map(|_| ())
	}

	pub async fn deliver(
		&self,
		notification: &Notification,
		envelope: &Envelope,
		device: &Device,
		now: u64,
	) -> Outcome {
		for renew in [false, true] {
			let token = match self.access_token(now, renew).await {
				Ok(token) => token,
				Err(outcome) => return outcome,
			};
			let request = match fcm::request(
				notification,
				envelope,
				&device.token,
				&self.credentials.project_id,
				&token,
			) {
				Ok(request) => request,
				Err(error) => return refused(error),
			};
			let response = match self.http.send(&request).await {
				Ok(response) => response,
				Err(error) => return network(error, "FCM"),
			};
			let outcome = fcm::classify(
				response.status,
				response.header("retry-after"),
				&response.body,
			);
			// UNAUTHENTICATED: the token was revoked or expired early; mint one more and retry.
			if !renew
				&& matches!(
					outcome,
					Outcome::Failed {
						retry_after: Some(0),
						..
					}
				) {
				continue;
			}
			return outcome;
		}
		unreachable!("the loop returns on its second pass")
	}
}

/// A project's VAPID keys, by id. `current` signs devices that recorded no key.
pub struct Web {
	keys: HashMap<String, EsKey>,
	current: String,
	subject: String,
	http: Http,
}

impl Web {
	/// `subject` is the contact RFC 8292 asks for; Apple refuses anything but `mailto:` or `https:`.
	pub fn new(
		keys: HashMap<String, EsKey>,
		current: &str,
		subject: &str,
		http: Http,
	) -> Result<Self, NotificationError> {
		if !keys.contains_key(current) {
			return Err(NotificationError(
				"The current VAPID key is not among the project's keys.".into(),
			));
		}
		if !(subject.starts_with("mailto:") || subject.starts_with("https://")) {
			return Err(NotificationError(
				"The VAPID subject is a mailto: or https: URL.".into(),
			));
		}
		Ok(Self {
			keys,
			current: current.to_string(),
			subject: subject.to_string(),
			http,
		})
	}

	pub fn public_key(&self) -> &[u8] {
		self.keys[&self.current].public_key()
	}

	/// The key a new subscription is made with, recorded on its device row (A8).
	pub fn current_id(&self) -> &str {
		&self.current
	}

	pub async fn deliver(
		&self,
		notification: &Notification,
		envelope: &Envelope,
		device: &Device,
		now: u64,
	) -> Outcome {
		let subscription = match webpush::Subscription::parse(
			&device.token,
			device.web_p256dh.as_deref().unwrap_or(""),
			device.web_auth.as_deref().unwrap_or(""),
		) {
			Ok(subscription) => subscription,
			// A stored subscription that no longer passes the rules can never be sent to.
			Err(error) => {
				return Outcome::Unregistered {
					reason: error.0,
					since_ms: None,
				};
			}
		};
		let key_id = device.vapid_key_id.as_deref().unwrap_or(&self.current);
		let Some(key) = self.keys.get(key_id) else {
			return Outcome::Unregistered {
				reason: format!(
					"The subscription was made with VAPID key {key_id}, which this project no longer has."
				),
				since_ms: None,
			};
		};
		let request = match webpush::request(
			notification,
			envelope,
			&subscription,
			key,
			&self.subject,
			now,
		) {
			Ok(request) => request,
			Err(error) => return Outcome::Refused { reason: error.0 },
		};
		match self.http.send(&request).await {
			Ok(response) => webpush::classify(
				response.status,
				response.header("location"),
				response.header("retry-after"),
				&response.body,
			),
			Err(error) => network(error, "Web Push"),
		}
	}
}

/// Everything one project can send through. A transport it has not set up answers every device
/// on it with a sentence, rather than being skipped in silence.
#[derive(Default)]
pub struct Providers {
	pub apns: Option<Apns>,
	pub fcm: Option<Fcm>,
	pub web: Option<Web>,
}

/// Which transports are set up, and nothing about their keys.
impl std::fmt::Debug for Providers {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Providers")
			.field("apns", &self.apns.is_some())
			.field("fcm", &self.fcm.is_some())
			.field("web", &self.web.is_some())
			.finish()
	}
}

impl Providers {
	pub async fn deliver(
		&self,
		notification: &Notification,
		envelope: &Envelope,
		device: &Device,
		now: u64,
	) -> Outcome {
		let missing = |what: &str| Outcome::Credentials {
			reason: format!(
				"This project has not set up {what}; add it in the project's Push settings."
			),
		};
		match device.transport {
			Transport::Apns => match &self.apns {
				Some(apns) => apns.deliver(notification, envelope, device, now).await,
				None => missing("APNs (an Apple .p8 key)"),
			},
			Transport::Fcm => match &self.fcm {
				Some(fcm) => fcm.deliver(notification, envelope, device, now).await,
				None => missing("FCM (a Firebase service account)"),
			},
			Transport::Web => match &self.web {
				Some(web) => web.deliver(notification, envelope, device, now).await,
				None => missing("Web Push"),
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::net::Policy;
	use crate::net::tests::{stand_in, stand_in_with};
	use serde_json::json;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};

	fn note() -> Notification {
		Notification::from_json(&json!({"title": "Hi", "body": "There"})).unwrap()
	}

	fn apns_key(key_id: &str) -> apns::Credentials {
		let (_, der) = EsKey::generate().unwrap();
		use base64::Engine;
		let p8 = crate::keys::test_pem(&base64::engine::general_purpose::STANDARD.encode(der));
		apns::Credentials::new(&p8, key_id, "TEAM123456").unwrap()
	}

	fn apns_device(environment: &str) -> Device {
		Device {
			id: "d1".into(),
			transport: Transport::Apns,
			token: "a1".repeat(32),
			web_p256dh: None,
			web_auth: None,
			vapid_key_id: None,
			apns_environment: Some(environment.into()),
			app: None,
		}
	}

	#[tokio::test]
	async fn apns_sends_and_reuses_its_token() {
		let (origin, mut seen) = stand_in(200, vec![("apns-id", "id-1")], vec![]).await;
		let apns = Apns::new(
			vec![(None, apns_key("KEY0000001"))],
			"com.example.app",
			Http::new(Policy::local(&origin)).unwrap(),
		)
		.unwrap();
		let outcome = apns
			.deliver(
				&note(),
				&Envelope::default(),
				&apns_device("production"),
				1_000,
			)
			.await;
		assert_eq!(
			outcome,
			Outcome::Accepted {
				provider_id: Some("id-1".into())
			}
		);
		let _ = apns
			.deliver(
				&note(),
				&Envelope::default(),
				&apns_device("sandbox"),
				1_100,
			)
			.await;
		let first = seen.recv().await.unwrap();
		let second = seen.recv().await.unwrap();
		let auth = |s: &crate::net::tests::Seen| {
			s.1.iter()
				.find(|(n, _)| n == "authorization")
				.unwrap()
				.1
				.clone()
		};
		assert_eq!(
			auth(&first),
			auth(&second),
			"one token for 40 minutes, across environments"
		);
		assert!(first.0.starts_with("/3/device/"));
	}

	#[tokio::test]
	async fn apns_picks_the_key_for_the_devices_environment() {
		let (origin, mut seen) = stand_in(200, vec![], vec![]).await;
		let http = Http::new(Policy::local(&origin)).unwrap();
		let apns = Apns::new(
			vec![(Some(Environment::Sandbox), apns_key("SANDBOX001"))],
			"com.example.app",
			http,
		)
		.unwrap();
		let outcome = apns
			.deliver(&note(), &Envelope::default(), &apns_device("production"), 0)
			.await;
		assert!(
			matches!(&outcome, Outcome::Credentials { reason } if reason.contains("production")),
			"{outcome:?}"
		);
		apns.deliver(&note(), &Envelope::default(), &apns_device("sandbox"), 0)
			.await;
		let (_, headers, _) = seen.recv().await.unwrap();
		let token = headers
			.iter()
			.find(|(n, _)| n == "authorization")
			.unwrap()
			.1
			.trim_start_matches("bearer ")
			.to_string();
		let header: serde_json::Value = serde_json::from_slice(
			&crate::b64url_decode(token.split('.').next().unwrap()).unwrap(),
		)
		.unwrap();
		assert_eq!(header["kid"], "SANDBOX001");
	}

	#[tokio::test]
	async fn apns_renews_an_expired_token_once() {
		let calls = Arc::new(AtomicUsize::new(0));
		let counter = calls.clone();
		let (origin, _seen) = stand_in_with(move |_| {
			if counter.fetch_add(1, Ordering::SeqCst) == 0 {
				(
					403,
					vec![],
					br#"{"reason":"ExpiredProviderToken"}"#.to_vec(),
				)
			} else {
				(200, vec![("apns-id", "id-2")], vec![])
			}
		})
		.await;
		let apns = Apns::new(
			vec![(None, apns_key("KEY0000001"))],
			"com.example.app",
			Http::new(Policy::local(&origin)).unwrap(),
		)
		.unwrap();
		let outcome = apns
			.deliver(&note(), &Envelope::default(), &apns_device("production"), 0)
			.await;
		assert_eq!(
			outcome,
			Outcome::Accepted {
				provider_id: Some("id-2".into())
			}
		);
		assert_eq!(calls.load(Ordering::SeqCst), 2);
	}

	#[tokio::test]
	async fn fcm_mints_a_token_then_sends() {
		let Ok(out) = std::process::Command::new("openssl")
			.args([
				"genpkey",
				"-algorithm",
				"RSA",
				"-pkeyopt",
				"rsa_keygen_bits:2048",
			])
			.output()
		else {
			eprintln!("skipped: no openssl");
			return;
		};
		let file = json!({"type": "service_account", "project_id": "my-app-1234", "private_key": String::from_utf8(out.stdout).unwrap(),
			"client_email": "push@my-app-1234.iam.gserviceaccount.com"});
		let (origin, mut seen) = stand_in_with(|path: &str| {
			if path == "/token" {
				(
					200,
					vec![],
					br#"{"access_token":"ya29.test","expires_in":3599}"#.to_vec(),
				)
			} else {
				(
					200,
					vec![],
					br#"{"name":"projects/my-app-1234/messages/0:1"}"#.to_vec(),
				)
			}
		})
		.await;
		let fcm = Fcm::new(
			fcm::Credentials::from_json(&file.to_string()).unwrap(),
			Http::new(Policy::local(&origin)).unwrap(),
		);
		let device = Device {
			transport: Transport::Fcm,
			token: "fGx0c1ZlQ0y:APA91bHq8zX_abcdefghijklmnopqrstuvwxyz".into(),
			apns_environment: None,
			..apns_device("x")
		};
		for now in [0, 60] {
			let outcome = fcm
				.deliver(&note(), &Envelope::default(), &device, now)
				.await;
			assert_eq!(
				outcome,
				Outcome::Accepted {
					provider_id: Some("projects/my-app-1234/messages/0:1".into())
				}
			);
		}
		let paths: Vec<String> = std::iter::from_fn(|| seen.try_recv().ok())
			.map(|s| s.0)
			.collect();
		assert_eq!(
			paths,
			[
				"/token",
				"/v1/projects/my-app-1234/messages:send",
				"/v1/projects/my-app-1234/messages:send"
			],
			"one token for both sends"
		);
	}

	#[tokio::test]
	async fn web_push_sends_with_the_key_the_device_subscribed_under() {
		use ring::agreement::{ECDH_P256, EphemeralPrivateKey};
		let (origin, mut seen) = stand_in(
			201,
			vec![("location", "https://fcm.googleapis.com/m/1")],
			vec![],
		)
		.await;
		let (old, _) = EsKey::generate().unwrap();
		let (new, _) = EsKey::generate().unwrap();
		let old_public = old.public_key().to_vec();
		let keys = HashMap::from([("k1".to_string(), old), ("k2".to_string(), new)]);
		let web = Web::new(
			keys,
			"k2",
			"mailto:push@example.com",
			Http::new(Policy::local(&origin)).unwrap(),
		)
		.unwrap();
		let browser =
			EphemeralPrivateKey::generate(&ECDH_P256, &ring::rand::SystemRandom::new()).unwrap();
		let device = Device {
			id: "w1".into(),
			transport: Transport::Web,
			token: "https://fcm.googleapis.com/fcm/send/abc".into(),
			web_p256dh: Some(crate::b64url(
				browser.compute_public_key().unwrap().as_ref(),
			)),
			web_auth: Some(crate::b64url(&[9; 16])),
			vapid_key_id: Some("k1".into()),
			apns_environment: None,
			app: None,
		};
		let outcome = web.deliver(&note(), &Envelope::default(), &device, 0).await;
		assert_eq!(
			outcome,
			Outcome::Accepted {
				provider_id: Some("https://fcm.googleapis.com/m/1".into())
			}
		);
		let (path, headers, _) = seen.recv().await.unwrap();
		assert_eq!(path, "/fcm/send/abc");
		let auth = &headers
			.iter()
			.find(|(n, _)| n == "authorization")
			.unwrap()
			.1;
		assert!(
			auth.ends_with(&format!("k={}", crate::b64url(&old_public))),
			"signed with k1, the key it subscribed under"
		);

		let gone = Device {
			vapid_key_id: Some("k0".into()),
			..device
		};
		assert!(matches!(
			web.deliver(&note(), &Envelope::default(), &gone, 0).await,
			Outcome::Unregistered { .. }
		));
	}

	#[tokio::test]
	async fn a_transport_not_set_up_says_so() {
		let providers = Providers::default();
		let outcome = providers
			.deliver(&note(), &Envelope::default(), &apns_device("production"), 0)
			.await;
		assert!(
			matches!(&outcome, Outcome::Credentials { reason } if reason.contains(".p8")),
			"{outcome:?}"
		);
	}
}
