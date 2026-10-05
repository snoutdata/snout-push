//! APNs: the only way to reach a native app on an iPhone, iPad, Mac or Watch.
//!
//! HTTP/2 to Apple, one request per device, authenticated with a provider token: an ES256 JWT
//! signed with the customer's `.p8` key (key id + team id). A key serves every app of the team and
//! does not expire yearly as certificates did, so certificates are not supported at all. Apple
//! now also issues keys restricted to ONE environment, so a project may hold a key per
//! environment; which key signs is chosen by the device's environment. Apple wants the token renewed at most every 20 minutes and at least every 60.
//!
//! The environment belongs to the DEVICE, not the project: a development build's token is only
//! valid against the sandbox, and sending it to production is Apple's single most common
//! "BadDeviceToken". The client SDK records which one it registered from.

use serde_json::{Map, Value, json};

use crate::keys::EsKey;
use crate::notification::{
	Envelope, Notification, NotificationError, Outcome, Priority, Request, merge, retry_after,
};

/// Apple caps an alert or background payload at 4 KB.
pub const MAX_PAYLOAD: usize = 4096;
/// Renew between Apple's floor (20 minutes) and ceiling (60).
pub const TOKEN_REFRESH_SECS: u64 = 40 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
	Production,
	Sandbox,
}

impl Environment {
	pub fn parse(text: &str) -> Result<Self, NotificationError> {
		match text {
			"production" => Ok(Self::Production),
			"sandbox" => Ok(Self::Sandbox),
			other => Err(NotificationError(format!(
				"apns_environment is \"production\" or \"sandbox\", not \"{other}\"."
			))),
		}
	}

	pub fn host(self) -> &'static str {
		match self {
			Self::Production => "api.push.apple.com",
			Self::Sandbox => "api.sandbox.push.apple.com",
		}
	}
}

/// A project's APNs key. Holds the private key in memory only.
#[derive(Debug)]
pub struct Credentials {
	key: EsKey,
	pub key_id: String,
	pub team_id: String,
}

/// Apple's key and team ids are ten characters, upper-case letters and digits.
fn apple_id(text: &str, what: &str) -> Result<String, NotificationError> {
	let text = text.trim();
	if text.len() == 10
		&& text
			.bytes()
			.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
	{
		Ok(text.to_string())
	} else {
		Err(NotificationError(format!(
			"The APNs {what} is ten capital letters and digits, as shown in Apple's developer account."
		)))
	}
}

impl Credentials {
	pub fn new(p8: &str, key_id: &str, team_id: &str) -> Result<Self, NotificationError> {
		Ok(Self {
			key: EsKey::from_pem(p8).map_err(|e| NotificationError(e.0))?,
			key_id: apple_id(key_id, "key ID")?,
			team_id: apple_id(team_id, "team ID")?,
		})
	}

	/// A provider token issued at `now`. The caller keeps it for [`TOKEN_REFRESH_SECS`].
	pub fn provider_token(&self, now: u64) -> Result<String, NotificationError> {
		self.key
			.jwt(
				&json!({"alg": "ES256", "kid": self.key_id}),
				&json!({"iss": self.team_id, "iat": now}),
			)
			.map_err(|e| NotificationError(e.0))
	}
}

/// A device token as an app hands it over: hex. Apple warns tokens may grow, so any even length
/// from 32 to 200 bytes of hex is taken; it is stored lower-case so a device registers once.
pub fn check_device_token(text: &str) -> Result<String, NotificationError> {
	let text = text.trim();
	if (64..=400).contains(&text.len())
		&& text.len().is_multiple_of(2)
		&& text.bytes().all(|b| b.is_ascii_hexdigit())
	{
		Ok(text.to_ascii_lowercase())
	} else {
		Err(NotificationError(
			"An APNs device token is a hex string (usually 64 characters).".into(),
		))
	}
}

/// A bundle id: the `apns-topic`. Letters, digits, dots and hyphens.
pub fn check_topic(text: &str) -> Result<(), NotificationError> {
	let ok = !text.is_empty()
		&& text.len() <= 255
		&& text
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
	if ok {
		Ok(())
	} else {
		Err(NotificationError(format!(
			"\"{text}\" is not an app bundle ID."
		)))
	}
}

/// The payload Apple reads: `aps` plus the customer's data beside it.
pub fn payload(notification: &Notification) -> Map<String, Value> {
	let mut aps = Map::new();
	if notification.background {
		aps.insert("content-available".into(), json!(1));
	} else {
		let mut alert = Map::new();
		if let Some(title) = &notification.title {
			alert.insert("title".into(), json!(title));
		}
		if let Some(body) = &notification.body {
			alert.insert("body".into(), json!(body));
		}
		aps.insert("alert".into(), Value::Object(alert));
		if let Some(sound) = &notification.sound {
			aps.insert("sound".into(), json!(sound));
		}
		if notification.image.is_some() {
			// A notification service extension fetches the image; this is what wakes it.
			aps.insert("mutable-content".into(), json!(1));
		}
	}
	if let Some(badge) = notification.badge {
		aps.insert("badge".into(), json!(badge));
	}
	if let Some(thread) = &notification.thread {
		aps.insert("thread-id".into(), json!(thread));
	}
	let mut root = Map::new();
	root.insert("aps".into(), Value::Object(aps));
	for (k, v) in &notification.data {
		root.insert(k.clone(), v.clone());
	}
	if let Some(image) = &notification.image {
		root.insert("image".into(), json!(image));
	}
	merge(&mut root, &notification.apns);
	root
}

/// The request for one device.
pub fn request(
	notification: &Notification,
	envelope: &Envelope,
	device_token: &str,
	environment: Environment,
	topic: &str,
	provider_token: &str,
	now: u64,
) -> Result<Request, NotificationError> {
	check_topic(topic)?;
	let body = Value::Object(payload(notification))
		.to_string()
		.into_bytes();
	if body.len() > MAX_PAYLOAD {
		return Err(NotificationError(format!(
			"The notification is {} bytes for APNs, which carries at most {MAX_PAYLOAD}.",
			body.len()
		)));
	}
	let mut headers = vec![
		(
			"authorization".to_string(),
			format!("bearer {provider_token}"),
		),
		("apns-topic".to_string(), topic.to_string()),
		(
			"apns-push-type".to_string(),
			if notification.background {
				"background"
			} else {
				"alert"
			}
			.to_string(),
		),
		(
			// Apple rejects priority 10 on a background push.
			"apns-priority".to_string(),
			if notification.background || envelope.priority == Priority::Normal {
				"5"
			} else {
				"10"
			}
			.to_string(),
		),
	];
	if let Some(ttl) = envelope.ttl {
		let expiration = if ttl == 0 { 0 } else { now + u64::from(ttl) };
		headers.push(("apns-expiration".to_string(), expiration.to_string()));
	}
	if let Some(key) = &envelope.collapse_key {
		headers.push(("apns-collapse-id".to_string(), key.clone()));
	}
	headers.push(("content-type".to_string(), "application/json".to_string()));
	Ok(Request {
		url: format!("https://{}/3/device/{device_token}", environment.host()),
		headers,
		body,
	})
}

/// Apple's answer. `apns_id` is the `apns-id` response header.
pub fn classify(
	status: u16,
	apns_id: Option<&str>,
	retry_after_header: Option<&str>,
	body: &[u8],
) -> Outcome {
	if status == 200 {
		return Outcome::Accepted {
			provider_id: apns_id.map(str::to_string),
		};
	}
	let parsed = serde_json::from_slice::<Value>(body).ok();
	let reason = parsed
		.as_ref()
		.and_then(|v| v.get("reason").and_then(Value::as_str).map(str::to_string))
		.unwrap_or_else(|| format!("HTTP {status}"));
	let since_ms = parsed
		.as_ref()
		.and_then(|v| v.get("timestamp").and_then(Value::as_u64));
	let said = format!("APNs: {reason}");
	match (status, reason.as_str()) {
		(410, _) => Outcome::Unregistered {
			reason: said,
			since_ms,
		},
		(400, "BadDeviceToken") => Outcome::Unregistered {
			reason: said,
			since_ms: None,
		},
		(403, "ExpiredProviderToken") => Outcome::Failed {
			reason: said,
			retry_after: Some(0),
		},
		(403, _) | (400, "TopicDisallowed" | "BadCertificateEnvironment" | "BadCertificate") => {
			Outcome::Credentials { reason: said }
		}
		(429, _) => Outcome::Failed {
			reason: said,
			retry_after: Some(retry_after(retry_after_header, 5)),
		},
		(500..=599, _) => Outcome::Failed {
			reason: said,
			retry_after: Some(retry_after(retry_after_header, 5)),
		},
		_ => Outcome::Failed {
			reason: said,
			retry_after: None,
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::notification::Notification;

	fn note(value: Value) -> Notification {
		Notification::from_json(&value).unwrap()
	}

	const TOKEN: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

	#[test]
	fn an_alert() {
		let n = note(
			json!({"title": "Order shipped", "body": "Arrives Tuesday", "badge": 2, "sound": "default",
			"thread": "orders", "data": {"order": 42}}),
		);
		let r = request(
			&n,
			&Envelope {
				ttl: Some(3600),
				collapse_key: Some("order-42".into()),
				..Default::default()
			},
			TOKEN,
			Environment::Production,
			"com.example.app",
			"TOKEN",
			1_000,
		)
		.unwrap();
		assert_eq!(
			r.url,
			format!("https://api.push.apple.com/3/device/{TOKEN}")
		);
		assert_eq!(r.header("apns-push-type"), Some("alert"));
		assert_eq!(r.header("apns-priority"), Some("10"));
		assert_eq!(r.header("apns-topic"), Some("com.example.app"));
		assert_eq!(r.header("apns-expiration"), Some("4600"));
		assert_eq!(r.header("apns-collapse-id"), Some("order-42"));
		assert_eq!(r.header("authorization"), Some("bearer TOKEN"));
		let body: Value = serde_json::from_slice(&r.body).unwrap();
		assert_eq!(
			body,
			json!({"aps": {"alert": {"title": "Order shipped", "body": "Arrives Tuesday"},
			"sound": "default", "badge": 2, "thread-id": "orders"}, "order": 42})
		);
	}

	#[test]
	fn a_background_push_is_priority_5_and_content_available() {
		let n = note(json!({"background": true, "data": {"sync": "inbox"}}));
		let r = request(
			&n,
			&Envelope::default(),
			TOKEN,
			Environment::Sandbox,
			"com.example.app",
			"T",
			0,
		)
		.unwrap();
		assert!(r.url.starts_with("https://api.sandbox.push.apple.com/"));
		assert_eq!(r.header("apns-push-type"), Some("background"));
		assert_eq!(r.header("apns-priority"), Some("5"));
		assert_eq!(r.header("apns-expiration"), None);
		let body: Value = serde_json::from_slice(&r.body).unwrap();
		assert_eq!(
			body,
			json!({"aps": {"content-available": 1}, "sync": "inbox"})
		);
	}

	#[test]
	fn overrides_reach_aps_and_ttl_zero_means_now_or_never() {
		let n =
			note(json!({"title": "t", "apns": {"aps": {"interruption-level": "time-sensitive"}}}));
		let r = request(
			&n,
			&Envelope {
				ttl: Some(0),
				..Default::default()
			},
			TOKEN,
			Environment::Production,
			"a.b",
			"T",
			99,
		)
		.unwrap();
		assert_eq!(r.header("apns-expiration"), Some("0"));
		let body: Value = serde_json::from_slice(&r.body).unwrap();
		assert_eq!(body["aps"]["interruption-level"], "time-sensitive");
		assert_eq!(body["aps"]["alert"]["title"], "t");
	}

	#[test]
	fn too_big_and_bad_topic_are_refused() {
		let n = note(json!({"title": "t", "body": "x".repeat(5000)}));
		let error = request(
			&n,
			&Envelope::default(),
			TOKEN,
			Environment::Production,
			"a.b",
			"T",
			0,
		)
		.unwrap_err();
		assert!(error.0.contains("4096"), "{error}");
		let n = note(json!({"title": "t"}));
		assert!(
			request(
				&n,
				&Envelope::default(),
				TOKEN,
				Environment::Production,
				"a/b",
				"T",
				0
			)
			.is_err()
		);
	}

	#[test]
	fn device_tokens() {
		assert_eq!(check_device_token(&TOKEN.to_uppercase()).unwrap(), TOKEN);
		assert!(check_device_token("abc").is_err());
		assert!(check_device_token(&"z".repeat(64)).is_err());
		assert!(check_device_token(&format!("{TOKEN}a")).is_err());
	}

	#[test]
	fn apple_ids_and_the_provider_token() {
		let (_, der) = crate::keys::EsKey::generate().unwrap();
		use base64::Engine;
		let p8 = crate::keys::test_pem(&base64::engine::general_purpose::STANDARD.encode(der));
		assert!(
			Credentials::new(&p8, "abc", "TEAM123456")
				.unwrap_err()
				.0
				.contains("key ID")
		);
		let credentials = Credentials::new(&p8, "ABC123DEFG", "TEAM123456").unwrap();
		let token = credentials.provider_token(1_700_000_000).unwrap();
		let parts: Vec<&str> = token.split('.').collect();
		let header: Value =
			serde_json::from_slice(&crate::b64url_decode(parts[0]).unwrap()).unwrap();
		let claims: Value =
			serde_json::from_slice(&crate::b64url_decode(parts[1]).unwrap()).unwrap();
		assert_eq!(header, json!({"alg": "ES256", "kid": "ABC123DEFG"}));
		assert_eq!(claims, json!({"iss": "TEAM123456", "iat": 1_700_000_000}));
	}

	#[test]
	fn a_410_carries_apples_timestamp() {
		assert_eq!(
			classify(
				410,
				None,
				None,
				br#"{"reason":"Unregistered","timestamp":1700000000123}"#
			),
			Outcome::Unregistered {
				reason: "APNs: Unregistered".into(),
				since_ms: Some(1_700_000_000_123)
			}
		);
	}

	#[test]
	fn what_apple_says() {
		assert_eq!(
			classify(200, Some("abc-1"), None, b""),
			Outcome::Accepted {
				provider_id: Some("abc-1".into())
			}
		);
		assert!(matches!(
			classify(
				410,
				None,
				None,
				br#"{"reason":"Unregistered","timestamp":1}"#
			),
			Outcome::Unregistered { .. }
		));
		assert!(matches!(
			classify(400, None, None, br#"{"reason":"BadDeviceToken"}"#),
			Outcome::Unregistered { .. }
		));
		assert!(matches!(
			classify(403, None, None, br#"{"reason":"InvalidProviderToken"}"#),
			Outcome::Credentials { .. }
		));
		assert_eq!(
			classify(403, None, None, br#"{"reason":"ExpiredProviderToken"}"#),
			Outcome::Failed {
				reason: "APNs: ExpiredProviderToken".into(),
				retry_after: Some(0)
			}
		);
		assert_eq!(
			classify(429, None, Some("30"), br#"{"reason":"TooManyRequests"}"#),
			Outcome::Failed {
				reason: "APNs: TooManyRequests".into(),
				retry_after: Some(30)
			}
		);
		assert!(matches!(
			classify(503, None, None, b"not json"),
			Outcome::Failed {
				retry_after: Some(5),
				..
			}
		));
		assert_eq!(
			classify(400, None, None, br#"{"reason":"DeviceTokenNotForTopic"}"#),
			Outcome::Failed {
				reason: "APNs: DeviceTokenNotForTopic".into(),
				retry_after: None
			}
		);
	}
}
