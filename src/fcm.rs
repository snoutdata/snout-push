//! FCM: how an Android app with Google Play services receives a push, and how an iOS or web app
//! built on the Firebase SDKs does (Google relays those to APNs or the browser itself).
//!
//! HTTP v1 only (the legacy API was shut down in 2024): one request per message, authorised by an
//! OAuth2 access token this server mints from the customer's service account, an RS256 assertion
//! exchanged at Google's token endpoint and good for an hour.
//!
//! The service-account JSON names its own `token_uri`. It is IGNORED: the assertion goes to
//! Google's endpoint and nowhere else, since honouring the field would let an uploaded file choose
//! where this server sends a signed request.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::keys::RsKey;
use crate::notification::{
	Envelope, Notification, NotificationError, Outcome, Priority, Request, merge, retry_after,
};

pub const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
pub const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Google's cap on an access token, and so on the assertion's lifetime.
pub const TOKEN_LIFETIME_SECS: u64 = 3600;
/// FCM's cap on a message's notification and data together.
pub const MAX_PAYLOAD: usize = 4096;

fn error(message: impl Into<String>) -> NotificationError {
	NotificationError(message.into())
}

#[derive(Deserialize)]
struct ServiceAccountJson {
	#[serde(rename = "type")]
	kind: String,
	project_id: String,
	private_key_id: Option<String>,
	private_key: String,
	client_email: String,
}

/// A project's Firebase service account. The private key is held in memory only.
#[derive(Debug)]
pub struct Credentials {
	pub project_id: String,
	pub client_email: String,
	key_id: Option<String>,
	key: RsKey,
}

impl Credentials {
	/// From the JSON file Firebase's console downloads (Project settings → Service accounts).
	pub fn from_json(text: &str) -> Result<Self, NotificationError> {
		let file: ServiceAccountJson = serde_json::from_str(text).map_err(|_| {
			error("This is not a Firebase service-account file: download it from Project settings, Service accounts, \"Generate new private key\".")
		})?;
		if file.kind != "service_account" {
			return Err(error(format!(
				"The file is a \"{}\" credential; FCM needs a \"service_account\" one.",
				file.kind
			)));
		}
		let project_ok = (4..=30).contains(&file.project_id.len())
			&& file
				.project_id
				.bytes()
				.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
		if !project_ok {
			return Err(error("The file's project_id is not a Firebase project ID."));
		}
		if !file.client_email.contains('@') {
			return Err(error("The file's client_email is not a service account."));
		}
		Ok(Self {
			key: RsKey::from_pem(&file.private_key).map_err(|e| error(e.0))?,
			project_id: file.project_id,
			client_email: file.client_email,
			key_id: file.private_key_id,
		})
	}

	/// The signed assertion for Google's token endpoint.
	pub fn assertion(&self, now: u64) -> Result<String, NotificationError> {
		let mut header = json!({"alg": "RS256", "typ": "JWT"});
		if let Some(kid) = &self.key_id {
			header["kid"] = json!(kid);
		}
		self.key
			.jwt(
				&header,
				&json!({"iss": self.client_email, "scope": SCOPE, "aud": TOKEN_URI, "iat": now, "exp": now + TOKEN_LIFETIME_SECS}),
			)
			.map_err(|e| error(e.0))
	}

	/// The request that exchanges the assertion for an access token.
	pub fn token_request(&self, now: u64) -> Result<Request, NotificationError> {
		// A JWT is base64url and dots, so it needs no form-encoding.
		let body = format!(
			"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
			self.assertion(now)?
		);
		Ok(Request {
			url: TOKEN_URI.to_string(),
			headers: vec![(
				"content-type".into(),
				"application/x-www-form-urlencoded".into(),
			)],
			body: body.into_bytes(),
		})
	}
}

/// Google's answer to the token request: the token and its lifetime in seconds.
pub fn parse_token_response(status: u16, body: &[u8]) -> Result<(String, u64), Outcome> {
	let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
	if status == 200
		&& let Some(token) = value.get("access_token").and_then(Value::as_str)
	{
		let expires_in = value
			.get("expires_in")
			.and_then(Value::as_u64)
			.unwrap_or(TOKEN_LIFETIME_SECS);
		return Ok((token.to_string(), expires_in));
	}
	let said = value
		.get("error_description")
		.or_else(|| value.get("error"))
		.and_then(Value::as_str)
		.map_or_else(|| format!("HTTP {status}"), str::to_string);
	if status >= 500 {
		Err(Outcome::Failed {
			reason: format!("Google's token endpoint: {said}"),
			retry_after: Some(5),
		})
	} else {
		// A revoked key, a deleted service account, a clock far off: the customer's to fix.
		Err(Outcome::Credentials {
			reason: format!("Google refused the service account: {said}"),
		})
	}
}

/// An FCM registration token: opaque, but printable and bounded.
pub fn check_device_token(text: &str) -> Result<String, NotificationError> {
	let text = text.trim();
	let ok = (32..=4096).contains(&text.len())
		&& text
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'));
	if ok {
		Ok(text.to_string())
	} else {
		Err(error("That is not an FCM registration token."))
	}
}

/// The `message` object FCM reads.
pub fn message(
	notification: &Notification,
	envelope: &Envelope,
	device_token: &str,
) -> Map<String, Value> {
	let mut message = Map::new();
	message.insert("token".into(), json!(device_token));

	if !notification.background {
		let mut shown = Map::new();
		if let Some(title) = &notification.title {
			shown.insert("title".into(), json!(title));
		}
		if let Some(body) = &notification.body {
			shown.insert("body".into(), json!(body));
		}
		if let Some(image) = &notification.image {
			shown.insert("image".into(), json!(image));
		}
		message.insert("notification".into(), Value::Object(shown));
	}
	let data = notification.string_data();
	if !data.is_empty() {
		message.insert("data".into(), Value::Object(data));
	}

	let mut android = Map::new();
	android.insert(
		"priority".into(),
		json!(if envelope.priority == Priority::High {
			"HIGH"
		} else {
			"NORMAL"
		}),
	);
	if let Some(ttl) = envelope.ttl {
		android.insert("ttl".into(), json!(format!("{ttl}s")));
	}
	if let Some(key) = &envelope.collapse_key {
		android.insert("collapse_key".into(), json!(key));
	}
	let mut android_shown = Map::new();
	if let Some(sound) = &notification.sound {
		android_shown.insert("sound".into(), json!(sound));
	}
	if let Some(thread) = &notification.thread {
		android_shown.insert("tag".into(), json!(thread));
	}
	if let Some(badge) = notification.badge {
		android_shown.insert("notification_count".into(), json!(badge));
	}
	if !notification.background && !android_shown.is_empty() {
		android.insert("notification".into(), Value::Object(android_shown));
	}
	message.insert("android".into(), Value::Object(android));

	// An iOS app on the Firebase SDK registers an FCM token; Google hands the message to APNs,
	// which needs the same aps fields a direct APNs send gets.
	let mut aps = Map::new();
	if notification.background {
		aps.insert("content-available".into(), json!(1));
	}
	if let Some(badge) = notification.badge {
		aps.insert("badge".into(), json!(badge));
	}
	if let Some(sound) = &notification.sound {
		aps.insert("sound".into(), json!(sound));
	}
	if let Some(thread) = &notification.thread {
		aps.insert("thread-id".into(), json!(thread));
	}
	if notification.image.is_some() {
		aps.insert("mutable-content".into(), json!(1));
	}
	let mut apns_headers = Map::new();
	if notification.background {
		apns_headers.insert("apns-push-type".into(), json!("background"));
		apns_headers.insert("apns-priority".into(), json!("5"));
	}
	if let Some(key) = &envelope.collapse_key {
		apns_headers.insert("apns-collapse-id".into(), json!(key));
	}
	if !aps.is_empty() || !apns_headers.is_empty() {
		let mut apns = Map::new();
		if !apns_headers.is_empty() {
			apns.insert("headers".into(), Value::Object(apns_headers));
		}
		apns.insert("payload".into(), json!({"aps": aps}));
		message.insert("apns".into(), Value::Object(apns));
	}

	merge(&mut message, &notification.fcm);
	message
}

/// The request for one device.
pub fn request(
	notification: &Notification,
	envelope: &Envelope,
	device_token: &str,
	project_id: &str,
	access_token: &str,
) -> Result<Request, NotificationError> {
	let message = message(notification, envelope, device_token);
	let carried = json!({"notification": message.get("notification"), "data": message.get("data")})
		.to_string();
	if carried.len() > MAX_PAYLOAD {
		return Err(error(format!(
			"The notification is {} bytes for FCM, which carries at most {MAX_PAYLOAD}.",
			carried.len()
		)));
	}
	Ok(Request {
		url: format!("https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"),
		headers: vec![
			("authorization".into(), format!("Bearer {access_token}")),
			("content-type".into(), "application/json".into()),
		],
		body: json!({"message": message}).to_string().into_bytes(),
	})
}

/// FCM's answer: `errorCode` from the error's details when there is one, else the HTTP status.
pub fn classify(status: u16, retry_after_header: Option<&str>, body: &[u8]) -> Outcome {
	let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
	if status == 200 {
		return Outcome::Accepted {
			provider_id: value
				.get("name")
				.and_then(Value::as_str)
				.map(str::to_string),
		};
	}
	let error = &value["error"];
	let code = error["details"]
		.as_array()
		.and_then(|details| {
			details
				.iter()
				.find_map(|d| d.get("errorCode").and_then(Value::as_str))
		})
		.or_else(|| error["status"].as_str())
		.unwrap_or("");
	let message = error["message"].as_str().unwrap_or("");
	let said = if message.is_empty() {
		format!(
			"FCM: {} (HTTP {status})",
			if code.is_empty() { "error" } else { code }
		)
	} else {
		format!("FCM: {code}: {message}")
	};
	match code {
		"UNREGISTERED" | "SENDER_ID_MISMATCH" => Outcome::Unregistered {
			reason: said,
			since_ms: None,
		},
		"INVALID_ARGUMENT" if message.contains("registration token") => Outcome::Unregistered {
			reason: said,
			since_ms: None,
		},
		"THIRD_PARTY_AUTH_ERROR" | "PERMISSION_DENIED" => Outcome::Credentials { reason: said },
		"UNAUTHENTICATED" => Outcome::Failed {
			reason: said,
			retry_after: Some(0),
		},
		"QUOTA_EXCEEDED" | "UNAVAILABLE" | "INTERNAL" => Outcome::Failed {
			reason: said,
			retry_after: Some(retry_after(retry_after_header, 10)),
		},
		_ if status == 401 => Outcome::Failed {
			reason: said,
			retry_after: Some(0),
		},
		_ if status == 429 || status >= 500 => Outcome::Failed {
			reason: said,
			retry_after: Some(retry_after(retry_after_header, 10)),
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

	fn note(value: Value) -> Notification {
		Notification::from_json(&value).unwrap()
	}

	const TOKEN: &str = "fGx0c1ZlQ0y:APA91bHq8zX_abcdefghijklmnopqrstuvwxyz0123456789";

	#[test]
	fn a_visible_message_for_android_and_for_ios_through_firebase() {
		let n = note(
			json!({"title": "Hi", "body": "There", "badge": 3, "sound": "default", "thread": "chat-9",
			"image": "https://cdn.example/a.png", "data": {"chat": 9}}),
		);
		let e = Envelope {
			ttl: Some(600),
			priority: Priority::Normal,
			collapse_key: Some("chat-9".into()),
		};
		let m = Value::Object(message(&n, &e, TOKEN));
		assert_eq!(m["token"], TOKEN);
		assert_eq!(
			m["notification"],
			json!({"title": "Hi", "body": "There", "image": "https://cdn.example/a.png"})
		);
		assert_eq!(m["data"], json!({"chat": "9"}));
		assert_eq!(
			m["android"],
			json!({"priority": "NORMAL", "ttl": "600s", "collapse_key": "chat-9",
			"notification": {"sound": "default", "tag": "chat-9", "notification_count": 3}})
		);
		assert_eq!(
			m["apns"],
			json!({"headers": {"apns-collapse-id": "chat-9"},
			"payload": {"aps": {"badge": 3, "sound": "default", "thread-id": "chat-9", "mutable-content": 1}}})
		);
	}

	#[test]
	fn a_background_message_is_data_only() {
		let n = note(json!({"background": true, "data": {"sync": "inbox"}}));
		let m = Value::Object(message(&n, &Envelope::default(), TOKEN));
		assert!(m.get("notification").is_none());
		assert_eq!(m["data"], json!({"sync": "inbox"}));
		assert_eq!(m["android"], json!({"priority": "HIGH"}));
		assert_eq!(
			m["apns"],
			json!({"headers": {"apns-push-type": "background", "apns-priority": "5"},
			"payload": {"aps": {"content-available": 1}}})
		);
	}

	#[test]
	fn the_request_and_the_size_cap() {
		let r = request(
			&note(json!({"title": "t", "fcm": {"android": {"direct_boot_ok": true}}})),
			&Envelope::default(),
			TOKEN,
			"my-app-1234",
			"ya29.x",
		)
		.unwrap();
		assert_eq!(
			r.url,
			"https://fcm.googleapis.com/v1/projects/my-app-1234/messages:send"
		);
		assert_eq!(r.header("authorization"), Some("Bearer ya29.x"));
		let body: Value = serde_json::from_slice(&r.body).unwrap();
		assert_eq!(body["message"]["android"]["direct_boot_ok"], true);
		let big = note(json!({"title": "t", "data": {"blob": "x".repeat(4100)}}));
		assert!(
			request(&big, &Envelope::default(), TOKEN, "my-app-1234", "t")
				.unwrap_err()
				.0
				.contains("4096")
		);
	}

	#[test]
	fn what_google_says() {
		assert_eq!(
			classify(200, None, br#"{"name":"projects/p/messages/0:1"}"#),
			Outcome::Accepted {
				provider_id: Some("projects/p/messages/0:1".into())
			}
		);
		let unregistered = br#"{"error":{"code":404,"message":"Requested entity was not found.","status":"NOT_FOUND",
			"details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#;
		assert!(matches!(
			classify(404, None, unregistered),
			Outcome::Unregistered { .. }
		));
		let bad_token = br#"{"error":{"code":400,"message":"The registration token is not a valid FCM registration token","status":"INVALID_ARGUMENT",
			"details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"INVALID_ARGUMENT"}]}}"#;
		assert!(matches!(
			classify(400, None, bad_token),
			Outcome::Unregistered { .. }
		));
		let bad_payload = br#"{"error":{"code":400,"message":"Invalid value at 'message.data'","status":"INVALID_ARGUMENT"}}"#;
		assert!(matches!(
			classify(400, None, bad_payload),
			Outcome::Failed {
				retry_after: None,
				..
			}
		));
		let quota = br#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"errorCode":"QUOTA_EXCEEDED"}]}}"#;
		assert!(matches!(
			classify(429, Some("60"), quota),
			Outcome::Failed {
				retry_after: Some(60),
				..
			}
		));
		let apns_missing = br#"{"error":{"code":401,"status":"UNAUTHENTICATED","details":[{"errorCode":"THIRD_PARTY_AUTH_ERROR"}]}}"#;
		assert!(matches!(
			classify(401, None, apns_missing),
			Outcome::Credentials { .. }
		));
		assert!(matches!(
			classify(503, None, b""),
			Outcome::Failed {
				retry_after: Some(10),
				..
			}
		));
	}

	#[test]
	fn the_token_response() {
		assert_eq!(
			parse_token_response(
				200,
				br#"{"access_token":"ya29.a","expires_in":3599,"token_type":"Bearer"}"#
			),
			Ok(("ya29.a".into(), 3599))
		);
		assert!(
			matches!(parse_token_response(400, br#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#),
			Err(Outcome::Credentials { reason }) if reason.contains("Invalid JWT Signature"))
		);
		assert!(matches!(
			parse_token_response(502, b""),
			Err(Outcome::Failed { .. })
		));
	}

	#[test]
	fn a_service_account_file_is_checked() {
		assert!(
			Credentials::from_json("{}")
				.unwrap_err()
				.0
				.contains("service-account")
		);
		let wrong_kind = json!({"type": "authorized_user", "project_id": "abcd", "private_key": "x", "client_email": "a@b"});
		assert!(
			Credentials::from_json(&wrong_kind.to_string())
				.unwrap_err()
				.0
				.contains("authorized_user")
		);
		let bad_key = json!({"type": "service_account", "project_id": "my-app-1234", "private_key": crate::keys::test_pem("AAAA"),
			"client_email": "push@my-app-1234.iam.gserviceaccount.com", "token_uri": "https://attacker.example/token"});
		assert!(
			Credentials::from_json(&bad_key.to_string())
				.unwrap_err()
				.0
				.contains("RSA")
		);
	}

	/// A real RSA key, made for the test by openssl (the stack's container has it) rather than
	/// committed: no key of any kind lives in the tree (X13). Skips where there is no openssl.
	#[test]
	fn the_assertion_is_rs256_signed_for_google_whatever_the_file_says() {
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
		let pem = String::from_utf8(out.stdout).unwrap();
		let file = json!({"type": "service_account", "project_id": "my-app-1234", "private_key_id": "kid-1",
			"private_key": pem, "client_email": "push@my-app-1234.iam.gserviceaccount.com",
			"token_uri": "https://attacker.example/token"});
		let credentials = Credentials::from_json(&file.to_string()).unwrap();
		let request = credentials.token_request(1_700_000_000).unwrap();
		assert_eq!(request.url, TOKEN_URI, "the file's token_uri is never used");
		let body = String::from_utf8(request.body).unwrap();
		let assertion = body.split("assertion=").nth(1).unwrap();
		let parts: Vec<&str> = assertion.split('.').collect();
		let header: Value =
			serde_json::from_slice(&crate::b64url_decode(parts[0]).unwrap()).unwrap();
		let claims: Value =
			serde_json::from_slice(&crate::b64url_decode(parts[1]).unwrap()).unwrap();
		assert_eq!(
			header,
			json!({"alg": "RS256", "typ": "JWT", "kid": "kid-1"})
		);
		assert_eq!(
			claims,
			json!({"iss": "push@my-app-1234.iam.gserviceaccount.com", "scope": SCOPE,
			"aud": TOKEN_URI, "iat": 1_700_000_000, "exp": 1_700_003_600})
		);
		assert_eq!(
			crate::b64url_decode(parts[2]).unwrap().len(),
			256,
			"a 2048-bit signature"
		);
	}

	#[test]
	fn device_tokens() {
		assert!(check_device_token(TOKEN).is_ok());
		assert!(check_device_token("short").is_err());
		assert!(check_device_token(&format!("{TOKEN} x")).is_err());
	}
}
