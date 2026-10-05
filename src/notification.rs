//! One notification, as a customer writes it, for every transport.
//!
//! `push.messages.notification` holds this shape. It is validated ONCE, before a message is
//! queued, against the strictest rule any transport has (FCM's reserved data keys, APNs' `aps`),
//! so a message that is accepted can be delivered everywhere its targets are, and a refusal comes
//! back to the sender as a sentence rather than as a failed delivery an hour later.

use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct NotificationError(pub String);

fn error(message: impl Into<String>) -> NotificationError {
	NotificationError(message.into())
}

/// What the customer writes. Unknown fields are refused rather than ignored: a typo (`tittle`)
/// otherwise becomes a notification with no title and no clue why.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notification {
	pub title: Option<String>,
	pub body: Option<String>,
	/// Delivered to the app alongside the notification. Values that are not strings are sent as
	/// their JSON text, since FCM carries strings only.
	#[serde(default)]
	pub data: Map<String, Value>,
	pub badge: Option<u32>,
	pub sound: Option<String>,
	/// Groups notifications on the device (APNs `thread-id`, Android `tag`, Web `tag`).
	pub thread: Option<String>,
	/// An image URL, shown where the platform supports one.
	pub image: Option<String>,
	/// Where a click on a web notification goes.
	pub url: Option<String>,
	/// A silent push: nothing is shown, the app is woken to handle `data`.
	#[serde(default)]
	pub background: bool,
	/// Per-transport fields merged over what this server builds, for anything this shape does not
	/// name (`{"aps": {"interruption-level": "time-sensitive"}}`). The escape hatch, not the API.
	#[serde(default)]
	pub apns: Map<String, Value>,
	#[serde(default)]
	pub fcm: Map<String, Value>,
	#[serde(default)]
	pub web: Map<String, Value>,
}

/// How a message travels, from `push.messages`' own columns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Envelope {
	/// Seconds a provider may hold the message for an offline device. `None` is each provider's
	/// default; `Some(0)` is "now or never".
	pub ttl: Option<u32>,
	pub priority: Priority,
	/// A newer message with the same key replaces an undelivered older one.
	pub collapse_key: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Priority {
	#[default]
	High,
	Normal,
}

impl Priority {
	pub fn parse(text: &str) -> Result<Self, NotificationError> {
		match text {
			"high" => Ok(Self::High),
			"normal" => Ok(Self::Normal),
			other => Err(error(format!(
				"priority is \"high\" or \"normal\", not \"{other}\"."
			))),
		}
	}
}

/// The data key every delivery carries its id under, so the app can report it received or opened
/// Reserved, like the providers' own.
pub const DELIVERY_KEY: &str = "snout_push_delivery";

/// FCM refuses these data keys, and `snout_push*` is ours; refusing them for every transport
/// keeps one message portable.
fn reserved_data_key(key: &str) -> bool {
	matches!(key, "from" | "notification" | "message_type" | "aps")
		|| key.starts_with("google.")
		|| key.starts_with("gcm.")
		|| key.starts_with("snout_push")
}

/// APNs caps a collapse id at 64 bytes.
const MAX_COLLAPSE_KEY: usize = 64;

impl Notification {
	pub fn from_json(value: &Value) -> Result<Self, NotificationError> {
		serde_json::from_value(value.clone())
			.map_err(|e| error(format!("The notification is not valid: {e}.")))
	}

	/// The rules every transport can keep. Size is checked per transport, once built.
	pub fn validate(&self, envelope: &Envelope) -> Result<(), NotificationError> {
		let has_text = self.title.as_deref().is_some_and(|t| !t.is_empty())
			|| self.body.as_deref().is_some_and(|b| !b.is_empty());
		if self.background && has_text {
			return Err(error(
				"A background notification is silent: it takes data, not a title or body.",
			));
		}
		if !self.background && !has_text {
			return Err(error(
				"A notification needs a title or a body (or \"background\": true for a silent one).",
			));
		}
		if self.background && self.data.is_empty() {
			return Err(error(
				"A background notification with no data has nothing for the app to do.",
			));
		}
		if let Some(key) = self.data.keys().find(|k| reserved_data_key(k)) {
			return Err(error(format!(
				"\"{key}\" is reserved by the push services and cannot be a data key."
			)));
		}
		if let Some(key) = &envelope.collapse_key
			&& (key.is_empty() || key.len() > MAX_COLLAPSE_KEY)
		{
			return Err(error(format!(
				"collapse_key is 1 to {MAX_COLLAPSE_KEY} bytes."
			)));
		}
		for (name, value) in [("image", &self.image), ("url", &self.url)] {
			let Some(value) = value else { continue };
			// A click target may be a path in the web app itself ("/inbox"), never "//host".
			if name == "url" && value.starts_with('/') && !value.starts_with("//") {
				continue;
			}
			let parsed =
				url::Url::parse(value).map_err(|_| error(format!("{name} is not a URL.")))?;
			if parsed.scheme() != "https" {
				return Err(error(format!("{name} must be an https URL.")));
			}
		}
		Ok(())
	}

	/// `data` with every value as a string, which is what FCM carries.
	pub fn string_data(&self) -> Map<String, Value> {
		self.data
			.iter()
			.map(|(k, v)| {
				let text = match v {
					Value::String(s) => s.clone(),
					other => other.to_string(),
				};
				(k.clone(), Value::String(text))
			})
			.collect()
	}
}

/// Merges `overlay` into `base`, objects recursively, anything else replaced.
pub fn merge(base: &mut Map<String, Value>, overlay: &Map<String, Value>) {
	for (key, value) in overlay {
		match (base.get_mut(key), value) {
			(Some(Value::Object(inner)), Value::Object(over)) => merge(inner, over),
			_ => {
				base.insert(key.clone(), value.clone());
			}
		}
	}
}

/// A request for a provider, built without any I/O so every transport is testable offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
	pub url: String,
	pub headers: Vec<(String, String)>,
	pub body: Vec<u8>,
}

impl Request {
	pub fn header(&self, name: &str) -> Option<&str> {
		self.headers
			.iter()
			.find(|(n, _)| n.eq_ignore_ascii_case(name))
			.map(|(_, v)| v.as_str())
	}
}

/// What a provider's answer means for the device and the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
	/// The provider took it. Not "delivered": that is only ever the app's report.
	Accepted { provider_id: Option<String> },
	/// The token or subscription is dead; the device is disabled with this reason. `since_ms` is
	/// when the provider says it stopped being valid (APNs' `timestamp`): a device that registered
	/// AGAIN after that moment is alive, so the caller disables it only if its `last_seen_at` is
	/// older (Apple's own guidance).
	Unregistered {
		reason: String,
		since_ms: Option<u64>,
	},
	/// This message failed. `retry_after` is `Some` when trying again could succeed.
	Failed {
		reason: String,
		retry_after: Option<u64>,
	},
	/// Never sent: this message cannot go to this device as it stands (too large once built for
	/// this transport, a silent push to a browser, a URL the rules refuse). Retrying cannot help.
	Refused { reason: String },
	/// The project's credentials were refused: every message on this transport will fail until the
	/// customer fixes them, so the sender stops using them and says so, rather than burning the queue.
	Credentials { reason: String },
}

/// Seconds from a `Retry-After` header (the delta form; a date is treated as "soon").
pub fn retry_after(value: Option<&str>, default: u64) -> u64 {
	value.and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	fn n(value: Value) -> Result<Notification, NotificationError> {
		Notification::from_json(&value)
	}

	#[test]
	fn a_typo_is_refused_not_ignored() {
		let error = n(json!({"tittle": "hi"})).unwrap_err();
		assert!(error.0.contains("tittle"), "{error}");
	}

	#[test]
	fn visible_needs_text_and_silent_needs_data() {
		let e = Envelope::default();
		assert!(n(json!({"title": "hi"})).unwrap().validate(&e).is_ok());
		assert!(n(json!({"body": "hi"})).unwrap().validate(&e).is_ok());
		assert!(
			n(json!({}))
				.unwrap()
				.validate(&e)
				.unwrap_err()
				.0
				.contains("title or a body")
		);
		assert!(
			n(json!({"background": true, "data": {"sync": 1}}))
				.unwrap()
				.validate(&e)
				.is_ok()
		);
		assert!(
			n(json!({"background": true}))
				.unwrap()
				.validate(&e)
				.unwrap_err()
				.0
				.contains("no data")
		);
		assert!(
			n(json!({"background": true, "title": "x", "data": {"a": 1}}))
				.unwrap()
				.validate(&e)
				.is_err()
		);
	}

	#[test]
	fn reserved_keys_are_refused_for_every_transport() {
		let e = Envelope::default();
		for key in [
			"from",
			"notification",
			"message_type",
			"aps",
			"google.c.a",
			"gcm.n.e",
			"snout_push_delivery",
		] {
			let error = n(json!({"title": "t", "data": {key: "x"}}))
				.unwrap()
				.validate(&e)
				.unwrap_err();
			assert!(error.0.contains(key), "{error}");
		}
	}

	#[test]
	fn collapse_key_and_urls() {
		let long = Envelope {
			collapse_key: Some("x".repeat(65)),
			..Default::default()
		};
		assert!(n(json!({"title": "t"})).unwrap().validate(&long).is_err());
		let e = Envelope::default();
		assert!(
			n(json!({"title": "t", "image": "http://x.example/a.png"}))
				.unwrap()
				.validate(&e)
				.is_err()
		);
		assert!(
			n(json!({"title": "t", "url": "/inbox"}))
				.unwrap()
				.validate(&e)
				.is_ok()
		);
		assert!(
			n(json!({"title": "t", "url": "//evil.example/x"}))
				.unwrap()
				.validate(&e)
				.is_err()
		);
		assert!(
			n(json!({"title": "t", "url": "javascript:alert(1)"}))
				.unwrap()
				.validate(&e)
				.is_err()
		);
		assert!(
			n(json!({"title": "t", "url": "https://app.example/inbox"}))
				.unwrap()
				.validate(&e)
				.is_ok()
		);
	}

	#[test]
	fn data_becomes_strings() {
		let note = n(json!({"title": "t", "data": {"id": 42, "s": "x", "o": {"a": [1]}}})).unwrap();
		assert_eq!(
			Value::Object(note.string_data()),
			json!({"id": "42", "s": "x", "o": "{\"a\":[1]}"})
		);
	}

	#[test]
	fn merge_is_deep_for_objects_only() {
		let mut base = json!({"aps": {"alert": {"title": "a"}, "badge": 1}, "k": [1]})
			.as_object()
			.unwrap()
			.clone();
		let over = json!({"aps": {"badge": 2, "interruption-level": "time-sensitive"}, "k": [2]});
		merge(&mut base, over.as_object().unwrap());
		assert_eq!(
			Value::Object(base),
			json!({"aps": {"alert": {"title": "a"}, "badge": 2, "interruption-level": "time-sensitive"}, "k": [2]})
		);
	}
}
