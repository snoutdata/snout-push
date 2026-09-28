//! snout-push: push notifications over APNs, FCM and Web Push, from one API and from SQL.
//!
//! Replaces: nothing. It is a new product: one API over the three transports, with the data kept
//! in the project's own database.
//!
//! One process per host serves every project that switched push on. The device registry, the
//! queue and the delivery log are tables in the project's own database (`push.*`), so the
//! project's row-level security decides who may notify whom, once, when a message is inserted;
//! this server only expands and delivers what was already allowed.

pub mod api;
pub mod apns;
pub mod config;
pub mod drain;
pub mod fcm;
pub mod jwt;
pub mod keys;
pub mod migrations;
pub mod net;
pub mod notification;
pub mod project;
pub mod providers;
pub mod webpush;

#[cfg(test)]
mod testing;

/// Entry points for the fuzz targets (`packages/stack/fuzz`): each parser of untrusted input,
/// called the way a request or a provider's answer reaches it. Not an API; nothing here is stable.
#[doc(hidden)]
pub mod fuzz {
	use crate::migrations::Roles;
	use crate::notification::{Envelope, Notification};

	/// What an app or a server sends: a notification (as JSON), tokens, subscriptions, a host.
	pub fn request(input: &str) {
		if let Ok(value) = serde_json::from_str::<serde_json::Value>(input)
			&& let Ok(notification) = Notification::from_json(&value)
		{
			let envelope = Envelope::default();
			if notification.validate(&envelope).is_ok() {
				let _ = crate::apns::payload(&notification);
				let _ = crate::fcm::message(&notification, &envelope, "t");
				let _ = crate::webpush::payload(&notification);
			}
		}
		let _ = crate::apns::check_device_token(input);
		let _ = crate::apns::check_topic(input);
		let _ = crate::fcm::check_device_token(input);
		let _ = crate::webpush::check_endpoint(input);
		// At a character boundary: splitting a two-byte character was the harness's own first crash.
		let middle = input
			.char_indices()
			.nth(input.chars().count() / 2)
			.map_or(input.len(), |(i, _)| i);
		let (a, b) = input.split_at(middle);
		let _ = crate::webpush::Subscription::parse(input, a, b);
		let _ = crate::fcm::Credentials::from_json(input);
		let _ = crate::keys::pem_to_der(input);
		let _ = crate::b64url_decode(input);
	}

	/// A bearer token, against a secret.
	pub fn token(input: &str) {
		let _ = crate::jwt::verify(
			input,
			"a-project-secret-of-at-least-32-chars",
			&Roles::default(),
			0,
		);
	}

	/// What a provider sends back, as each classifier reads it.
	pub fn provider_response(input: &[u8]) {
		let status = input.first().map_or(200, |b| 200 + u16::from(*b) * 2);
		let header = std::str::from_utf8(input).ok();
		let _ = crate::apns::classify(status, header, header, input);
		let _ = crate::fcm::classify(status, header, input);
		let _ = crate::fcm::parse_token_response(status, input);
		let _ = crate::webpush::classify(status, header, header, input);
	}
}

/// base64url without padding: what JWTs, Web Push keys and VAPID all use.
pub(crate) fn b64url(bytes: &[u8]) -> String {
	use base64::Engine;
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url, tolerating padding and the standard alphabet, since browsers and SDKs
/// hand keys over in both.
pub(crate) fn b64url_decode(text: &str) -> Option<Vec<u8>> {
	use base64::Engine;
	use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
	let trimmed = text.trim().trim_end_matches('=');
	URL_SAFE_NO_PAD
		.decode(trimmed)
		.or_else(|_| STANDARD_NO_PAD.decode(trimmed))
		.ok()
}
