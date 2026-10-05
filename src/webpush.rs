//! Web Push: what a browser's push service accepts, and nothing it does not.
//!
//!  - **RFC 8291**, message encryption (`aes128gcm`): the payload is sealed to the browser's own
//!    key, so the push service (Google's, Mozilla's, Apple's, Microsoft's) carries bytes it cannot
//!    read. One record, since every service caps a message at 4096 bytes.
//!  - **RFC 8292**, VAPID: each request carries a JWT signed with the PROJECT's key pair, whose
//!    public half the browser was given when it subscribed. No Google or Apple account is involved,
//!    which is why a web app on Snout Push needs no Firebase project.
//!  - **The endpoint allowlist**: a subscription's endpoint is a URL a browser
//!    hands us, so it is the one place a caller chooses where this server sends a request. The
//!    fleet's network cannot filter by host name, so this module does: https, the default port, and
//!    a host on the reviewed list, checked when a device registers AND again at send.

use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;

use crate::keys::EsKey;
use crate::notification::{Envelope, Notification, Outcome, Priority, Request, merge, retry_after};
use serde_json::{Map, Value};

/// The one record size this server writes (RFC 8188's `rs`), and every push service's cap on a
/// whole message.
pub const RECORD_SIZE: u32 = 4096;
/// The header: salt (16) + rs (4) + idlen (1) + the sender's public key (65).
const HEADER_LEN: usize = 16 + 4 + 1 + 65;
/// AES-GCM's tag.
const TAG_LEN: usize = 16;
/// The largest plaintext that fits one record: 4096 - 86 - 16 - 1 (the 0x02 delimiter).
pub const MAX_PLAINTEXT: usize = RECORD_SIZE as usize - HEADER_LEN - TAG_LEN - 1;

/// How long a VAPID token is good for. RFC 8292 caps it at 24 hours; half that leaves room for
/// a clock that is wrong in either direction.
pub const VAPID_LIFETIME_SECS: u64 = 12 * 60 * 60;

/// Push services a subscription may point at. Extended by a reviewed change to this list,
/// never by a setting: each entry is a host this server will send requests to on a stranger's say.
const EXACT_HOSTS: [&str; 2] = [
	// Chrome, Edge on Android, Opera, Samsung Internet.
	"fcm.googleapis.com",
	// Firefox.
	"updates.push.services.mozilla.com",
];
/// Edge on Windows (`wns2-<region>.notify.windows.com`), and Safari (macOS 13+, iOS/iPadOS 16.4+
/// web apps on the Home Screen), whose endpoints Apple documents as `*.push.apple.com`.
const SUFFIX_HOSTS: [&str; 2] = [".notify.windows.com", ".push.apple.com"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct WebPushError(pub String);

fn error(message: impl Into<String>) -> WebPushError {
	WebPushError(message.into())
}

/// A browser's subscription (`PushSubscription.toJSON()`): where to send, and the keys to seal to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
	pub endpoint: url::Url,
	/// The browser's P-256 public key, uncompressed (65 bytes).
	pub p256dh: Vec<u8>,
	/// The browser's authentication secret (16 bytes).
	pub auth: Vec<u8>,
}

impl Subscription {
	/// Checks a subscription as a browser hands it over, keys in base64url.
	pub fn parse(endpoint: &str, p256dh: &str, auth: &str) -> Result<Self, WebPushError> {
		let endpoint = check_endpoint(endpoint)?;
		let p256dh = crate::b64url_decode(p256dh)
			.filter(|k| k.len() == 65 && k[0] == 0x04)
			.ok_or_else(|| {
				error(
					"The subscription's p256dh key is not an uncompressed P-256 public key (65 bytes, base64url).",
				)
			})?;
		let auth = crate::b64url_decode(auth)
			.filter(|k| k.len() == 16)
			.ok_or_else(|| error("The subscription's auth secret is not 16 bytes of base64url."))?;
		Ok(Self {
			endpoint,
			p256dh,
			auth,
		})
	}
}

/// An endpoint this server will send to: https, the default port, no credentials in the URL, and a
/// host on the list. The sentence names the host, so a developer whose browser is not on the list
/// learns which one it was rather than that "the subscription is invalid".
pub fn check_endpoint(text: &str) -> Result<url::Url, WebPushError> {
	let url =
		url::Url::parse(text).map_err(|_| error("The subscription's endpoint is not a URL."))?;
	if url.scheme() != "https" {
		return Err(error("The subscription's endpoint must be https."));
	}
	if url.port().is_some() || !url.username().is_empty() || url.password().is_some() {
		return Err(error(
			"The subscription's endpoint may not carry a port or credentials.",
		));
	}
	let host = match url.host() {
		Some(url::Host::Domain(host)) => host.to_ascii_lowercase(),
		_ => {
			return Err(error(
				"The subscription's endpoint must name a push service by host name, not an address.",
			));
		}
	};
	let known = EXACT_HOSTS.contains(&host.as_str())
		|| SUFFIX_HOSTS
			.iter()
			.any(|suffix| host.ends_with(suffix) && host.len() > suffix.len());
	if !known {
		return Err(error(format!(
			"The subscription's endpoint is on {host}, which is not a push service Snout Push sends to. Supported: Chrome, Firefox, Safari and Edge."
		)));
	}
	Ok(url)
}

/// The origin a VAPID token's `aud` must be: scheme and host of the endpoint (RFC 8292 §2).
pub fn audience(endpoint: &url::Url) -> String {
	endpoint.origin().ascii_serialization()
}

/// The `Authorization` header value for one request: `vapid t=<jwt>, k=<public key>`.
/// `subject` is the contact RFC 8292 asks for, a `mailto:` or `https:` URL.
pub fn vapid_authorization(
	key: &EsKey,
	endpoint: &url::Url,
	subject: &str,
	now: u64,
) -> Result<String, WebPushError> {
	let token = key
		.jwt(
			&json!({"typ": "JWT", "alg": "ES256"}),
			&json!({"aud": audience(endpoint), "exp": now + VAPID_LIFETIME_SECS, "sub": subject}),
		)
		.map_err(|e| error(e.0))?;
	Ok(format!(
		"vapid t={token}, k={}",
		crate::b64url(key.public_key())
	))
}

/// Seals `plaintext` to a subscription: the request body, sent with `Content-Encoding: aes128gcm`.
pub fn encrypt(subscription: &Subscription, plaintext: &[u8]) -> Result<Vec<u8>, WebPushError> {
	if plaintext.len() > MAX_PLAINTEXT {
		return Err(error(format!(
			"The message is {} bytes once built; Web Push carries at most {MAX_PLAINTEXT}.",
			plaintext.len()
		)));
	}
	let rng = SystemRandom::new();
	let mut salt = [0u8; 16];
	rng.fill(&mut salt)
		.map_err(|_| error("Could not draw a salt."))?;
	let ephemeral = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
		.map_err(|_| error("Could not generate a key."))?;
	let as_public = ephemeral
		.compute_public_key()
		.map_err(|_| error("Could not generate a key."))?;
	let peer = UnparsedPublicKey::new(&ECDH_P256, &subscription.p256dh);
	let ecdh_secret = agree_ephemeral(ephemeral, &peer, |secret| secret.to_vec())
		.map_err(|_| error("The subscription's p256dh key is not a point on P-256."))?;
	seal(
		&ecdh_secret,
		&subscription.p256dh,
		as_public.as_ref(),
		&subscription.auth,
		&salt,
		plaintext,
	)
}

/// ring's HKDF wants the output length as a type.
struct Len(usize);

impl KeyType for Len {
	fn len(&self) -> usize {
		self.0
	}
}

fn expand(prk: &Prk, info: &[u8], len: usize) -> Result<Vec<u8>, WebPushError> {
	let mut out = vec![0; len];
	prk.expand(&[info], Len(len))
		.and_then(|okm| okm.fill(&mut out))
		.map_err(|_| error("Key derivation failed."))?;
	Ok(out)
}

/// RFC 8291 §3.3-3.4 and RFC 8188 from the shared secret on: everything but the ECDH, which is
/// what makes it deterministic and testable against the RFC's own intermediate values.
fn seal(
	ecdh_secret: &[u8],
	ua_public: &[u8],
	as_public: &[u8],
	auth_secret: &[u8],
	salt: &[u8; 16],
	plaintext: &[u8],
) -> Result<Vec<u8>, WebPushError> {
	// PRK_key = HMAC-SHA-256(auth_secret, ecdh_secret); IKM = HKDF-Expand(PRK_key, key_info, 32).
	let prk_key = Salt::new(HKDF_SHA256, auth_secret).extract(ecdh_secret);
	let mut key_info = b"WebPush: info\0".to_vec();
	key_info.extend_from_slice(ua_public);
	key_info.extend_from_slice(as_public);
	let ikm = expand(&prk_key, &key_info, 32)?;

	// PRK = HKDF-Extract(salt, IKM); then the content key and the nonce (RFC 8188 §2.2-2.3).
	let prk = Salt::new(HKDF_SHA256, salt).extract(&ikm);
	let cek = expand(&prk, b"Content-Encoding: aes128gcm\0", 16)?;
	let nonce = expand(&prk, b"Content-Encoding: nonce\0", 12)?;

	let key = LessSafeKey::new(
		UnboundKey::new(&AES_128_GCM, &cek).map_err(|_| error("Bad content key."))?,
	);
	let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|_| error("Bad nonce."))?;
	let mut record = Vec::with_capacity(plaintext.len() + 1 + TAG_LEN);
	record.extend_from_slice(plaintext);
	// The last (and only) record's padding delimiter.
	record.push(0x02);
	key.seal_in_place_append_tag(nonce, Aad::empty(), &mut record)
		.map_err(|_| error("Encryption failed."))?;

	let mut body = Vec::with_capacity(HEADER_LEN + record.len());
	body.extend_from_slice(salt);
	body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
	body.push(as_public.len() as u8);
	body.extend_from_slice(as_public);
	body.extend_from_slice(&record);
	Ok(body)
}

/// How long a push service holds a message for an offline browser when the sender says nothing:
/// RFC 8030 makes `TTL` mandatory, and four weeks is what the services cap it at anyway.
pub const DEFAULT_TTL: u32 = 28 * 24 * 60 * 60;

/// What the service worker receives, decrypted: the notification in the shape the client SDK's
/// service-worker helper shows (`self.registration.showNotification(title, options)`).
pub fn payload(notification: &Notification) -> Map<String, Value> {
	let mut out = Map::new();
	for (key, value) in [
		("title", notification.title.as_ref().map(|v| json!(v))),
		("body", notification.body.as_ref().map(|v| json!(v))),
		("badge", notification.badge.map(|v| json!(v))),
		("tag", notification.thread.as_ref().map(|v| json!(v))),
		("image", notification.image.as_ref().map(|v| json!(v))),
		("url", notification.url.as_ref().map(|v| json!(v))),
	] {
		if let Some(value) = value {
			out.insert(key.into(), value);
		}
	}
	if !notification.data.is_empty() {
		out.insert("data".into(), Value::Object(notification.data.clone()));
	}
	if notification.background {
		out.insert("background".into(), json!(true));
	}
	merge(&mut out, &notification.web);
	out
}

/// RFC 8030's `Topic` is at most 32 characters of the base64url alphabet, which a customer's
/// collapse key need not be; a hash of it is, and the same key always maps to the same topic.
pub fn topic(collapse_key: &str) -> String {
	let digest = ring::digest::digest(&ring::digest::SHA256, collapse_key.as_bytes());
	crate::b64url(&digest.as_ref()[..24])
}

/// The request for one browser.
pub fn request(
	notification: &Notification,
	envelope: &Envelope,
	subscription: &Subscription,
	vapid: &EsKey,
	subject: &str,
	now: u64,
) -> Result<Request, WebPushError> {
	// Checked again at send, not only at registration: the list may have shrunk since.
	check_endpoint(subscription.endpoint.as_str())?;
	// Every browser requires a push to SHOW something (`userVisibleOnly`), and Safari revokes the
	// permission of a site whose push shows nothing. A silent push is refused for the web rather
	// than costing the customer their subscribers.
	if notification.background {
		return Err(error(
			"A background (silent) notification cannot go to a browser: browsers require every push to show something, and Safari removes the permission of a site whose push does not.",
		));
	}
	let plaintext = Value::Object(payload(notification)).to_string();
	let body = encrypt(subscription, plaintext.as_bytes())?;
	let mut headers = vec![
		(
			"authorization".to_string(),
			vapid_authorization(vapid, &subscription.endpoint, subject, now)?,
		),
		("content-encoding".to_string(), "aes128gcm".to_string()),
		(
			"content-type".to_string(),
			"application/octet-stream".to_string(),
		),
		(
			"ttl".to_string(),
			envelope.ttl.unwrap_or(DEFAULT_TTL).to_string(),
		),
		(
			"urgency".to_string(),
			if envelope.priority == Priority::High {
				"high"
			} else {
				"normal"
			}
			.to_string(),
		),
	];
	if let Some(key) = &envelope.collapse_key {
		headers.push(("topic".to_string(), topic(key)));
	}
	Ok(Request {
		url: subscription.endpoint.to_string(),
		headers,
		body,
	})
}

/// The push service's answer. `location` is the message's URL on the service, its only id.
pub fn classify(
	status: u16,
	location: Option<&str>,
	retry_after_header: Option<&str>,
	body: &[u8],
) -> Outcome {
	let said = |what: &str| {
		let detail = String::from_utf8_lossy(&body[..body.len().min(200)])
			.trim()
			.to_string();
		if detail.is_empty() {
			format!("Web Push: {what} (HTTP {status})")
		} else {
			format!("Web Push: {what} (HTTP {status}): {detail}")
		}
	};
	match status {
		200..=202 => Outcome::Accepted {
			provider_id: location.map(str::to_string),
		},
		404 | 410 => Outcome::Unregistered {
			reason: said("the subscription has expired or was removed"),
			since_ms: None,
		},
		// The subscription was made with another VAPID key: it can never take ours again.
		403 => Outcome::Unregistered {
			reason: said("the subscription belongs to a different VAPID key"),
			since_ms: None,
		},
		413 => Outcome::Failed {
			reason: said("the message is too large"),
			retry_after: None,
		},
		429 | 500..=599 => Outcome::Failed {
			reason: said("the push service is busy"),
			retry_after: Some(retry_after(retry_after_header, 10)),
		},
		_ => Outcome::Failed {
			reason: said("refused"),
			retry_after: None,
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey as SigKey};

	fn d(text: &str) -> Vec<u8> {
		crate::b64url_decode(&text.replace([' ', '\n'], "")).unwrap()
	}

	/// RFC 8291 Appendix A, from the shared secret on, byte for byte.
	#[test]
	fn rfc_8291_appendix_a() {
		let ecdh_secret = d("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs");
		let ua_public = d(
			"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
		);
		let as_public = d(
			"BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
		);
		let auth = d("BTBZMqHH6r4Tts7J_aSIgg");
		let salt: [u8; 16] = d("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
		let plaintext = d("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24");
		assert_eq!(plaintext, b"When I grow up, I want to be a watermelon");

		let body = seal(
			&ecdh_secret,
			&ua_public,
			&as_public,
			&auth,
			&salt,
			&plaintext,
		)
		.unwrap();
		let header = d(
			"DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8",
		);
		let ciphertext =
			d("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs bI_0LpXMuGvnzQ");
		assert_eq!(header.len(), 86);
		assert_eq!(&body[..86], &header[..], "the header");
		assert_eq!(&body[86..], &ciphertext[..], "the ciphertext");
	}

	/// The full path with a real ECDH: what `encrypt` emits, the receiver can open. The receiver's
	/// half here is the RFC's own derivation run from its side, with ring's ECDH on both.
	#[test]
	fn encrypt_opens_on_the_receiving_side() {
		let rng = SystemRandom::new();
		let ua = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
		let ua_public = ua.compute_public_key().unwrap().as_ref().to_vec();
		let mut auth = [0u8; 16];
		rng.fill(&mut auth).unwrap();
		let subscription = Subscription {
			endpoint: check_endpoint("https://fcm.googleapis.com/fcm/send/abc").unwrap(),
			p256dh: ua_public.clone(),
			auth: auth.to_vec(),
		};
		let body = encrypt(&subscription, b"{\"title\":\"hello\"}").unwrap();

		// The receiver reads the sender's key and salt out of the header and derives the same CEK.
		let salt: [u8; 16] = body[..16].try_into().unwrap();
		assert_eq!(
			u32::from_be_bytes(body[16..20].try_into().unwrap()),
			RECORD_SIZE
		);
		assert_eq!(body[20], 65);
		let as_public = body[21..86].to_vec();
		let ecdh_secret =
			agree_ephemeral(ua, &UnparsedPublicKey::new(&ECDH_P256, &as_public), |s| {
				s.to_vec()
			})
			.unwrap();
		let prk_key = Salt::new(HKDF_SHA256, &auth).extract(&ecdh_secret);
		let mut key_info = b"WebPush: info\0".to_vec();
		key_info.extend_from_slice(&ua_public);
		key_info.extend_from_slice(&as_public);
		let ikm = expand(&prk_key, &key_info, 32).unwrap();
		let prk = Salt::new(HKDF_SHA256, &salt).extract(&ikm);
		let cek = expand(&prk, b"Content-Encoding: aes128gcm\0", 16).unwrap();
		let nonce = expand(&prk, b"Content-Encoding: nonce\0", 12).unwrap();
		let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &cek).unwrap());
		let mut record = body[86..].to_vec();
		let opened = key
			.open_in_place(
				Nonce::try_assume_unique_for_key(&nonce).unwrap(),
				Aad::empty(),
				&mut record,
			)
			.unwrap();
		assert_eq!(opened, b"{\"title\":\"hello\"}\x02");
	}

	#[test]
	fn too_big_is_refused_with_the_numbers() {
		let subscription = Subscription {
			endpoint: check_endpoint("https://web.push.apple.com/abc").unwrap(),
			p256dh: vec![4; 65],
			auth: vec![0; 16],
		};
		let error = encrypt(&subscription, &vec![b'x'; MAX_PLAINTEXT + 1]).unwrap_err();
		assert!(error.0.contains("3993"), "{error}");
		assert_eq!(MAX_PLAINTEXT, 3993);
	}

	#[test]
	fn endpoints_are_the_known_push_services_only() {
		for ok in [
			"https://fcm.googleapis.com/fcm/send/dQw4w9",
			"https://updates.push.services.mozilla.com/wpush/v2/gAAAA",
			"https://web.push.apple.com/QGuQ",
			"https://wns2-par02p.notify.windows.com/w/?token=BQYAAA",
			"https://FCM.googleapis.com/fcm/send/x",
		] {
			assert!(check_endpoint(ok).is_ok(), "{ok}");
		}
		for (bad, says) in [
			("http://fcm.googleapis.com/fcm/send/x", "https"),
			("https://fcm.googleapis.com:8443/x", "port"),
			("https://user:pw@fcm.googleapis.com/x", "credentials"),
			("https://169.254.169.254/latest/meta-data", "host name"),
			("https://[::1]/x", "host name"),
			("https://evil.example/x", "evil.example"),
			("https://fcm.googleapis.com.evil.example/x", "evil.example"),
			("https://notify.windows.com/x", "notify.windows.com"),
			("https://push.apple.com/x", "push.apple.com"),
			(
				"https://evilnotify.windows.com.attacker.net/x",
				"attacker.net",
			),
			("not a url", "not a URL"),
		] {
			let error = check_endpoint(bad).unwrap_err();
			assert!(error.0.contains(says), "{bad}: {error}");
		}
	}

	#[test]
	fn a_subscription_checks_its_keys() {
		let good_key = crate::b64url(&[4u8; 65]);
		let good_auth = crate::b64url(&[1u8; 16]);
		assert!(Subscription::parse("https://web.push.apple.com/x", &good_key, &good_auth).is_ok());
		// Browsers hand keys over padded and in the standard alphabet too.
		use base64::Engine;
		let padded = base64::engine::general_purpose::STANDARD.encode([4u8; 65]);
		assert!(Subscription::parse("https://web.push.apple.com/x", &padded, &good_auth).is_ok());
		assert!(
			Subscription::parse(
				"https://web.push.apple.com/x",
				&crate::b64url(&[4u8; 33]),
				&good_auth
			)
			.is_err()
		);
		assert!(
			Subscription::parse(
				"https://web.push.apple.com/x",
				&good_key,
				&crate::b64url(&[1u8; 8])
			)
			.is_err()
		);
	}

	#[test]
	fn vapid_header_is_a_verifiable_es256_token_for_the_origin() {
		let (key, _) = EsKey::generate().unwrap();
		let endpoint =
			check_endpoint("https://updates.push.services.mozilla.com/wpush/v2/x").unwrap();
		let header =
			vapid_authorization(&key, &endpoint, "mailto:push@snoutdata.com", 1_800_000_000)
				.unwrap();
		let rest = header.strip_prefix("vapid t=").unwrap();
		let (token, k) = rest.split_once(", k=").unwrap();
		assert_eq!(crate::b64url_decode(k).unwrap(), key.public_key());
		let parts: Vec<&str> = token.split('.').collect();
		let claims: serde_json::Value =
			serde_json::from_slice(&crate::b64url_decode(parts[1]).unwrap()).unwrap();
		assert_eq!(claims["aud"], "https://updates.push.services.mozilla.com");
		assert_eq!(claims["exp"], 1_800_000_000 + VAPID_LIFETIME_SECS);
		assert_eq!(claims["sub"], "mailto:push@snoutdata.com");
		SigKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key())
			.verify(
				format!("{}.{}", parts[0], parts[1]).as_bytes(),
				&crate::b64url_decode(parts[2]).unwrap(),
			)
			.unwrap();
	}

	#[test]
	fn a_request_for_a_browser() {
		let rng = SystemRandom::new();
		let ua = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
		let subscription = Subscription {
			endpoint: check_endpoint("https://updates.push.services.mozilla.com/wpush/v2/abc")
				.unwrap(),
			p256dh: ua.compute_public_key().unwrap().as_ref().to_vec(),
			auth: vec![7; 16],
		};
		let (vapid, _) = EsKey::generate().unwrap();
		let n = Notification::from_json(&json!({"title": "Hi", "url": "/inbox", "data": {"id": 1},
			"web": {"requireInteraction": true}}))
		.unwrap();
		let e = Envelope {
			ttl: None,
			priority: Priority::Normal,
			collapse_key: Some("inbox updates, for user 7".into()),
		};
		let r = request(
			&n,
			&e,
			&subscription,
			&vapid,
			"mailto:push@snoutdata.com",
			1_000,
		)
		.unwrap();
		assert_eq!(
			r.url,
			"https://updates.push.services.mozilla.com/wpush/v2/abc"
		);
		assert_eq!(r.header("content-encoding"), Some("aes128gcm"));
		assert_eq!(r.header("ttl"), Some("2419200"));
		assert_eq!(r.header("urgency"), Some("normal"));
		let topic_header = r.header("topic").unwrap();
		assert_eq!(topic_header.len(), 32);
		assert!(
			topic_header
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
		);
		assert_eq!(topic_header, topic("inbox updates, for user 7"));
		assert!(r.header("authorization").unwrap().starts_with("vapid t="));
		assert_eq!(
			Value::Object(payload(&n)),
			json!({"title": "Hi", "url": "/inbox", "data": {"id": 1}, "requireInteraction": true})
		);
	}

	#[test]
	fn a_silent_push_never_goes_to_a_browser() {
		let subscription = Subscription {
			endpoint: check_endpoint("https://web.push.apple.com/abc").unwrap(),
			p256dh: vec![4; 65],
			auth: vec![0; 16],
		};
		let (vapid, _) = EsKey::generate().unwrap();
		let n = Notification::from_json(&json!({"background": true, "data": {"a": 1}})).unwrap();
		let error = request(
			&n,
			&Envelope::default(),
			&subscription,
			&vapid,
			"mailto:x@y.z",
			0,
		)
		.unwrap_err();
		assert!(error.0.contains("Safari"), "{error}");
	}

	#[test]
	fn what_a_push_service_says() {
		assert_eq!(
			classify(201, Some("https://fcm.googleapis.com/0:1"), None, b""),
			Outcome::Accepted {
				provider_id: Some("https://fcm.googleapis.com/0:1".into())
			}
		);
		assert!(matches!(
			classify(410, None, None, b""),
			Outcome::Unregistered { .. }
		));
		assert!(matches!(
			classify(404, None, None, b"gone"),
			Outcome::Unregistered { .. }
		));
		assert!(
			matches!(classify(403, None, None, b""), Outcome::Unregistered { reason, .. } if reason.contains("VAPID"))
		);
		assert!(matches!(
			classify(429, None, Some("120"), b""),
			Outcome::Failed {
				retry_after: Some(120),
				..
			}
		));
		assert!(matches!(
			classify(413, None, None, b""),
			Outcome::Failed {
				retry_after: None,
				..
			}
		));
	}
}
