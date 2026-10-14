//! The caller's token: HS256, signed with the project's JWT secret, as every SnoutData Cloud
//! project signs them. Verified here, in constant time, before anything reaches the database.
//!
//! The `role` claim becomes the database role the request runs as, so it is restricted to the
//! three API roles: a token that names any other role (`postgres`, the schema's owner) is refused,
//! however well it is signed.

use serde_json::{Map, Value};

use crate::migrations::Roles;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct JwtError(pub String);

fn refuse(message: &str) -> JwtError {
	JwtError(message.to_string())
}

/// The verified claims, and the role they run as.
#[derive(Debug, Clone, PartialEq)]
pub struct Caller {
	pub role: String,
	pub claims: Map<String, Value>,
}

/// Verifies `token` and returns the caller. `now` is seconds since the epoch.
pub fn verify(token: &str, secret: &str, roles: &Roles, now: u64) -> Result<Caller, JwtError> {
	let parts: Vec<&str> = token.split('.').collect();
	let [header, payload, signature] = parts[..] else {
		return Err(refuse("The token is not a JWT."));
	};
	let header: Value = crate::b64url_decode(header)
		.and_then(|b| serde_json::from_slice(&b).ok())
		.ok_or_else(|| refuse("The token's header is not JSON."))?;
	if header.get("alg").and_then(Value::as_str) != Some("HS256") {
		return Err(refuse(
			"The token must be signed HS256 with the project's JWT secret.",
		));
	}
	let signature = crate::b64url_decode(signature)
		.ok_or_else(|| refuse("The token's signature is not base64url."))?;
	let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
	let signed = &token[..token.len() - parts[2].len() - 1];
	ring::hmac::verify(&key, signed.as_bytes(), &signature)
		.map_err(|_| refuse("The token's signature does not verify."))?;

	let claims: Map<String, Value> = crate::b64url_decode(payload)
		.and_then(|b| serde_json::from_slice(&b).ok())
		.ok_or_else(|| refuse("The token's claims are not a JSON object."))?;
	let now = now as f64;
	if claims
		.get("exp")
		.and_then(Value::as_f64)
		.is_some_and(|exp| exp <= now)
	{
		return Err(refuse("The token has expired."));
	}
	if claims
		.get("nbf")
		.and_then(Value::as_f64)
		.is_some_and(|nbf| nbf > now + 30.0)
	{
		return Err(refuse("The token is not valid yet."));
	}
	let role = claims
		.get("role")
		.and_then(Value::as_str)
		.unwrap_or(&roles.anon)
		.to_string();
	if ![&roles.anon, &roles.authenticated, &roles.service].contains(&&role) {
		return Err(refuse("The token's role is not one this API runs as."));
	}
	Ok(Caller { role, claims })
}

#[cfg(test)]
pub(crate) fn sign(claims: &Value, secret: &str) -> String {
	let head = crate::b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
	let body = crate::b64url(claims.to_string().as_bytes());
	let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
	let tag = ring::hmac::sign(&key, format!("{head}.{body}").as_bytes());
	format!("{head}.{body}.{}", crate::b64url(tag.as_ref()))
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	const SECRET: &str = "a-project-secret-of-at-least-32-chars";

	#[test]
	fn a_good_token_names_its_role() {
		let token = sign(
			&json!({"sub": "u1", "role": "authenticated", "exp": 2000}),
			SECRET,
		);
		let caller = verify(&token, SECRET, &Roles::default(), 1000).unwrap();
		assert_eq!(caller.role, "authenticated");
		assert_eq!(caller.claims["sub"], "u1");
	}

	#[test]
	fn refusals() {
		let roles = Roles::default();
		let expired = sign(&json!({"role": "anon", "exp": 999}), SECRET);
		assert!(
			verify(&expired, SECRET, &roles, 1000)
				.unwrap_err()
				.0
				.contains("expired")
		);
		let other_secret = sign(
			&json!({"role": "anon"}),
			"another-secret-of-at-least-32-chars!",
		);
		assert!(
			verify(&other_secret, SECRET, &roles, 0)
				.unwrap_err()
				.0
				.contains("does not verify")
		);
		let superuser = sign(&json!({"role": "postgres"}), SECRET);
		assert!(
			verify(&superuser, SECRET, &roles, 0)
				.unwrap_err()
				.0
				.contains("role")
		);
		assert!(verify("a.b", SECRET, &roles, 0).is_err());
		// alg: none, however it is dressed up.
		let none = format!(
			"{}.{}.",
			crate::b64url(br#"{"alg":"none"}"#),
			crate::b64url(br#"{"role":"service_role"}"#)
		);
		assert!(
			verify(&none, SECRET, &roles, 0)
				.unwrap_err()
				.0
				.contains("HS256")
		);
		// A token with no role is anon.
		assert_eq!(
			verify(&sign(&json!({}), SECRET), SECRET, &roles, 0)
				.unwrap()
				.role,
			"anon"
		);
	}
}
