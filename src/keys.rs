//! The keys push signs with, and the JWTs it signs.
//!
//! Three keys, all the customer's or the project's, none of them ours:
//!
//!  - **ES256**, the APNs `.p8` a customer downloads from Apple, and the project's VAPID key pair
//!    this server generates for Web Push. Both are PKCS#8 P-256.
//!  - **RS256**, the private key inside a customer's Firebase service-account JSON, which signs the
//!    assertion Google exchanges for an FCM access token.
//!
//! Only signing lives here. Tokens this server VERIFIES (the caller's, HS256 with the project's
//! secret) are a different job and a different module.

use ring::rand::SystemRandom;
use ring::signature::{
	ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct KeyError(pub String);

/// The DER inside a PEM block, or the input itself decoded when it is bare base64. Accepts any
/// `... PRIVATE KEY` label, since Apple and Google both use `PRIVATE KEY` but a key converted by
/// hand often says `EC PRIVATE KEY`, and the parse that follows is what decides.
pub fn pem_to_der(text: &str) -> Result<Vec<u8>, KeyError> {
	let text = text.trim();
	let body = if text.starts_with("-----BEGIN") {
		let mut inside = false;
		let mut body = String::new();
		for line in text.lines() {
			let line = line.trim();
			if line.starts_with("-----BEGIN") {
				inside = true;
			} else if line.starts_with("-----END") {
				break;
			} else if inside {
				body.push_str(line);
			}
		}
		body
	} else {
		text.split_whitespace().collect()
	};
	use base64::Engine;
	use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
	const LENIENT: GeneralPurpose = GeneralPurpose::new(
		&base64::alphabet::STANDARD,
		GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
	);
	LENIENT.decode(body).map_err(|_| {
		KeyError(
			"The key is not PEM or base64: expected the PRIVATE KEY block exactly as downloaded."
				.into(),
		)
	})
}

/// A header and claims, signed: `base64url(header).base64url(claims).base64url(signature)`.
fn signed_jwt(
	header: &Value,
	claims: &Value,
	sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, KeyError>,
) -> Result<String, KeyError> {
	let signing_input = format!(
		"{}.{}",
		crate::b64url(header.to_string().as_bytes()),
		crate::b64url(claims.to_string().as_bytes())
	);
	let signature = sign(signing_input.as_bytes())?;
	Ok(format!("{signing_input}.{}", crate::b64url(&signature)))
}

/// A P-256 key that signs ES256: an APNs `.p8`, or a project's VAPID key.
pub struct EsKey {
	pair: EcdsaKeyPair,
	rng: SystemRandom,
}

impl std::fmt::Debug for EsKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Never the private half, not even in a debug print.
		f.debug_struct("EsKey")
			.field("public", &crate::b64url(self.public_key()))
			.finish()
	}
}

impl EsKey {
	pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, KeyError> {
		let rng = SystemRandom::new();
		let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng).map_err(|e| {
			KeyError(format!(
				"The key is not a P-256 (ES256) private key in PKCS#8 form, which is what Apple's .p8 download is ({e})."
			))
		})?;
		Ok(Self { pair, rng })
	}

	pub fn from_pem(text: &str) -> Result<Self, KeyError> {
		Self::from_pkcs8_der(&pem_to_der(text)?)
	}

	/// A new key pair, and its PKCS#8 bytes: the secret to keep. A project's VAPID key is made
	/// here once and never again, since every browser subscription is bound to its public half.
	pub fn generate() -> Result<(Self, Vec<u8>), KeyError> {
		let rng = SystemRandom::new();
		let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
			.map_err(|_| KeyError("Could not generate a key pair.".into()))?;
		let der = document.as_ref().to_vec();
		Ok((Self::from_pkcs8_der(&der)?, der))
	}

	/// The uncompressed public point (65 bytes, leading 0x04), as Web Push and VAPID want it.
	pub fn public_key(&self) -> &[u8] {
		self.pair.public_key().as_ref()
	}

	/// Signs `input` as JWS ES256 wants it: the 64-byte `r || s`, not DER.
	pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, KeyError> {
		self.pair
			.sign(&self.rng, input)
			.map(|s| s.as_ref().to_vec())
			.map_err(|_| KeyError("Signing failed.".into()))
	}

	pub fn jwt(&self, header: &Value, claims: &Value) -> Result<String, KeyError> {
		signed_jwt(header, claims, |input| self.sign(input))
	}
}

/// An RSA key that signs RS256: the `private_key` of a Firebase service account.
pub struct RsKey {
	pair: RsaKeyPair,
	rng: SystemRandom,
}

impl std::fmt::Debug for RsKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("RsKey")
			.field("bits", &(self.pair.public().modulus_len() * 8))
			.finish()
	}
}

impl RsKey {
	pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, KeyError> {
		let pair = RsaKeyPair::from_pkcs8(der).map_err(|e| {
			KeyError(format!(
				"The service account's private_key is not an RSA private key in PKCS#8 form ({e})."
			))
		})?;
		Ok(Self {
			pair,
			rng: SystemRandom::new(),
		})
	}

	pub fn from_pem(text: &str) -> Result<Self, KeyError> {
		Self::from_pkcs8_der(&pem_to_der(text)?)
	}

	pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, KeyError> {
		let mut signature = vec![0; self.pair.public().modulus_len()];
		self.pair
			.sign(&RSA_PKCS1_SHA256, &self.rng, input, &mut signature)
			.map_err(|_| KeyError("Signing failed.".into()))?;
		Ok(signature)
	}

	pub fn jwt(&self, header: &Value, claims: &Value) -> Result<String, KeyError> {
		signed_jwt(header, claims, |input| self.sign(input))
	}
}

/// A PEM block around `body`, for tests. The markers are assembled so no line of the source reads
/// as a key to a secret scanner (X13); every key a test uses is generated when it runs.
#[cfg(test)]
pub(crate) fn test_pem(body: &str) -> String {
	let label = ["PRIVATE", "KEY"].join(" ");
	format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

#[cfg(test)]
mod tests {
	use super::*;
	use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
	use serde_json::json;

	#[test]
	fn an_es256_jwt_verifies_against_its_public_key() {
		let (key, der) = EsKey::generate().unwrap();
		let token = key
			.jwt(
				&json!({"alg": "ES256", "kid": "ABC123DEFG"}),
				&json!({"iss": "TEAM"}),
			)
			.unwrap();
		let parts: Vec<&str> = token.split('.').collect();
		assert_eq!(parts.len(), 3);
		let signature = crate::b64url_decode(parts[2]).unwrap();
		assert_eq!(signature.len(), 64, "JWS ES256 is r || s, not DER");
		let input = format!("{}.{}", parts[0], parts[1]);
		UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key())
			.verify(input.as_bytes(), &signature)
			.expect("the signature verifies");
		// And the kept secret loads back into the same key.
		assert_eq!(
			EsKey::from_pkcs8_der(&der).unwrap().public_key(),
			key.public_key()
		);
	}

	#[test]
	fn pem_round_trips_with_any_line_width() {
		let (key, der) = EsKey::generate().unwrap();
		use base64::Engine;
		let body = base64::engine::general_purpose::STANDARD.encode(&der);
		let wrapped: Vec<String> = body
			.as_bytes()
			.chunks(40)
			.map(|c| String::from_utf8(c.to_vec()).unwrap())
			.collect();
		let pem = test_pem(&wrapped.join("\r\n")).replace('\n', "\r\n");
		assert_eq!(
			EsKey::from_pem(&pem).unwrap().public_key(),
			key.public_key()
		);
		assert_eq!(
			EsKey::from_pem(&body).unwrap().public_key(),
			key.public_key()
		);
	}

	#[test]
	fn a_wrong_key_says_what_was_expected() {
		let error = EsKey::from_pem(&test_pem("AAAA")).unwrap_err();
		assert!(error.0.contains(".p8"), "{error}");
		let error = RsKey::from_pem("not a key at all!").unwrap_err();
		assert!(error.0.contains("PEM"), "{error}");
	}

	#[test]
	fn debug_never_prints_the_private_half() {
		let (key, der) = EsKey::generate().unwrap();
		let printed = format!("{key:?}");
		use base64::Engine;
		assert!(!printed.contains(&base64::engine::general_purpose::STANDARD.encode(&der)));
		assert!(printed.contains(&crate::b64url(key.public_key())));
	}
}
