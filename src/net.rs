//! The only way this server makes a request, and the rules every request keeps.
//!
//! A Web Push endpoint is a URL a stranger's browser handed us, and the fleet's
//! network cannot filter by host name, so the checks live here, in process:
//!
//!  - **Every address is checked before a connection is made.** The client resolves names through
//!    [`SafeResolver`], which drops anything private, loopback, link-local, carrier-grade NAT,
//!    multicast, reserved or documentation-only, in IPv4 and IPv6 (including IPv4 carried inside
//!    IPv6). The connection goes to an address that passed, so a name that resolves to a public
//!    address when checked and a private one a moment later (DNS rebinding) never reaches the
//!    private one: there is no second lookup.
//!  - **A URL naming an address directly is refused**, since it would skip the resolver.
//!  - **No redirects, no proxies, https only, bounded time, bounded response.** A push service has
//!    no reason to redirect, and following one would be a second, unchecked destination.
//!
//! None of it can be turned off in a running server: the relaxed policy exists only in tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::notification::Request;

/// How much of a response body is read. Every provider's error is a few hundred bytes.
pub const MAX_RESPONSE: usize = 64 * 1024;
/// Per request, connect to last byte. Providers answer in well under a second.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum NetError {
	#[error("{0}")]
	Refused(String),
	#[error("{0}")]
	Transport(String),
}

impl NetError {
	/// A network failure could succeed next time; a refusal by these rules never will.
	pub fn retryable(&self) -> bool {
		matches!(self, NetError::Transport(_))
	}
}

/// What came back: the status, the headers a classifier reads, and at most [`MAX_RESPONSE`] bytes.
#[derive(Debug, Clone)]
pub struct Response {
	pub status: u16,
	pub headers: Vec<(String, String)>,
	pub body: Vec<u8>,
}

impl Response {
	pub fn header(&self, name: &str) -> Option<&str> {
		self.headers
			.iter()
			.find(|(n, _)| n.eq_ignore_ascii_case(name))
			.map(|(_, v)| v.as_str())
	}
}

/// Whether an address is somewhere on the public internet this server may send to.
pub fn is_public(ip: IpAddr) -> bool {
	match ip {
		IpAddr::V4(v4) => is_public_v4(v4),
		IpAddr::V6(v6) => is_public_v6(v6),
	}
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
	let [a, b, c, _] = ip.octets();
	!(ip.is_unspecified()
		|| ip.is_loopback()
		|| ip.is_private()
		|| ip.is_link_local()
		|| ip.is_broadcast()
		|| ip.is_multicast()
		|| ip.is_documentation()
		|| a == 0
		// Carrier-grade NAT (100.64/10).
		|| (a == 100 && (64..=127).contains(&b))
		// IETF protocol assignments (192.0.0/24) and 6to4 relay anycast (192.88.99/24).
		|| (a == 192 && b == 0 && c == 0)
		|| (a == 192 && b == 88 && c == 99)
		// Benchmarking (198.18/15).
		|| (a == 198 && (b == 18 || b == 19))
		// Reserved (240/4).
		|| a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
	let s = ip.segments();
	// IPv4 carried in IPv6 is judged as the IPv4 it carries.
	if let Some(v4) = ip.to_ipv4_mapped() {
		return is_public_v4(v4);
	}
	// NAT64 (64:ff9b::/96): the last 32 bits are an IPv4 address.
	if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
		return is_public_v4(Ipv4Addr::new(
			(s[6] >> 8) as u8,
			s[6] as u8,
			(s[7] >> 8) as u8,
			s[7] as u8,
		));
	}
	// 6to4 (2002::/16): bits 16-47 are an IPv4 address.
	if s[0] == 0x2002 {
		return is_public_v4(Ipv4Addr::new(
			(s[1] >> 8) as u8,
			s[1] as u8,
			(s[2] >> 8) as u8,
			s[2] as u8,
		));
	}
	!(ip.is_unspecified()
		|| ip.is_loopback()
		|| ip.is_multicast()
		// Unique local (fc00::/7) and link-local (fe80::/10).
		|| (s[0] & 0xfe00) == 0xfc00
		|| (s[0] & 0xffc0) == 0xfe80
		// Site-local, deprecated but still routed somewhere (fec0::/10).
		|| (s[0] & 0xffc0) == 0xfec0
		// Documentation (2001:db8::/32) and Teredo (2001::/32, which tunnels to anywhere).
		|| (s[0] == 0x2001 && s[1] == 0x0db8)
		|| (s[0] == 0x2001 && s[1] == 0)
		// The old IPv4-compatible form (::a.b.c.d) and discard-only (100::/64).
		|| (s[0..6] == [0, 0, 0, 0, 0, 0])
		|| (s[0] == 0x100 && s[1..4] == [0, 0, 0]))
}

/// Resolves a host name to the addresses that pass [`is_public`], or refuses.
#[derive(Debug, Clone, Copy)]
pub struct SafeResolver {
	allow_private: bool,
}

impl reqwest::dns::Resolve for SafeResolver {
	fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
		let allow_private = self.allow_private;
		let host = name.as_str().to_string();
		Box::pin(async move {
			let found: Vec<SocketAddr> =
				tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
			let kept: Vec<SocketAddr> = found
				.iter()
				.copied()
				.filter(|addr| allow_private || is_public(addr.ip()))
				.collect();
			if kept.is_empty() {
				let error: Box<dyn std::error::Error + Send + Sync> = if found.is_empty() {
					format!("{host} does not resolve").into()
				} else {
					format!("{host} resolves only to addresses Snout Push does not send to").into()
				};
				return Err(error);
			}
			let addrs: reqwest::dns::Addrs = Box::new(kept.into_iter());
			Ok(addrs)
		})
	}
}

/// The rules a client keeps. Production has exactly one; the relaxed one is for tests against a
/// server on this machine.
#[derive(Debug, Clone)]
pub struct Policy {
	allow_private: bool,
	https_only: bool,
	#[cfg(test)]
	origin: Option<String>,
}

impl Policy {
	pub fn strict() -> Self {
		Self {
			allow_private: false,
			https_only: true,
			#[cfg(test)]
			origin: None,
		}
	}

	/// Plain http to 127.0.0.1, with every request's origin replaced by `origin`, so the real
	/// provider URLs a builder makes reach a local stand-in.
	#[cfg(test)]
	pub fn local(origin: &str) -> Self {
		Self {
			allow_private: true,
			https_only: false,
			origin: Some(origin.trim_end_matches('/').to_string()),
		}
	}
}

/// A client: its own connection pool, so a caller that must not share connections (APNs: one
/// team per connection) makes its own, and everyone else shares one.
#[derive(Debug, Clone)]
pub struct Http {
	client: reqwest::Client,
	policy: Policy,
}

impl Http {
	pub fn new(policy: Policy) -> Result<Self, NetError> {
		let client = reqwest::Client::builder()
			.dns_resolver(Arc::new(SafeResolver {
				allow_private: policy.allow_private,
			}))
			.redirect(reqwest::redirect::Policy::none())
			.no_proxy()
			.https_only(policy.https_only)
			.connect_timeout(CONNECT_TIMEOUT)
			.timeout(REQUEST_TIMEOUT)
			.pool_idle_timeout(Duration::from_secs(300))
			.http2_keep_alive_interval(Duration::from_secs(60))
			.http2_keep_alive_while_idle(true)
			.user_agent(concat!("snout-push/", env!("CARGO_PKG_VERSION")))
			.build()
			.map_err(|e| NetError::Transport(format!("could not build an HTTP client: {e}")))?;
		Ok(Self { client, policy })
	}

	fn url(&self, request: &Request) -> Result<url::Url, NetError> {
		#[allow(unused_mut)]
		let mut url = url::Url::parse(&request.url)
			.map_err(|_| NetError::Refused(format!("not a URL: {}", request.url)))?;
		if !self.policy.allow_private {
			match url.host() {
				Some(url::Host::Domain(_)) => {}
				_ => {
					return Err(NetError::Refused(
						"a request must name its host, not an address".into(),
					));
				}
			}
		}
		#[cfg(test)]
		if let Some(origin) = &self.policy.origin {
			let path = url[url::Position::BeforePath..].to_string();
			url = url::Url::parse(&format!("{origin}{path}"))
				.map_err(|_| NetError::Refused("bad test origin".into()))?;
		}
		Ok(url)
	}

	/// Sends one request and reads at most [`MAX_RESPONSE`] of the answer.
	pub async fn send(&self, request: &Request) -> Result<Response, NetError> {
		let url = self.url(request)?;
		let mut builder = self.client.post(url).body(request.body.clone());
		for (name, value) in &request.headers {
			builder = builder.header(name, value);
		}
		let mut response = builder.send().await.map_err(|e| {
			// The resolver's refusal arrives as a connect error; say which it was.
			let text = format!("{e:#}");
			let chain = std::iter::successors(std::error::Error::source(&e), |s| s.source())
				.map(ToString::to_string)
				.collect::<Vec<_>>()
				.join(": ");
			if chain.contains("does not send to") {
				NetError::Refused(chain)
			} else if chain.is_empty() {
				NetError::Transport(text)
			} else {
				NetError::Transport(format!("{text}: {chain}"))
			}
		})?;
		let status = response.status().as_u16();
		let headers = response
			.headers()
			.iter()
			.filter_map(|(n, v)| {
				v.to_str()
					.ok()
					.map(|v| (n.as_str().to_string(), v.to_string()))
			})
			.collect();
		let mut body = Vec::new();
		while let Some(chunk) = response
			.chunk()
			.await
			.map_err(|e| NetError::Transport(e.to_string()))?
		{
			let room = MAX_RESPONSE - body.len();
			body.extend_from_slice(&chunk[..chunk.len().min(room)]);
			if body.len() >= MAX_RESPONSE {
				break;
			}
		}
		Ok(Response {
			status,
			headers,
			body,
		})
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;

	#[test]
	fn what_counts_as_public() {
		for public in [
			"17.188.143.34",
			"142.250.72.106",
			"2620:149:a44::1",
			"2a00:1450:4001::200e",
			"1.1.1.1",
		] {
			assert!(is_public(public.parse().unwrap()), "{public}");
		}
		for private in [
			"127.0.0.1",
			"10.92.0.5",
			"172.16.0.1",
			"192.168.1.1",
			"169.254.169.254",
			"100.64.0.1",
			"0.0.0.0",
			"0.1.2.3",
			"255.255.255.255",
			"224.0.0.1",
			"240.0.0.1",
			"192.0.2.1",
			"198.18.0.1",
			"192.0.0.8",
			"::1",
			"::",
			"fc00::1",
			"fd12:3456::1",
			"fe80::1",
			"fec0::1",
			"ff02::1",
			"2001:db8::1",
			"2001::1",
			"::ffff:127.0.0.1",
			"::ffff:169.254.169.254",
			"64:ff9b::a9fe:a9fe",
			"2002:a9fe:a9fe::1",
			"::127.0.0.1",
			"100::1",
		] {
			assert!(!is_public(private.parse().unwrap()), "{private}");
		}
		// Public IPv4 inside NAT64 and 6to4 is public.
		assert!(is_public("64:ff9b::808:808".parse().unwrap()));
		assert!(is_public("2002:808:808::1".parse().unwrap()));
	}

	#[tokio::test]
	async fn the_strict_client_refuses_this_machine() {
		let http = Http::new(Policy::strict()).unwrap();
		for url in [
			"https://127.0.0.1/x",
			"https://[::1]/x",
			"https://169.254.169.254/latest",
		] {
			let error = http
				.send(&Request {
					url: url.into(),
					headers: vec![],
					body: vec![],
				})
				.await
				.unwrap_err();
			assert!(matches!(error, NetError::Refused(_)), "{url}: {error}");
			assert!(!error.retryable());
		}
		// A NAME that resolves to loopback is refused by the resolver, before any connection.
		let error = http
			.send(&Request {
				url: "https://localhost/x".into(),
				headers: vec![],
				body: vec![],
			})
			.await
			.unwrap_err();
		assert!(
			matches!(&error, NetError::Refused(m) if m.contains("does not send to")),
			"{error}"
		);
		// And plain http is refused outright.
		let error = http
			.send(&Request {
				url: "http://example.com/x".into(),
				headers: vec![],
				body: vec![],
			})
			.await
			.unwrap_err();
		assert!(
			format!("{error}").to_lowercase().contains("http"),
			"{error}"
		);
	}

	/// What a stand-in received: the path, the headers, the body.
	pub(crate) type Seen = (String, Vec<(String, String)>, Vec<u8>);

	/// A stand-in provider on 127.0.0.1 that answers every request with `status`, `headers` and
	/// `body`, and hands back what it received.
	pub(crate) async fn stand_in(
		status: u16,
		headers: Vec<(&'static str, &'static str)>,
		body: Vec<u8>,
	) -> (String, tokio::sync::mpsc::UnboundedReceiver<Seen>) {
		stand_in_with(move |_| (status, headers.clone(), body.clone())).await
	}

	/// A stand-in whose answer depends on the path (a token endpoint and a send endpoint on one
	/// origin, or a first answer and then a second).
	pub(crate) async fn stand_in_with(
		answer: impl Fn(&str) -> (u16, Vec<(&'static str, &'static str)>, Vec<u8>)
		+ Clone
		+ Send
		+ Sync
		+ 'static,
	) -> (String, tokio::sync::mpsc::UnboundedReceiver<Seen>) {
		use axum::body::Bytes;
		use axum::http::{HeaderMap, StatusCode, Uri};
		let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
		let app = axum::Router::new().fallback(move |uri: Uri, got: HeaderMap, sent: Bytes| {
			let tx = tx.clone();
			let answer = answer.clone();
			async move {
				let seen = got
					.iter()
					.map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
					.collect();
				let path = uri.to_string();
				let (status, headers, body) = answer(&path);
				let _ = tx.send((path, seen, sent.to_vec()));
				let mut reply = HeaderMap::new();
				for (n, v) in headers {
					reply.insert(n, v.parse().unwrap());
				}
				(StatusCode::from_u16(status).unwrap(), reply, body)
			}
		});
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let origin = format!("http://{}", listener.local_addr().unwrap());
		tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
		(origin, rx)
	}

	#[tokio::test]
	async fn a_round_trip_keeps_the_path_and_headers_and_caps_the_body() {
		let (origin, mut seen) =
			stand_in(410, vec![("apns-id", "abc")], vec![b'x'; MAX_RESPONSE * 2]).await;
		let http = Http::new(Policy::local(&origin)).unwrap();
		let response = http
			.send(&Request {
				url: "https://api.push.apple.com/3/device/abcd".into(),
				headers: vec![("apns-topic".into(), "com.example.app".into())],
				body: b"{}".to_vec(),
			})
			.await
			.unwrap();
		assert_eq!(response.status, 410);
		assert_eq!(response.header("apns-id"), Some("abc"));
		assert_eq!(response.body.len(), MAX_RESPONSE);
		let (uri, headers, body) = seen.recv().await.unwrap();
		assert_eq!(uri, "/3/device/abcd");
		assert!(
			headers
				.iter()
				.any(|(n, v)| n == "apns-topic" && v == "com.example.app")
		);
		assert_eq!(body, b"{}");
	}

	#[tokio::test]
	async fn a_redirect_is_not_followed() {
		let (origin, _seen) = stand_in(
			307,
			vec![("location", "http://169.254.169.254/latest")],
			vec![],
		)
		.await;
		let http = Http::new(Policy::local(&origin)).unwrap();
		let response = http
			.send(&Request {
				url: "https://fcm.googleapis.com/x".into(),
				headers: vec![],
				body: vec![],
			})
			.await
			.unwrap();
		assert_eq!(
			response.status, 307,
			"the redirect comes back as an answer, not a second request"
		);
	}
}
