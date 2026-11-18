//! Social publishing credentials and identity verification.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use zeroize::Zeroizing;

/// An input field required for enrollment.
pub struct Input {
    pub name: &'static str,
    pub secret: bool,
    /// May be left out; the platform then discovers it.
    pub optional: bool,
}

/// An n8n credential and its single secret field.
pub struct Credential {
    pub name: &'static str,
    pub kind: &'static str,
    pub field: &'static str,
    pub slug: &'static str,
}

/// The supported provider and its enrollment contract.
pub struct Platform {
    pub name: &'static str,
    pub inputs: &'static [Input],
    pub credentials: &'static [Credential],
    pub account_id_kind: &'static str,
}

const TOKEN: &[Input] = &[Input {
    name: "token",
    secret: true,
    optional: false,
}];
const BLUESKY: &[Input] = &[
    Input {
        name: "handle",
        secret: false,
        optional: false,
    },
    Input {
        name: "password",
        secret: true,
        optional: false,
    },
    Input {
        name: "pds",
        secret: false,
        optional: true,
    },
];
const MASTODON: &[Input] = &[
    Input {
        name: "instance",
        secret: false,
        optional: false,
    },
    Input {
        name: "token",
        secret: true,
        optional: false,
    },
];

/// Providers supported by the n8n publish contract.
pub static PLATFORMS: &[Platform] = &[
    Platform {
        name: "bluesky",
        inputs: BLUESKY,
        account_id_kind: "did",
        credentials: &[Credential {
            name: "Bluesky app password",
            kind: "httpCustomAuth",
            field: "json",
            slug: "app-password",
        }],
    },
    Platform {
        name: "mastodon",
        inputs: MASTODON,
        account_id_kind: "account id",
        credentials: &[Credential {
            name: "Mastodon access token",
            kind: "httpHeaderAuth",
            field: "value",
            slug: "access-token",
        }],
    },
    Platform {
        name: "linkedin",
        inputs: TOKEN,
        account_id_kind: "member URN",
        credentials: &[Credential {
            name: "LinkedIn Posts token",
            kind: "httpHeaderAuth",
            field: "value",
            slug: "posts-token",
        }],
    },
    Platform {
        name: "threads",
        inputs: TOKEN,
        account_id_kind: "user id",
        credentials: &[Credential {
            name: "Threads access token",
            kind: "httpQueryAuth",
            field: "value",
            slug: "access-token",
        }],
    },
    Platform {
        name: "facebook-page",
        inputs: TOKEN,
        account_id_kind: "page id",
        credentials: &[
            Credential {
                name: "Facebook Page Graph token",
                kind: "httpQueryAuth",
                field: "value",
                slug: "graph-token",
            },
            Credential {
                name: "Facebook Reels upload token",
                kind: "httpHeaderAuth",
                field: "value",
                slug: "reels-token",
            },
        ],
    },
];

/// A verified provider identity.
#[derive(Debug, PartialEq, Eq)]
pub struct Identity {
    pub account_id: String,
    pub handle: String,
    pub origin: Option<String>,
}

/// Look up a platform by its CLI name.
pub fn platform(name: &str) -> Option<&'static Platform> {
    PLATFORMS.iter().find(|p| p.name == name)
}

fn input<'a>(values: &'a BTreeMap<String, Zeroizing<String>>, name: &str) -> Result<&'a str> {
    values
        .get(name)
        .map(|v| v.as_str())
        .filter(|v| !v.is_empty() && !v.chars().any(char::is_control))
        .with_context(|| format!("missing or invalid {name}"))
}

/// Render credential fields without exposing them through Debug or logs.
pub fn render(
    p: &Platform,
    values: &BTreeMap<String, Zeroizing<String>>,
) -> Result<Vec<Zeroizing<String>>> {
    let token = || input(values, "token");
    Ok(match p.name {
        "bluesky" => vec![Zeroizing::new(json!({"body": {"identifier": input(values, "handle")?, "password": input(values, "password")?}}).to_string())],
        "mastodon" | "linkedin" => vec![Zeroizing::new(format!("Bearer {}", token()?))],
        "threads" => vec![Zeroizing::new(token()?.to_owned())],
        "facebook-page" => vec![Zeroizing::new(token()?.to_owned()), Zeroizing::new(format!("OAuth {}", token()?))],
        _ => bail!("unsupported platform"),
    })
}

/// Parse a successful provider response, rejecting incomplete identities.
pub fn parse_identity(p: &Platform, body: &Value) -> Result<Identity> {
    if p.name == "facebook-page" {
        ensure!(
            body.get("category")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()),
            "provider response is not a Facebook Page"
        );
    }
    let (id, handle) = match p.name {
        "bluesky" => ("did", "handle"),
        "mastodon" => ("id", "acct"),
        "linkedin" => ("sub", "name"),
        "threads" => ("id", "username"),
        "facebook-page" => ("id", "name"),
        _ => bail!("unsupported platform"),
    };
    let id = body
        .get(id)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .context("provider response missing identity")?;
    let handle = body
        .get(handle)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .context("provider response missing handle")?;
    Ok(Identity {
        account_id: if p.name == "linkedin" {
            format!("urn:li:person:{id}")
        } else {
            id.to_owned()
        },
        handle: handle.to_owned(),
        origin: None,
    })
}

fn origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid origin"))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "must be an HTTPS origin"
    );
    Ok(url.origin().ascii_serialization())
}

fn did_url(did: &str) -> Result<String> {
    if let Some(id) = did.strip_prefix("did:plc:") {
        ensure!(
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "invalid PLC DID"
        );
        Ok(format!("https://plc.directory/{did}"))
    } else if let Some(host) = did.strip_prefix("did:web:") {
        ensure!(
            !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "unsupported web DID"
        );
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        bail!("unsupported DID method")
    }
}

/// The account's PDS origin from its DID document: the `#atproto_pds`
/// service of type `AtprotoPersonalDataServer`. `bsky.social` is only an
/// entryway, so the document, not a default, names where the account lives.
fn discovered_pds(did: &str, doc: &Value) -> Result<String> {
    ensure!(
        doc.get("id").and_then(Value::as_str) == Some(did),
        "DID document identity mismatch"
    );
    let endpoint =
        doc.get("service")
            .and_then(Value::as_array)
            .and_then(|services| {
                services.iter().find(|s| {
                    s.get("id").and_then(Value::as_str).is_some_and(|id| {
                        id == "#atproto_pds" || id == format!("{did}#atproto_pds")
                    }) && s.get("type").and_then(Value::as_str) == Some("AtprotoPersonalDataServer")
                })
            })
            .and_then(|s| s.get("serviceEndpoint"))
            .and_then(Value::as_str)
            .context("DID document missing PDS")?;
    origin(endpoint)
}

/// Whether an address is on the public internet: not loopback, private,
/// link-local, CGNAT, multicast, documentation, unspecified or ULA.
fn is_public(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v) => {
            let [a, b, ..] = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
                || v.is_multicast()
                || a == 0
                || (a == 100 && (b & 0xc0) == 64))
        }
        IpAddr::V6(v) => {
            let first = v.segments()[0];
            match v.to_ipv4_mapped() {
                Some(mapped) => is_public(IpAddr::V4(mapped)),
                None => {
                    !(v.is_loopback()
                        || v.is_unspecified()
                        || v.is_multicast()
                        || (first & 0xfe00) == 0xfc00
                        || (first & 0xffc0) == 0xfe80)
                }
            }
        }
    }
}

/// A client that reaches `host:port` only at the addresses checked public
/// now and never through a proxy (which would resolve the name itself), so a
/// DID document or PDS endpoint cannot point a request at an internal service.
fn pinned_client(host: &str, port: u16) -> Result<reqwest::blocking::Client> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|_| anyhow::anyhow!("could not resolve {host}"))?
        .collect();
    ensure!(
        !addrs.is_empty() && addrs.iter().all(|a| is_public(a.ip())),
        "{host} does not resolve to public addresses only"
    );
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .resolve_to_addrs(host, &addrs)
        .build()
        .context("could not initialize HTTP client")
}

/// A client for an approved IP-literal origin: public only, never proxied.
fn literal_client(ip: std::net::IpAddr) -> Result<reqwest::blocking::Client> {
    ensure!(is_public(ip), "{ip} is not a public address");
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .build()
        .context("could not initialize HTTP client")
}

/// Whether the app password may go to `pds`: a Bluesky-hosted PDS, or the
/// origin the operator approved with `--input pds=…`. A DID document alone
/// never decides where a password is sent.
fn pds_approved(pds: &str, requested: Option<&str>) -> Result<bool> {
    if let Some(requested) = requested {
        return Ok(origin(requested)? == pds);
    }
    let host = url::Url::parse(pds)?
        .host_str()
        .map(str::to_owned)
        .unwrap_or_default();
    Ok(host.ends_with(".host.bsky.network"))
}

/// The DID document must claim the handle back (`alsoKnownAs: at://HANDLE`),
/// so a resolver answer alone cannot bind a handle to someone else's DID.
fn claims_handle(doc: &Value, handle: &str) -> bool {
    let expected = format!("at://{}", handle.to_ascii_lowercase());
    doc.get("alsoKnownAs")
        .and_then(Value::as_array)
        .is_some_and(|aka| {
            aka.iter()
                .filter_map(Value::as_str)
                .any(|a| a.to_ascii_lowercase() == expected)
        })
}

fn response_json(response: reqwest::blocking::Response) -> Result<Value> {
    ensure!(
        response.status().is_success(),
        "provider rejected request (HTTP {})",
        response.status().as_u16()
    );
    response
        .json()
        .map_err(|_| anyhow::anyhow!("invalid provider response"))
}

/// Verify once against the provider. Errors never include request URLs or bodies.
pub fn verify(p: &Platform, values: &BTreeMap<String, Zeroizing<String>>) -> Result<Identity> {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("could not initialize HTTP client")?;
    let mut verified_origin = None;
    let mut expected_did = None;
    let request = match p.name {
        "bluesky" => {
            let handle = input(values, "handle")?;
            let did = if handle.starts_with("did:") {
                handle.to_owned()
            } else {
                let mut url = url::Url::parse(
                    "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle",
                )?;
                url.query_pairs_mut().append_pair("handle", handle);
                let body = response_json(
                    client
                        .get(url)
                        .send()
                        .map_err(|_| anyhow::anyhow!("handle resolution failed"))?,
                )?;
                body.get("did")
                    .and_then(Value::as_str)
                    .context("handle resolution missing DID")?
                    .to_owned()
            };
            // did:web names an arbitrary host: fetch it only at a public address.
            let resolver = match did.strip_prefix("did:web:") {
                Some(host) => pinned_client(host, 443)?,
                None => client.clone(),
            };
            let doc = response_json(
                resolver
                    .get(did_url(&did)?)
                    .send()
                    .map_err(|_| anyhow::anyhow!("DID resolution failed"))?,
            )?;
            let pds = discovered_pds(&did, &doc)?;
            ensure!(
                handle.starts_with("did:") || claims_handle(&doc, handle),
                "the DID document does not claim the handle {handle}"
            );
            let requested = values
                .get("pds")
                .map(|v| v.as_str())
                .filter(|v| !v.is_empty());
            ensure!(
                pds_approved(&pds, requested)?,
                "the account is hosted at {pds}; re-run with --input pds={pds} to approve sending its app password there"
            );
            let pds_url = url::Url::parse(&pds)?;
            let port = pds_url.port_or_known_default().unwrap_or(443);
            let session = match pds_url.host().context("PDS has no host")? {
                url::Host::Domain(host) => pinned_client(host, port)?,
                // An IP literal needs no lookup: check it, never proxy it.
                url::Host::Ipv4(ip) => literal_client(ip.into())?,
                url::Host::Ipv6(ip) => literal_client(ip.into())?,
            };
            expected_did = Some(did);
            verified_origin = Some(pds.clone());
            session
                .post(format!("{pds}/xrpc/com.atproto.server.createSession"))
                .json(&json!({"identifier": handle, "password": input(values, "password")?}))
        }
        "mastodon" => {
            let normalized = origin(input(values, "instance")?)?;
            let url = url::Url::parse(&normalized)?;
            verified_origin = Some(normalized);
            client
                .get(
                    url.join("/api/v1/accounts/verify_credentials")
                        .map_err(|_| anyhow::anyhow!("invalid instance URL"))?,
                )
                .bearer_auth(input(values, "token")?)
        }
        "linkedin" => client
            .get("https://api.linkedin.com/v2/userinfo")
            .bearer_auth(input(values, "token")?),
        "threads" => client
            .get("https://graph.threads.net/v1.0/me?fields=id,username")
            .bearer_auth(input(values, "token")?),
        "facebook-page" => client
            .get("https://graph.facebook.com/v21.0/me?fields=id,name,category")
            .bearer_auth(input(values, "token")?),
        _ => bail!("unsupported platform"),
    };
    let response = request
        .send()
        .map_err(|_| anyhow::anyhow!("provider request failed"))?;
    ensure!(
        response.status().is_success(),
        "provider rejected credentials (HTTP {})",
        response.status().as_u16()
    );
    let body: Value = response
        .json()
        .map_err(|_| anyhow::anyhow!("invalid provider response"))?;
    let mut identity = parse_identity(p, &body)?;
    if let Some(did) = expected_did {
        ensure!(
            identity.account_id == did,
            "session DID does not match resolved account"
        );
    }
    identity.origin = verified_origin;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_go_only_to_approved_pds_and_claimed_handles() {
        let hosted = "https://morel.us-east.host.bsky.network";
        assert!(pds_approved(hosted, None).unwrap());
        assert!(!pds_approved("https://evil.example", None).unwrap());
        assert!(pds_approved("https://pds.example", Some("https://pds.example/")).unwrap());
        assert!(!pds_approved("https://pds.example", Some("https://other.example")).unwrap());
        let doc = json!({"alsoKnownAs": ["at://Four.Example"]});
        assert!(claims_handle(&doc, "four.example"));
        assert!(!claims_handle(&doc, "five.example"));
        assert!(!claims_handle(&json!({}), "four.example"));
    }

    #[test]
    fn only_public_addresses_pass() {
        for ip in ["93.184.216.34", "2606:2800:220:1::1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn recorded_pds_and_page_responses() {
        let doc = json!({"id":"did:plc:abc", "service":[{"id":"#atproto_pds", "type":"AtprotoPersonalDataServer", "serviceEndpoint":"https://PDS.example:443/"}]});
        assert_eq!(
            discovered_pds("did:plc:abc", &doc).unwrap(),
            "https://pds.example"
        );
        // Another DID's document, or a service of the wrong type, names no PDS.
        assert!(discovered_pds("did:plc:other", &doc).is_err());
        let untyped = json!({"id":"did:plc:abc", "service":[{"id":"#atproto_pds", "serviceEndpoint":"https://pds.example"}]});
        assert!(discovered_pds("did:plc:abc", &untyped).is_err());
        assert!(
            parse_identity(
                platform("facebook-page").unwrap(),
                &json!({"id":"123","name":"User"})
            )
            .is_err()
        );
        assert_eq!(
            origin("https://EXAMPLE.com:443/").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            origin("https://EXAMPLE.com:8443/").unwrap(),
            "https://example.com:8443"
        );
        assert!(origin("https://example.com/path").is_err());
    }

    #[test]
    fn recorded_responses_and_rendering() {
        for (name, body, expected) in [
            (
                "bluesky",
                r#"{"did":"did:plc:abc","handle":"a.bsky.social"}"#,
                "did:plc:abc",
            ),
            ("mastodon", r#"{"id":"42","acct":"alice"}"#, "42"),
            (
                "linkedin",
                r#"{"sub":"abc","name":"Alice"}"#,
                "urn:li:person:abc",
            ),
            ("threads", r#"{"id":"123","username":"alice"}"#, "123"),
            (
                "facebook-page",
                r#"{"id":"456","name":"Page","category":"Community"}"#,
                "456",
            ),
        ] {
            let p = platform(name).unwrap();
            assert_eq!(
                parse_identity(p, &serde_json::from_str(body).unwrap())
                    .unwrap()
                    .account_id,
                expected
            );
            let values = [("handle", "alice"), ("password", "pw"), ("token", "tok")]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), Zeroizing::new(v.to_owned())))
                .collect();
            let rendered = render(p, &values).unwrap();
            assert_eq!(rendered.len(), p.credentials.len());
            if name == "facebook-page" {
                assert_eq!(rendered[1].as_str(), "OAuth tok");
            }
            if name == "bluesky" {
                assert_eq!(
                    serde_json::from_str::<Value>(&rendered[0]).unwrap()["body"]["password"],
                    "pw"
                );
            }
        }
        assert!(parse_identity(platform("threads").unwrap(), &json!({})).is_err());
    }
}
