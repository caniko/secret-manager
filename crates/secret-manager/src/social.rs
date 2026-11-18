//! Social publishing credentials and identity verification.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use zeroize::Zeroizing;

/// An input field required for enrollment.
pub struct Input {
    pub name: &'static str,
    pub secret: bool,
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
}];
const BLUESKY: &[Input] = &[
    Input {
        name: "handle",
        secret: false,
    },
    Input {
        name: "password",
        secret: true,
    },
    Input {
        name: "pds",
        secret: false,
    },
];
const MASTODON: &[Input] = &[
    Input {
        name: "instance",
        secret: false,
    },
    Input {
        name: "token",
        secret: true,
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

fn check_pds(did: &str, pds: &str, doc: &Value) -> Result<()> {
    ensure!(
        doc.get("id").and_then(Value::as_str) == Some(did),
        "DID document identity mismatch"
    );
    let endpoint = doc
        .get("service")
        .and_then(Value::as_array)
        .and_then(|services| {
            services.iter().find(|s| {
                s.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id == "#atproto_pds" || id == format!("{did}#atproto_pds"))
            })
        })
        .and_then(|s| s.get("serviceEndpoint"))
        .and_then(Value::as_str)
        .context("DID document missing PDS")?;
    ensure!(
        origin(endpoint)? == pds,
        "account PDS does not match requested origin"
    );
    Ok(())
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
            let pds = origin(
                values
                    .get("pds")
                    .map_or("https://bsky.social", |v| v.as_str()),
            )?;
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
            let doc = response_json(
                client
                    .get(did_url(&did)?)
                    .send()
                    .map_err(|_| anyhow::anyhow!("DID resolution failed"))?,
            )?;
            check_pds(&did, &pds, &doc)?;
            expected_did = Some(did);
            verified_origin = Some(pds.clone());
            client
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
    fn recorded_pds_and_page_responses() {
        let doc = json!({"id":"did:plc:abc", "service":[{"id":"#atproto_pds", "serviceEndpoint":"https://PDS.example:443/"}]});
        assert!(check_pds("did:plc:abc", "https://pds.example", &doc).is_ok());
        assert!(check_pds("did:plc:abc", "https://other.example", &doc).is_err());
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
