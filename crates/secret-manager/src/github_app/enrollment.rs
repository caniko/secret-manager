use super::{
    EnrollArgs, Issued,
    api::{Api, Github},
    config::Config,
    installation_url, now, process, publish, settle,
};
use anyhow::{Context, Result, ensure};
use reqwest::Method;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) fn run(args: EnrollArgs) -> Result<()> {
    let (config, store, mut transaction) = args.common.load()?;
    let github = Github::new()?;
    if matches!(
        transaction.state.phase.as_str(),
        "exchange-started" | "capture-started"
    ) {
        // A crash between ciphertext fsync and metadata publication is
        // recoverable. A consumed code without ciphertext must not be replayed.
        let path = transaction.directory.join("issued.age");
        ensure!(
            path.exists(),
            "manifest conversion outcome is ambiguous and no encrypted response exists; recover the app's issued key with github app import in a fresh transaction"
        );
        let path = transaction.checked_checkpoint()?;
        let identities = store.resolve_identities(&args.common.identities)?;
        let plaintext = Zeroizing::new(crate::age::decrypt_with_identities(&path, &identities)?);
        let issued: Issued = serde_json::from_str(&plaintext)?;
        settle(&config, &mut transaction, &issued)?;
    }
    ensure!(
        matches!(
            transaction.state.phase.as_str(),
            "prepared" | "enrolled" | "published"
        ),
        "unsupported enrollment phase"
    );
    if transaction.state.phase == "prepared" {
        ensure!(
            now()?.saturating_sub(transaction.state.created_at) < 3600,
            "manifest transaction expired; start with a fresh transaction directory"
        );
        // Validate encryption and recipient/plugin availability BEFORE GitHub
        // issues a one-use response. No private key is generated locally.
        process::encrypt(&config, b"GitHub App encryption preflight")?;
    }
    if let Some(port) = transaction.state.callback_port {
        ensure!(
            args.port == 0 || args.port == port,
            "retry must use the original callback port"
        );
    }
    let listener = TcpListener::bind((
        "127.0.0.1",
        transaction.state.callback_port.unwrap_or(args.port),
    ))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    transaction.state.callback_port = Some(address.port());
    transaction.save()?;
    let base = format!("http://{address}");
    println!("Open the authenticated GitHub enrollment flow: {base}/");
    std::io::stdout().flush()?;
    let deadline = Instant::now() + Duration::from_secs(args.timeout_seconds);
    while Instant::now() < deadline {
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let target = match request(&mut stream, &address.to_string()) {
            Ok(target) => target,
            Err(_) => {
                respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    "Invalid local request.",
                    None,
                )?;
                continue;
            }
        };
        let url = url::Url::parse(&format!("{base}{}", target.as_str()))?;
        match url.path() {
            "/" => {
                if let Some(app) = &transaction.state.app {
                    respond(
                        &mut stream,
                        "302 Found",
                        "text/plain",
                        "Continue GitHub installation authorization.",
                        Some(&installation_url(app)),
                    )?;
                } else {
                    let owner: serde_json::Value = serde_json::from_slice(&github.request(
                        Method::GET,
                        &format!("/users/{}", config.owner),
                        None,
                        None,
                    )?)?;
                    ensure!(
                        owner["login"].as_str() == Some(config.owner.as_str()),
                        "GitHub owner identity mismatch"
                    );
                    let action = match owner["type"].as_str() {
                        Some("User") => "https://github.com/settings/apps/new".to_owned(),
                        Some("Organization") => format!(
                            "https://github.com/organizations/{}/settings/apps/new",
                            config.owner
                        ),
                        _ => anyhow::bail!("unsupported GitHub account type"),
                    };
                    let body = page(&config, &base, &action, &transaction.state.nonce)?;
                    respond(
                        &mut stream,
                        "200 OK",
                        "text/html; charset=utf-8",
                        &body,
                        None,
                    )?;
                }
            }
            "/callback" => {
                let result = (|| {
                    ensure!(
                        transaction.state.phase == "prepared",
                        "manifest callback already consumed"
                    );
                    ensure!(
                        now()?.saturating_sub(transaction.state.created_at) < 3600,
                        "manifest transaction expired"
                    );
                    let code = callback_code(&url, &transaction.state.nonce)?;
                    transaction.state.phase = "exchange-started".into();
                    transaction.save()?;
                    let bytes = github.request(
                        Method::POST,
                        &format!("/app-manifests/{}/conversions", code.as_str()),
                        None,
                        None,
                    )?;
                    // Retain ALL issued secrets encrypted before parsing or
                    // policy validation. Never print the conversion response.
                    transaction.checkpoint(&process::encrypt(&config, &bytes)?)?;
                    let issued: Issued = serde_json::from_slice(&bytes)?;
                    settle(&config, &mut transaction, &issued)?;
                    Ok(issued.app)
                })();
                match result {
                    Ok(app) => respond(
                        &mut stream,
                        "302 Found",
                        "text/plain",
                        "App enrolled. Authorize its selected-repository installation.",
                        Some(&installation_url(&app)),
                    )?,
                    Err(error) => {
                        respond(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain",
                            "Enrollment stopped. Consult the CLI; its encrypted transaction is retained.",
                            None,
                        )?;
                        return Err(error);
                    }
                }
            }
            "/installed" => {
                let result = (|| {
                    callback_state(&url, &transaction.state.nonce)?;
                    let issued = args.common.issued(&store, &mut transaction)?;
                    publish(
                        &args.common,
                        &config,
                        &store,
                        &mut transaction,
                        &issued,
                        false,
                    )
                })();
                match result {
                    Ok(()) => {
                        respond(
                            &mut stream,
                            "200 OK",
                            "text/plain",
                            "Issued key encrypted and Actions slots published. Run the trusted PR review workflow to qualify destination use.",
                            None,
                        )?;
                        return Ok(());
                    }
                    Err(error) => {
                        respond(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain",
                            "Installation/publication stopped. The CLI retains the encrypted transaction for retry.",
                            None,
                        )?;
                        return Err(error);
                    }
                }
            }
            _ => respond(
                &mut stream,
                "404 Not Found",
                "text/plain",
                "Not found.",
                None,
            )?,
        }
    }
    anyhow::bail!(
        "enrollment timed out; encrypted transaction retained; retry enroll or publish with the same policy and transaction"
    )
}

fn request(stream: &mut TcpStream, host: &str) -> Result<Zeroizing<String>> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = [0; 1024];
    while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk)?;
        ensure!(n > 0, "incomplete local request");
        bytes.extend_from_slice(&chunk[..n]);
        ensure!(bytes.len() <= 8192, "local request exceeds limit");
    }
    let text = std::str::from_utf8(&bytes)?;
    let mut lines = text.split("\r\n");
    let mut fields = lines
        .next()
        .context("missing request line")?
        .split_whitespace();
    ensure!(fields.next() == Some("GET"), "only GET is accepted");
    let target = fields.next().context("missing request target")?;
    ensure!(
        target.starts_with('/')
            && !target.starts_with("//")
            && fields.next() == Some("HTTP/1.1")
            && fields.next().is_none(),
        "invalid request target"
    );
    let hosts: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .collect();
    ensure!(
        hosts.len() == 1 && hosts[0].1.trim() == host,
        "local request Host does not match listener"
    );
    Ok(Zeroizing::new(target.to_owned()))
}

fn callback_state(url: &url::Url, expected: &str) -> Result<()> {
    let values: Vec<_> = url.query_pairs().filter(|(k, _)| k == "state").collect();
    ensure!(
        values.len() == 1 && values[0].1 == expected,
        "GitHub callback state mismatch"
    );
    Ok(())
}

fn callback_code(url: &url::Url, expected: &str) -> Result<Zeroizing<String>> {
    callback_state(url, expected)?;
    let values: Vec<_> = url.query_pairs().filter(|(k, _)| k == "code").collect();
    ensure!(
        values.len() == 1
            && (20..=128).contains(&values[0].1.len())
            && values[0].1.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invalid manifest conversion code"
    );
    Ok(Zeroizing::new(values[0].1.to_string()))
}

fn page(config: &Config, base: &str, action: &str, nonce: &str) -> Result<String> {
    let mut manifest = config.manifest(&format!("{base}/callback"));
    manifest["setup_url"] = serde_json::json!(format!("{base}/installed?state={nonce}"));
    Ok(format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>GitHub App enrollment</title><h1>Enroll {}</h1><p>Owner: {}. Select only {} during installation.</p><form method=\"post\" action=\"{}?state={}\"><input type=\"hidden\" name=\"manifest\" value=\"{}\"><button type=\"submit\">Register and install on GitHub</button></form></html>",
        html(&config.slug),
        html(&config.owner),
        html(&config.repository),
        html(action),
        html(nonce),
        html(&serde_json::to_string(&manifest)?)
    ))
}

fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    kind: &str,
    body: &str,
    redirect: Option<&str>,
) -> Result<()> {
    let location = redirect
        .map(|url| format!("Location: {url}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; form-action https://github.com; frame-ancestors 'none'\r\n{location}Connection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callbacks_refuse_wrong_or_duplicate_state_and_codes() {
        for query in [
            "state=wrong&code=12345678901234567890",
            "state=expected&state=expected&code=12345678901234567890",
            "state=expected&code=short",
            "state=expected&code=12345678901234567890&code=12345678901234567890",
        ] {
            assert!(
                callback_code(
                    &url::Url::parse(&format!("http://127.0.0.1/callback?{query}")).unwrap(),
                    "expected"
                )
                .is_err()
            );
        }
        assert_eq!(
            callback_code(
                &url::Url::parse(
                    "http://127.0.0.1/callback?state=expected&code=12345678901234567890"
                )
                .unwrap(),
                "expected"
            )
            .unwrap()
            .as_str(),
            "12345678901234567890"
        );
    }
}
