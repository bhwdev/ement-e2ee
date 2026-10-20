use anyhow::Context;
use clap::Subcommand;

use crate::CtlArgs;
use crate::admin::{debug, verify};
use crate::config::AdminEndpoint;

#[derive(Subcommand)]
pub enum CtlCommand {
    /// Show proxy status: sessions, cross-signing, backup.
    Status,
    /// Join the existing encrypted identity: decrypt cross-signing + backup
    /// secrets with your recovery key, self-sign this device, and restore
    /// room keys from the server-side backup.
    Bootstrap {
        /// Act on this user's session (needed only with multiple accounts).
        #[arg(long)]
        user_id: Option<String>,
        /// Read the recovery key from a file instead of prompting.
        #[arg(long)]
        recovery_key_file: Option<std::path::PathBuf>,
    },
    /// Emoji-verify this device against another one. Without a subcommand
    /// this walks the whole flow and only asks whether the emoji match; the
    /// subcommands perform single steps, for scripting. ement must stay
    /// connected meanwhile: verification messages travel in its syncs.
    Verify(VerifyArgs),
    /// Export/import room keys as a passphrase-protected file (Element-compatible).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Find out what is wrong: health checks with remedies, and a closer
    /// look at a session, a room, an event, the devices or the logs.
    Debug(debug::DebugArgs),
}

#[derive(Subcommand)]
pub enum KeysAction {
    /// Export all room keys to FILE.
    Export {
        file: std::path::PathBuf,
        #[arg(long)]
        user_id: Option<String>,
    },
    /// Import room keys from FILE.
    Import {
        file: std::path::PathBuf,
        #[arg(long)]
        user_id: Option<String>,
    },
}

#[derive(clap::Args)]
pub struct VerifyCommon {
    /// Act on this user's session (needed only with multiple accounts).
    #[arg(long)]
    user_id: Option<String>,
    /// The other user of the verification (defaults to your own user, i.e.
    /// verifying one of your own devices).
    #[arg(long)]
    with_user: Option<String>,
}

#[derive(clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct VerifyArgs {
    /// Start the verification with this device of yours (its ID is shown in
    /// Element under Settings > Sessions). Without it, wait for a request
    /// started on the other device.
    #[arg(long)]
    device: Option<String>,
    #[command(flatten)]
    common: VerifyCommon,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 300)]
    timeout: u64,
    #[command(subcommand)]
    action: Option<VerifyAction>,
}

#[derive(Subcommand)]
pub enum VerifyAction {
    /// List verification flows.
    List {
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Request verification of one of your own devices (e.g. Element).
    Start {
        /// The device ID to verify with (see Element: Settings > Sessions).
        device: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Show a flow's state, including the emoji once SAS is running.
    Show {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Accept an incoming verification request.
    Accept {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Transition an accepted flow into emoji (SAS) verification.
    StartSas {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Accept a SAS the other side started.
    SasAccept {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Confirm that the emoji match.
    Confirm {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
    /// Cancel a flow.
    Cancel {
        flow: String,
        #[command(flatten)]
        common: VerifyCommon,
    },
}

pub async fn run(args: CtlArgs) -> anyhow::Result<()> {
    let endpoint = AdminEndpoint::load(args.config.as_deref(), args.proxy.as_deref())?;
    let client = Client::new(&endpoint.url, endpoint.admin_token);
    run_command(&client, args.command).await
}

pub async fn run_command(client: &Client, command: CtlCommand) -> anyhow::Result<()> {
    match command {
        CtlCommand::Status => {
            let resp = client.get("status").await?;
            println!("{}", terminal_safe(&serde_json::to_string_pretty(&resp)?));
        }
        CtlCommand::Bootstrap {
            user_id,
            recovery_key_file,
        } => {
            let recovery_key = match recovery_key_file {
                Some(path) => std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?
                    .trim()
                    .to_owned(),
                None => rpassword::prompt_password("Recovery key (or passphrase): ")
                    .context("failed to read recovery key")?,
            };
            let mut body = serde_json::json!({ "recovery_key": recovery_key });
            if let Some(user_id) = user_id {
                body["user_id"] = user_id.into();
            }
            let resp = client.post("bootstrap", &body).await?;
            println!("{}", terminal_safe(&serde_json::to_string_pretty(&resp)?));
        }
        CtlCommand::Verify(VerifyArgs {
            action: Some(action),
            ..
        }) => run_verify(client, action).await?,
        CtlCommand::Verify(args) => {
            let options = verify::Options {
                device: args.device,
                user_id: args.common.user_id,
                with_user: args.common.with_user,
                timeout: std::time::Duration::from_secs(args.timeout),
                poll: std::time::Duration::from_millis(500),
            };
            let flow = verify::run(client, &mut verify::TerminalUi, &options).await?;
            let other = flow["other_device"].as_str().unwrap_or("the other device");
            let other = terminal_safe(other);
            println!("\n✓ Verified: this device and {other} now trust each other.");
        }
        CtlCommand::Keys { action } => run_keys(client, action).await?,
        CtlCommand::Debug(args) => debug::run(client, args).await?,
    }
    Ok(())
}

async fn run_keys(client: &Client, action: KeysAction) -> anyhow::Result<()> {
    match action {
        KeysAction::Export { file, user_id } => {
            let passphrase = rpassword::prompt_password("Passphrase to protect the export: ")?;
            let mut body = serde_json::json!({ "passphrase": passphrase });
            if let Some(user_id) = user_id {
                body["user_id"] = user_id.into();
            }
            let resp = client.post("keys/export", &body).await?;
            let export = resp
                .get("export")
                .and_then(|v| v.as_str())
                .context("malformed export response")?;
            crate::secret::write_private(&file, export.as_bytes())?;
            println!(
                "Exported {} room keys to {}",
                resp.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
                file.display()
            );
        }
        KeysAction::Import { file, user_id } => {
            let data = std::fs::read_to_string(&file)
                .with_context(|| format!("failed to read {}", file.display()))?;
            let passphrase = rpassword::prompt_password("Export passphrase: ")?;
            let mut body = serde_json::json!({ "passphrase": passphrase, "data": data });
            if let Some(user_id) = user_id {
                body["user_id"] = user_id.into();
            }
            let resp = client.post("keys/import", &body).await?;
            println!("{}", terminal_safe(&serde_json::to_string_pretty(&resp)?));
        }
    }
    Ok(())
}

fn common_body(common: &VerifyCommon) -> serde_json::Value {
    let mut body = serde_json::json!({});
    if let Some(user_id) = &common.user_id {
        body["user_id"] = user_id.clone().into();
    }
    if let Some(with_user) = &common.with_user {
        body["with_user"] = with_user.clone().into();
    }
    body
}

fn common_query(common: &VerifyCommon) -> String {
    let mut parts = Vec::new();
    if let Some(user_id) = &common.user_id {
        parts.push(format!("user_id={user_id}"));
    }
    if let Some(with_user) = &common.with_user {
        parts.push(format!("with_user={with_user}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

fn print_flow(value: &serde_json::Value) {
    // Emoji first and prominently, if present.
    if let Some(formatted) = value
        .pointer("/sas/emoji/formatted")
        .and_then(|v| v.as_str())
    {
        println!("\nCompare these emoji with the other device:\n");
        println!("{}\n", terminal_safe(formatted));
    }
    println!(
        "{}",
        terminal_safe(&serde_json::to_string_pretty(value).unwrap_or_default())
    );
}

/// `text` with the control characters a terminal would act on (escape
/// sequences that move the cursor, retitle the window, set the clipboard)
/// replaced: what the proxy answers carries strings other people chose,
/// such as device names, log lines and event fields.
pub fn terminal_safe(text: &str) -> std::borrow::Cow<'_, str> {
    let acted_on = |c: char| c.is_control() && c != '\n' && c != '\t';
    if !text.chars().any(acted_on) {
        return std::borrow::Cow::Borrowed(text);
    }
    text.chars()
        .map(|c| {
            if acted_on(c) {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
}

async fn run_verify(client: &Client, action: VerifyAction) -> anyhow::Result<()> {
    match action {
        VerifyAction::List { common } => {
            let resp = client
                .get(&format!("verify{}", common_query(&common)))
                .await?;
            println!("{}", terminal_safe(&serde_json::to_string_pretty(&resp)?));
        }
        VerifyAction::Start { device, common } => {
            let mut body = common_body(&common);
            body["device_id"] = device.into();
            let resp = client.post("verify/start", &body).await?;
            print_flow(&resp);
            println!("\nNow accept the request on the other device, then run:");
            if let Some(flow) = resp.get("flow_id").and_then(|v| v.as_str()) {
                println!("  ement-e2ee ctl verify show {}", terminal_safe(flow));
            }
        }
        VerifyAction::Show { flow, common } => {
            let resp = client
                .get(&format!("verify/{flow}{}", common_query(&common)))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::Accept { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/accept"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::StartSas { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/start-sas"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::SasAccept { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/sas-accept"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::Confirm { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/confirm"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
        VerifyAction::Cancel { flow, common } => {
            let resp = client
                .post(&format!("verify/{flow}/cancel"), &common_body(&common))
                .await?;
            print_flow(&resp);
        }
    }
    Ok(())
}

/// Minimal HTTP client for the admin API.
pub struct Client {
    base: String,
    http: reqwest::Client,
    admin_token: Option<String>,
    connect_timeout: std::time::Duration,
}

/// How long to wait for the proxy to accept a connection. A proxy on
/// loopback accepts at once; but where nothing listens, connecting may hang
/// rather than fail (WSL2's mirrored networking does that), for as long as
/// the kernel keeps trying. Requests themselves get no limit: a bootstrap
/// that restores a large key backup takes its time.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl Client {
    pub fn new(proxy: &str, admin_token: Option<String>) -> Self {
        Self::with_connect_timeout(proxy, admin_token, CONNECT_TIMEOUT)
    }

    fn with_connect_timeout(
        proxy: &str,
        admin_token: Option<String>,
        connect_timeout: std::time::Duration,
    ) -> Self {
        Self {
            base: format!("{}/_ement", proxy.trim_end_matches('/')),
            http: reqwest::Client::builder()
                .connect_timeout(connect_timeout)
                // The proxy is local, and what goes to it (the admin token,
                // a recovery key) is not for an HTTP proxy that HTTP_PROXY
                // or ALL_PROXY may name.
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("failed to set up the HTTP client"),
            admin_token,
            connect_timeout,
        }
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> anyhow::Result<serde_json::Value> {
        let request = match &self.admin_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        let proxy = self.base.trim_end_matches("/_ement");
        let resp = request.send().await.map_err(|e| {
            if e.is_connect() && e.is_timeout() {
                anyhow::anyhow!(
                    "could not reach the proxy at {proxy}: no connection within {:?} \
                     (is `ement-e2ee serve` running, and listening there?)",
                    self.connect_timeout
                )
            } else {
                anyhow::Error::new(e).context(format!(
                    "could not reach the proxy at {proxy} (is `ement-e2ee serve` running?)"
                ))
            }
        })?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            let message = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            if status == reqwest::StatusCode::UNAUTHORIZED {
                anyhow::bail!(
                    "{status}: {message} (ctl takes the token from the config file's \
                     `admin_token`, or else from the store directory it names; pass --config \
                     if the proxy uses a different one)"
                );
            }
            anyhow::bail!("{status}: {message}");
        }
        Ok(body)
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        self.send(self.http.get(format!("{}/{path}", self.base)))
            .await
    }

    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        self.send(self.http.post(format!("{}/{path}", self.base)).json(body))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common(user_id: Option<&str>, with_user: Option<&str>) -> VerifyCommon {
        VerifyCommon {
            user_id: user_id.map(ToOwned::to_owned),
            with_user: with_user.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn verify_targets_are_sent_only_when_given() {
        let nothing = common(None, None);
        assert_eq!(common_query(&nothing), "");
        assert_eq!(common_body(&nothing), serde_json::json!({}));

        let both = common(Some("@me:example.org"), Some("@you:example.org"));
        assert_eq!(
            common_query(&both),
            "?user_id=@me:example.org&with_user=@you:example.org"
        );
        assert_eq!(
            common_body(&both),
            serde_json::json!({ "user_id": "@me:example.org", "with_user": "@you:example.org" })
        );

        let other_user_only = common(None, Some("@you:example.org"));
        assert_eq!(
            common_query(&other_user_only),
            "?with_user=@you:example.org"
        );
        assert_eq!(
            common_body(&other_user_only),
            serde_json::json!({ "with_user": "@you:example.org" })
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn connecting_gives_up_in_time_and_says_so() {
        // A listener whose accept queue is full: Linux drops further
        // connection attempts, which then hang, like those to a port that
        // WSL2's mirrored networking leaves unanswered.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(0).unwrap();
        let address = listener.local_addr().unwrap();
        let mut held = Vec::new();
        while let Ok(stream) =
            std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(200))
        {
            held.push(stream);
            assert!(held.len() < 100, "the accept queue never filled");
        }

        let timeout = std::time::Duration::from_millis(300);
        let client = Client::with_connect_timeout(&format!("http://{address}"), None, timeout);
        let started = std::time::Instant::now();
        let error = format!("{:#}", client.get("status").await.unwrap_err());
        assert!(
            error.contains(&format!(
                "could not reach the proxy at http://{address}: no connection within 300ms"
            )),
            "{error}"
        );
        assert!(error.contains("ement-e2ee serve"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        drop(listener);
    }

    #[test]
    fn terminal_controls_are_defused() {
        assert_eq!(terminal_safe("plain\ttext\nlines"), "plain\ttext\nlines");
        assert!(matches!(
            terminal_safe("Pixel 8"),
            std::borrow::Cow::Borrowed(_)
        ));
        // An OSC 52 clipboard write, a CSI cursor move (7- and 8-bit), DEL.
        assert_eq!(
            terminal_safe("a\u{1b}]52;c;cm0gLXJm\u{7}b\u{1b}[2Jc\u{9b}2Jd\u{7f}"),
            "a�]52;c;cm0gLXJm�b�[2Jc�2Jd�"
        );
    }

    #[test]
    fn client_base_url_tolerates_trailing_slash() {
        for proxy in ["http://127.0.0.1:8009", "http://127.0.0.1:8009/"] {
            assert_eq!(
                Client::new(proxy, None).base,
                "http://127.0.0.1:8009/_ement"
            );
        }
    }
}
