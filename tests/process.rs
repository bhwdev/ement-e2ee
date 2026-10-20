//! Process-level tests: the real binary, its command line, exit codes and
//! signals. (Everything that needs a homeserver is tested in-crate, in
//! `src/e2e_tests.rs`.)

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ement-e2ee");

/// A port nothing listens on (released just now): for a proxy to bind.
/// Until it does, another test may draw the same port.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running `ement-e2ee serve` with its own config and store.
struct Proxy {
    child: Child,
    config: PathBuf,
    port: u16,
    dir: tempfile::TempDir,
}

/// A config file for a proxy on `port` with its store in `store_dir`.
fn write_config(path: &Path, port: u16, homeserver: &str, store_dir: &Path, extra: &str) {
    std::fs::write(
        path,
        format!(
            "listen = \"127.0.0.1:{port}\"\nhomeserver = \"{homeserver}\"\nstore_dir = \"{}\"\n{extra}\n",
            store_dir.display()
        ),
    )
    .unwrap();
}

/// A port where connections are refused, until the tests end: bound, so
/// no other test can take it, but not listening.
fn closed_port() -> u16 {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket
        .bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    let port = socket.local_addr().unwrap().as_socket().unwrap().port();
    std::mem::forget(socket);
    port
}

/// A homeserver URL where nothing answers.
fn offline_homeserver() -> String {
    format!("http://127.0.0.1:{}", closed_port())
}

/// Run `serve --config CONFIG`, expecting it to give up by itself;
/// returns its exit status and standard error.
fn serve_until_exit(config: &Path) -> (std::process::ExitStatus, String) {
    let mut child = Command::new(BIN)
        .args(["serve", "--config"])
        .arg(config)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("serve did not give up");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut error = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    (status, error)
}

/// GET `path` from 127.0.0.1:`port`; returns the status code and body.
fn http_get(port: u16, path: &str) -> (u16, String) {
    try_http_get(port, path).unwrap_or_else(|e| panic!("GET {path} on port {port}: {e}"))
}

/// `http_get`, for a port where anything, or nothing, may answer.
fn try_http_get(port: u16, path: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("not an HTTP response: {response}")))?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// Wait until `child` serves on `port` (true) or exits (false). An open
/// port does not tell: `free_port` only found it free, and until `child`
/// binds it a concurrent test may draw the same port and start its proxy
/// there. So wait for the version route to give `child`'s pid.
fn wait_until_serving(child: &mut Child, port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        if let Ok((200, body)) = try_http_get(port, "/_ement/version") {
            let version: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            if version["pid"] == child.id() {
                return true;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the proxy did not start listening"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl Proxy {
    /// Start with `homeserver` (a URL) and any further config lines.
    fn start(homeserver: &str, extra_config: &str) -> Self {
        Self::start_with(homeserver, extra_config, &[])
    }

    /// Start with extra `serve` arguments too. Its standard input is a pipe
    /// the test holds, like Emacs does.
    fn start_with(homeserver: &str, extra_config: &str, serve_args: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        // Another port if a concurrent test's proxy got this one first.
        for _ in 0..5 {
            let port = free_port();
            write_config(
                &config,
                port,
                homeserver,
                &dir.path().join("store"),
                extra_config,
            );
            let mut child = Command::new(BIN)
                .args(["serve", "--config"])
                .arg(&config)
                .args(serve_args)
                .env_remove("RUST_LOG")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            if wait_until_serving(&mut child, port) {
                return Self {
                    child,
                    config,
                    port,
                    dir,
                };
            }
            let mut error = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut error)
                .unwrap();
            assert!(
                error.contains("failed to bind"),
                "the proxy did not start: {error}"
            );
        }
        panic!("the proxy found no free port");
    }

    /// Start with a homeserver URL where nothing answers.
    fn start_offline(extra_config: &str) -> Self {
        Self::start(&offline_homeserver(), extra_config)
    }

    /// Run `ement-e2ee ctl --config <this proxy's config> ARGS...`.
    fn ctl(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(["ctl", "--config"])
            .arg(&self.config)
            .args(args)
            .output()
            .unwrap()
    }

    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([signal, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Wait for the process to exit; returns (exit status, stdout).
    fn wait(mut self, limit: Duration) -> (std::process::ExitStatus, String) {
        let deadline = Instant::now() + limit;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the proxy did not exit within {limit:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stdout = String::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        (status, stdout)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn sigterm_stops_the_proxy_cleanly() {
    // How ement-e2ee.el stops it.
    let proxy = Proxy::start_offline("");
    proxy.signal("-TERM");
    let (status, log) = proxy.wait(Duration::from_secs(10));
    assert!(status.success(), "exit status: {status:?}\n{log}");
    assert!(log.contains("terminated; shutting down"), "{log}");
}

#[test]
fn sigint_stops_the_proxy_cleanly() {
    let proxy = Proxy::start_offline("");
    proxy.signal("-INT");
    let (status, log) = proxy.wait(Duration::from_secs(10));
    assert!(status.success(), "exit status: {status:?}\n{log}");
    assert!(log.contains("interrupted; shutting down"), "{log}");
}

#[test]
fn sighup_stops_the_proxy_cleanly() {
    // What Emacs sends its subprocesses when it exits.
    let proxy = Proxy::start_offline("");
    proxy.signal("-HUP");
    let (status, log) = proxy.wait(Duration::from_secs(10));
    assert!(status.success(), "exit status: {status:?}\n{log}");
    assert!(log.contains("hung up; shutting down"), "{log}");
}

#[test]
fn closing_stdin_stops_the_proxy() {
    // Emacs gone without a signal (SIGKILL, a crash): its end of the pipe
    // closes all the same.
    let mut proxy = Proxy::start_with(&offline_homeserver(), "", &["--exit-on-stdin-close"]);
    // Writing to it changes nothing.
    let mut stdin = proxy.child.stdin.take().unwrap();
    stdin.write_all(b"anything\n").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(proxy.child.try_wait().unwrap().is_none(), "exited early");
    drop(stdin);
    let (status, log) = proxy.wait(Duration::from_secs(10));
    assert!(status.success(), "exit status: {status:?}\n{log}");
    assert!(
        log.contains("standard input closed; shutting down"),
        "{log}"
    );
}

#[test]
fn closing_stdin_means_nothing_without_the_flag() {
    let mut proxy = Proxy::start_offline("");
    drop(proxy.child.stdin.take());
    std::thread::sleep(Duration::from_millis(500));
    assert!(proxy.child.try_wait().unwrap().is_none(), "exited");
    proxy.signal("-TERM");
    let (status, _) = proxy.wait(Duration::from_secs(10));
    assert!(status.success());
}

#[test]
fn second_proxy_on_the_same_store_is_refused() {
    let proxy = Proxy::start_offline("");
    // Another port, the same store directory.
    let port = free_port();
    let config = proxy.dir.path().join("second.toml");
    write_config(
        &config,
        port,
        &offline_homeserver(),
        &proxy.dir.path().join("store"),
        "",
    );
    let (status, error) = serve_until_exit(&config);
    assert!(!status.success());
    assert!(
        error.contains(&format!(
            "in use by another ement-e2ee (pid {})",
            proxy.child.id()
        )),
        "{error}"
    );
    // The first one is unharmed.
    assert_eq!(http_get(proxy.port, "/_ement/version").0, 200);
}

#[test]
fn newer_store_marker_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join(".version"), "999.0.0\n").unwrap();
    let port = free_port();
    let config = dir.path().join("config.toml");
    write_config(&config, port, &offline_homeserver(), &store, "");
    let (status, error) = serve_until_exit(&config);
    assert!(!status.success());
    assert!(
        error.contains(&format!(
            "store was last used by ement-e2ee 999.0.0, newer than this {}",
            env!("CARGO_PKG_VERSION")
        )),
        "{error}"
    );
    // An older marker is raised to this version.
    std::fs::write(store.join(".version"), "0.0.1\n").unwrap();
    let marker = {
        let mut child = Command::new(BIN)
            .args(["serve", "--config"])
            .arg(&config)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        // It raises the marker before it binds: even if a concurrent test
        // has taken the port, the marker is there once it serves or exits.
        wait_until_serving(&mut child, port);
        let marker = std::fs::read_to_string(store.join(".version")).unwrap();
        let _ = child.kill();
        let _ = child.wait();
        marker
    };
    assert_eq!(marker.trim(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn newer_crypto_store_schema_refuses_to_start() {
    // A store a newer matrix-sdk-sqlite has migrated, from before the
    // version marker existed: only its own schema version tells.
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let device = store.join("@me:example.org/DEVICE");
    std::fs::create_dir_all(&device).unwrap();
    let database = rusqlite::Connection::open(device.join("matrix-sdk-crypto.sqlite3")).unwrap();
    database
        .execute_batch(
            "CREATE TABLE kv (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL);
             INSERT INTO kv VALUES ('version', x'63');",
        )
        .unwrap();
    drop(database);
    let port = free_port();
    let config = dir.path().join("config.toml");
    write_config(&config, port, &offline_homeserver(), &store, "");
    let (status, error) = serve_until_exit(&config);
    assert!(!status.success());
    assert!(
        error.contains("has schema version 99, newer than"),
        "{error}"
    );
    assert!(error.contains("@me:example.org/DEVICE"), "{error}");
}

#[test]
fn version_route_needs_no_token() {
    let proxy = Proxy::start_offline("admin_token = \"s3cret\"");
    let (status, body) = http_get(proxy.port, "/_ement/version");
    assert_eq!(status, 200, "{body}");
    let version: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(version["name"], "ement-e2ee");
    assert_eq!(version["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(version["pid"], proxy.child.id());
    // Everything else still needs the token.
    assert_eq!(http_get(proxy.port, "/_ement/status").0, 401);
}

#[test]
fn info_json_reports_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let ran = dir.path().join("ran");
    let config = dir.path().join("config.toml");
    write_config(
        &config,
        9125,
        "https://matrix.example.org",
        &dir.path().join("store"),
        &format!("store_passphrase_command = \"touch {}\"", ran.display()),
    );
    let info = |config: &Path| {
        let output = Command::new(BIN)
            .args(["info", "--json", "--config"])
            .arg(config)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        serde_json::from_str::<serde_json::Value>(&stdout(&output)).unwrap()
    };
    let json = info(&config);
    assert!(!ran.exists(), "info ran the passphrase command");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["config_file"], config.to_str().unwrap());
    assert_eq!(json["config_exists"], true);
    assert_eq!(json["listen"], "127.0.0.1:9125");
    assert_eq!(json["url"], "http://127.0.0.1:9125");
    assert_eq!(json["homeserver"], "https://matrix.example.org");
    assert_eq!(
        json["store_dir"],
        dir.path().join("store").to_str().unwrap()
    );

    // No config yet: what setup would start from.
    let json = info(&dir.path().join("missing.toml"));
    assert_eq!(json["config_exists"], false);
    assert_eq!(json["homeserver"], serde_json::Value::Null);
    assert_eq!(json["url"], "http://127.0.0.1:8009");

    // Without --json, for people.
    let output = Command::new(BIN)
        .args(["info", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let text = stdout(&output);
    assert!(
        text.contains("url         http://127.0.0.1:9125\n"),
        "{text}"
    );
    assert!(
        text.contains("homeserver  https://matrix.example.org\n"),
        "{text}"
    );
}

#[test]
fn shutdown_does_not_wait_for_hung_requests() {
    // A homeserver that accepts connections and never answers, like a
    // long-polling /sync with nothing to report.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let homeserver = format!("http://{}", silent.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for connection in silent.incoming() {
            held.push(connection);
        }
    });
    let proxy = Proxy::start(&homeserver, "");

    // A client request the proxy is still waiting on upstream for.
    let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).unwrap();
    client
        .write_all(b"GET /_matrix/client/versions HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let asked = Instant::now();
    proxy.signal("-TERM");
    let (status, log) = proxy.wait(Duration::from_secs(15));
    assert!(status.success(), "exit status: {status:?}\n{log}");
    assert!(log.contains("closing remaining connections"), "{log}");
    // It gave the request a moment, but not its whole long-poll.
    assert!(
        asked.elapsed() >= Duration::from_secs(2),
        "{:?}",
        asked.elapsed()
    );
    assert!(
        asked.elapsed() < Duration::from_secs(10),
        "{:?}",
        asked.elapsed()
    );
}

#[test]
fn ctl_finds_the_proxy_and_its_token_through_the_config() {
    let proxy = Proxy::start_offline("admin_token = \"s3cret\"");

    // No --proxy, no token on the command line: both come from the config.
    let output = proxy.ctl(&["status"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let status: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["sessions"], serde_json::json!([]));

    // A config without the token, or a store with it, is turned away, and
    // told why.
    let other_config = proxy.dir.path().join("no-token.toml");
    std::fs::write(
        &other_config,
        format!(
            "listen = \"127.0.0.1:{}\"\nhomeserver = \"http://127.0.0.1:1\"\nstore_dir = \"{}\"\n",
            proxy.port,
            proxy.dir.path().join("elsewhere").display()
        ),
    )
    .unwrap();
    let output = Command::new(BIN)
        .args(["ctl", "--config"])
        .arg(&other_config)
        .arg("status")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("401"), "{error}");
    assert!(error.contains("admin_token"), "{error}");
}

#[test]
fn without_a_configured_token_the_proxy_draws_one() {
    let proxy = Proxy::start_offline("");
    // The admin API is closed all the same ...
    assert_eq!(http_get(proxy.port, "/_ement/status").0, 401);
    // ... and ctl finds the token where the proxy wrote it.
    let output = proxy.ctl(&["status"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let store = proxy.dir.path().join("store");
    let token = std::fs::read_to_string(store.join(".admin-token")).unwrap();
    assert_eq!(token.trim().len(), 64);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store), 0o700);
        assert_eq!(mode(&store.join(".admin-token")), 0o600);
        // Everything else the proxy made is private too (umask).
        assert_eq!(mode(&store.join(".lock")), 0o600);
        assert_eq!(mode(&store.join(".version")), 0o600);
    }
}

#[test]
fn ctl_says_when_no_proxy_is_running() {
    let output = Command::new(BIN)
        .args([
            "ctl",
            "--proxy",
            &format!("http://127.0.0.1:{}", closed_port()),
            "status",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(error.contains("could not reach the proxy"), "{error}");
    assert!(error.contains("ement-e2ee serve"), "{error}");
}

#[test]
fn debug_commands_against_a_running_proxy() {
    let proxy = Proxy::start_offline("");

    // The homeserver is unreachable: `check` says so, with the remedy, and
    // exits non-zero so scripts notice.
    let output = proxy.ctl(&["debug", "check"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let report = stdout(&output);
    assert!(
        report.starts_with(&format!("ement-e2ee {} — up ", env!("CARGO_PKG_VERSION"))),
        "{report}"
    );
    assert!(report.contains("  ✗ homeserver "), "{report}");
    assert!(
        report.contains("→ check the network and the `homeserver` setting"),
        "{report}"
    );
    assert!(report.contains("  ! sessions "), "{report}");
    assert!(report.contains("1 failure"), "{report}");
    assert!(stderr(&output).contains("1 check(s) failed"));

    // --json gives the same findings to a program.
    let output = proxy.ctl(&["debug", "check", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["summary"]["fail"], 1);
    assert_eq!(json["proxy"][0]["id"], "homeserver");

    // The log level changes without a restart, and the in-memory tail has
    // both the start-up line and the change.
    let output = proxy.ctl(&["debug", "log-level", "ement_e2ee=debug"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("now logs at: ement_e2ee=debug"));
    let output = proxy.ctl(&["debug", "log-level", "ement_e2ee=loud"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("invalid log filter"),
        "{}",
        stderr(&output)
    );
    let output = proxy.ctl(&["debug", "logs"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let logs = stdout(&output);
    assert!(
        logs.contains("INFO  ement_e2ee: starting ement-e2ee"),
        "{logs}"
    );
    assert!(
        logs.contains("log filter changed filter=ement_e2ee=debug"),
        "{logs}"
    );
    let output = proxy.ctl(&["debug", "logs", "--level", "error"]);
    assert!(
        stdout(&output).starts_with("No log lines"),
        "{}",
        stdout(&output)
    );

    // Session-specific commands explain what is missing.
    let output = proxy.ctl(&["debug", "session"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no active sessions"),
        "{}",
        stderr(&output)
    );

    // The report is one JSON file.
    let path = proxy.dir.path().join("report.json");
    let output = proxy.ctl(&["debug", "report", "--output", path.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(report["check"]["summary"]["fail"], 1);
    assert!(report["logs"]["lines"].as_array().unwrap().len() >= 2);
}

#[test]
fn debug_log_level_takes_effect_on_stdout() {
    let proxy = Proxy::start_offline("log_level = \"warn\"");
    // Nothing at INFO reaches stdout at first ...
    assert!(proxy.ctl(&["status"]).status.success());
    assert!(
        proxy
            .ctl(&["debug", "log-level", "ement_e2ee=trace"])
            .status
            .success()
    );
    // ... but after the change, per-request tracing does.
    assert!(proxy.ctl(&["status"]).status.success());
    proxy.signal("-TERM");
    let (_, log) = proxy.wait(Duration::from_secs(10));
    assert!(!log.contains("starting ement-e2ee"), "{log}");
    assert!(log.contains("log filter changed"), "{log}");
    assert!(log.contains("TRACE"), "{log}");
}

#[test]
fn a_failing_passphrase_command_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "homeserver = \"https://matrix.example.org\"\nstore_passphrase_command = \"exit 7\"\n",
    )
    .unwrap();
    let output = Command::new(BIN)
        .args(["serve", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("store_passphrase_command failed"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn setup_writes_the_config_and_prints_the_snippet() {
    // Just enough of a homeserver for setup's sanity check.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let homeserver = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for connection in listener.incoming() {
            let mut connection = connection.unwrap();
            let mut request = [0u8; 2048];
            let _ = connection.read(&mut request);
            let body = r#"{"versions":["v1.11"]}"#;
            let _ = write!(
                connection,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ement-e2ee/config.toml");
    let output = Command::new(BIN)
        .args(["setup", "--user-id", "@ben:example.org"])
        .args([
            "--homeserver",
            &homeserver,
            "--listen",
            "127.0.0.1:9123",
            "--config",
        ])
        .arg(&config)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains(":user-id \"@ben:example.org\""), "{text}");
    assert!(
        text.contains(":uri-prefix \"http://127.0.0.1:9123\""),
        "{text}"
    );
    assert!(
        text.contains(&format!("serve --config {}", config.display())),
        "{text}"
    );
    assert!(text.contains("ement-e2ee ctl bootstrap"), "{text}");
    assert!(text.contains("M-x ement-e2ee-install"), "{text}");

    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains("listen = \"127.0.0.1:9123\""), "{written}");
    assert!(
        written.contains(&format!("homeserver = \"{homeserver}\"")),
        "{written}"
    );

    // Without a user ID or homeserver it has to ask, and says so if it cannot.
    let output = Command::new(BIN)
        .args(["setup", "--config"])
        .arg(dir.path().join("other.toml"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no answer"), "{}", stderr(&output));
}
