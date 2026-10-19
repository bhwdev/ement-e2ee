mod admin;
mod config;
mod crypto;
mod error;
mod logbuf;
mod proxy;
mod session;
mod setup;
mod store_guard;
mod upstream;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod testutil;

use std::io::IsTerminal as _;
use std::sync::Arc;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

use crate::config::Config;

#[derive(Parser)]
#[command(name = "ement-e2ee", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy (default when no subcommand is given).
    Serve(ServeArgs),
    /// Talk to a running proxy's admin API.
    Ctl(CtlArgs),
    /// First-time setup: find the homeserver, write the config, and print
    /// how to run the proxy and connect ement through it.
    Setup(setup::SetupArgs),
    /// Show where a proxy started with this config would listen and keep
    /// its stores, without starting one.
    Info(InfoArgs),
}

#[derive(Args, Default, Clone)]
pub struct ServeArgs {
    /// Path to config file (default: ~/.config/ement-e2ee/config.toml)
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Listen address, e.g. 127.0.0.1:8009
    #[arg(long)]
    listen: Option<std::net::SocketAddr>,
    /// Upstream homeserver URL, e.g. https://matrix.example.org
    #[arg(long)]
    homeserver: Option<String>,
    /// Directory for crypto stores (default: ~/.local/share/ement-e2ee)
    #[arg(long)]
    store_dir: Option<std::path::PathBuf>,
    /// Log filter, e.g. info or ement_e2ee=debug
    #[arg(long)]
    log_level: Option<String>,
    /// Shut down when standard input reaches end of file: run as the child
    /// of a process holding the other end of a pipe, the proxy then ends
    /// with its parent however that ends.
    #[arg(long)]
    exit_on_stdin_close: bool,
}

#[derive(Args)]
pub struct InfoArgs {
    /// Path to config file (default: ~/.config/ement-e2ee/config.toml)
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Print JSON, for programs.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct CtlArgs {
    /// Path to the proxy's config file (default:
    /// ~/.config/ement-e2ee/config.toml); its `listen` and `admin_token` tell
    /// ctl how to reach the proxy.
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Base URL of the running proxy, overriding the config's `listen`.
    #[arg(long)]
    proxy: Option<String>,
    #[command(subcommand)]
    command: admin::ctl::CtlCommand,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new().context("failed to start tokio runtime")?;
    match cli.command {
        Some(Command::Ctl(args)) => runtime.block_on(admin::ctl::run(args)),
        Some(Command::Setup(args)) => runtime.block_on(setup::run(args)),
        Some(Command::Info(args)) => info(&args),
        Some(Command::Serve(args)) => runtime.block_on(serve(args)),
        None => runtime.block_on(serve(cli.serve)),
    }
}

fn info(args: &InfoArgs) -> anyhow::Result<()> {
    let info = config::Info::load(args.config.as_deref())?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }
    let config_file = match &info.config_file {
        Some(path) if info.config_exists => path.display().to_string(),
        Some(path) => format!("{} (does not exist)", path.display()),
        None => "(none)".to_owned(),
    };
    println!("version     {}", info.version);
    println!("config      {config_file}");
    println!("listen      {}", info.listen);
    println!("url         {}", info.url);
    println!(
        "homeserver  {}",
        info.homeserver.as_deref().unwrap_or("(not set)")
    );
    println!("store_dir   {}", info.store_dir.display());
    Ok(())
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let config = Config::load(&args)?;
    // Before any store is opened or the port bound.
    let _store_guard = store_guard::claim(&config.store_dir)?;

    // Two sinks: stdout, filtered by the configured level (changeable at
    // runtime through `ctl debug log-level`), and an in-memory tail of the
    // notable lines for `ctl debug logs`. Stdout is written from a thread of
    // its own, dropping lines rather than stalling the proxy when whoever
    // reads it (Emacs) falls behind; the guard flushes it on the way out.
    let (stdout, _stdout_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .finish(std::io::stdout());
    let logs = Arc::new(logbuf::LogBuffer::default());
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.log_level.clone()));
    let (filter, filter_handle) = tracing_subscriber::reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(stdout)
                .with_ansi(std::io::stdout().is_terminal())
                .with_filter(filter),
        )
        .with(logs.layer())
        .init();
    let log_control: proxy::LogControl = Arc::new(move |directives: &str| {
        let filter = EnvFilter::try_new(directives).context("invalid log filter")?;
        filter_handle
            .reload(filter)
            .context("failed to apply the log filter")?;
        Ok(())
    });

    tracing::info!(listen = %config.listen, homeserver = %config.homeserver, "starting ement-e2ee");

    let mut state = proxy::AppState::new(Arc::new(config)).await?;
    state.logs = logs;
    state.log_control = Some(log_control);
    let listen = state.config.listen;
    let router = proxy::router(state);

    // Listening for signals before the port opens: whoever sees it open may
    // signal at once, and a signal without a handler kills the process.
    let shutdown = shutdown_signal(args.exit_on_stdin_close);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind {listen}"))?;

    // Stop accepting on a shutdown signal and let in-flight requests finish,
    // but not forever: ement's /sync long-polls would hold the process open
    // for up to their full timeout.
    let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        shutdown.await;
        let _ = signalled_tx.send(());
    });
    tokio::select! {
        result = server => result?,
        () = async {
            let _ = signalled_rx.await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => tracing::info!("closing remaining connections"),
    }
    Ok(())
}

/// How long in-flight requests get to finish after a shutdown signal.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Resolves on SIGINT (Ctrl-C), SIGTERM, SIGHUP (what Emacs sends its
/// subprocesses when it exits), or, with `watch_stdin`, end of file on
/// standard input. Everything is in place once this returns, before the
/// future is first polled.
fn shutdown_signal(watch_stdin: bool) -> impl Future<Output = ()> {
    #[cfg(unix)]
    let (interrupt, terminate, hangup) = {
        use tokio::signal::unix::SignalKind;
        (
            unix_signal(SignalKind::interrupt(), "SIGINT"),
            unix_signal(SignalKind::terminate(), "SIGTERM"),
            unix_signal(SignalKind::hangup(), "SIGHUP"),
        )
    };
    #[cfg(not(unix))]
    let (interrupt, terminate, hangup) = (
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
        std::future::pending::<()>(),
        std::future::pending::<()>(),
    );
    let stdin_eof = watch_stdin.then(stdin_closed);

    async move {
        let stdin_closed = async {
            match stdin_eof {
                Some(closed) => closed.await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = interrupt => tracing::info!("interrupted; shutting down"),
            () = terminate => tracing::info!("terminated; shutting down"),
            () = hangup => tracing::info!("hung up; shutting down"),
            () = stdin_closed => tracing::info!("standard input closed; shutting down"),
        }
    }
}

/// Handle `kind` from now on; the future resolves when it arrives, or
/// never if it cannot be handled.
#[cfg(unix)]
fn unix_signal(
    kind: tokio::signal::unix::SignalKind,
    name: &'static str,
) -> impl Future<Output = ()> {
    let signal = tokio::signal::unix::signal(kind);
    async move {
        match signal {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = ?e, "could not install {name} handler");
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Watch standard input from now on; the future resolves at end of file,
/// which for a pipe means that the process holding its other end is gone:
/// exited, crashed, killed.
fn stdin_closed() -> impl Future<Output = ()> {
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
    // A thread of its own, not tokio's blocking pool: the runtime waits for
    // those when it shuts down, and this read only ends with the parent.
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdin = std::io::stdin().lock();
        let mut buffer = [0u8; 256];
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) => break,
                // Whatever is written to it means nothing.
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = closed_tx.send(());
    });
    async move {
        let _ = closed_rx.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once(&"ement-e2ee").chain(args)).unwrap()
    }

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn serve_is_the_default_command() {
        let cli = parse(&["--homeserver", "https://matrix.org", "--log-level", "debug"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.serve.homeserver.as_deref(), Some("https://matrix.org"));
        assert_eq!(cli.serve.log_level.as_deref(), Some("debug"));

        assert!(!cli.serve.exit_on_stdin_close);

        let cli = parse(&[
            "serve",
            "--listen",
            "127.0.0.1:9000",
            "--store-dir",
            "/tmp/s",
        ]);
        let Some(Command::Serve(args)) = cli.command else {
            panic!("expected serve");
        };
        assert_eq!(args.listen, Some("127.0.0.1:9000".parse().unwrap()));
        assert_eq!(args.store_dir, Some("/tmp/s".into()));

        // How Emacs runs it.
        let cli = parse(&["serve", "--exit-on-stdin-close", "--config", "/tmp/c.toml"]);
        let Some(Command::Serve(args)) = cli.command else {
            panic!("expected serve");
        };
        assert!(args.exit_on_stdin_close);
        assert!(parse(&["--exit-on-stdin-close"]).serve.exit_on_stdin_close);
    }

    #[test]
    fn info_invocations_parse() {
        let Some(Command::Info(args)) = parse(&["info"]).command else {
            panic!("expected info");
        };
        assert!(!args.json);
        assert_eq!(args.config, None);
        let Some(Command::Info(args)) =
            parse(&["info", "--config", "/tmp/c.toml", "--json"]).command
        else {
            panic!("expected info");
        };
        assert!(args.json);
        assert_eq!(args.config, Some("/tmp/c.toml".into()));
    }

    #[test]
    fn readme_ctl_invocations_parse() {
        for args in [
            &["ctl", "status"][..],
            &["ctl", "bootstrap"],
            &["ctl", "bootstrap", "--recovery-key-file", "key.txt"],
            &["ctl", "bootstrap", "--user-id", "@me:example.org"],
            &["ctl", "verify"],
            &["ctl", "verify", "--device", "ELEMENTDEVICEID"],
            &[
                "ctl",
                "verify",
                "--timeout",
                "60",
                "--with-user",
                "@you:example.org",
            ],
            &["ctl", "verify", "list"],
            &["ctl", "verify", "start", "ELEMENTDEVICEID"],
            &["ctl", "verify", "show", "flow1"],
            &["ctl", "verify", "accept", "flow1"],
            &["ctl", "verify", "start-sas", "flow1"],
            &["ctl", "verify", "sas-accept", "flow1"],
            &[
                "ctl",
                "verify",
                "confirm",
                "flow1",
                "--with-user",
                "@you:example.org",
            ],
            &["ctl", "verify", "cancel", "flow1"],
            &["ctl", "keys", "export", "keys.txt"],
            &[
                "ctl",
                "keys",
                "import",
                "keys.txt",
                "--user-id",
                "@me:example.org",
            ],
            &["ctl", "--proxy", "http://127.0.0.1:9000", "status"],
            &["ctl", "debug", "check"],
            &["ctl", "debug", "check", "--json"],
            &[
                "ctl",
                "debug",
                "--json",
                "session",
                "--user-id",
                "@me:example.org",
            ],
            &["ctl", "debug", "devices"],
            &["ctl", "debug", "devices", "@you:example.org"],
            &["ctl", "debug", "room", "!room:example.org"],
            &["ctl", "debug", "event", "!room:example.org", "$event"],
            &["ctl", "debug", "logs", "--level", "warn", "--limit", "5"],
            &["ctl", "debug", "log-level", "ement_e2ee=trace"],
            &["ctl", "debug", "report", "--output", "report.json"],
        ] {
            let cli = parse(args);
            assert!(matches!(cli.command, Some(Command::Ctl(_))), "{args:?}");
        }
    }

    #[test]
    fn ctl_connection_options() {
        // By default the address comes from the config file, not a flag.
        let Some(Command::Ctl(args)) = parse(&["ctl", "status"]).command else {
            panic!("expected ctl");
        };
        assert_eq!(args.proxy, None);
        assert_eq!(args.config, None);

        let cli = parse(&[
            "ctl",
            "--config",
            "/etc/ement.toml",
            "--proxy",
            "http://[::1]:9",
            "status",
        ]);
        let Some(Command::Ctl(args)) = cli.command else {
            panic!("expected ctl");
        };
        assert_eq!(args.proxy.as_deref(), Some("http://[::1]:9"));
        assert_eq!(args.config, Some("/etc/ement.toml".into()));
    }

    #[test]
    fn setup_invocations_parse() {
        for args in [
            &["setup"][..],
            &["setup", "--user-id", "@me:example.org"],
            &["setup", "--homeserver", "https://matrix.example.org"],
            &[
                "setup",
                "--listen",
                "127.0.0.1:9000",
                "--config",
                "/tmp/c.toml",
                "--force",
            ],
        ] {
            let cli = parse(args);
            assert!(matches!(cli.command, Some(Command::Setup(_))), "{args:?}");
        }
    }

    #[test]
    fn bad_invocations_are_rejected() {
        for args in [
            &["ctl"][..],
            &["ctl", "verify", "start"],
            &["ctl", "debug"],
            &["ctl", "debug", "event", "!room:example.org"],
            // Interactive options and single steps do not mix.
            &["ctl", "verify", "--device", "X", "list"],
            &["ctl", "keys", "export"],
            &["serve", "--listen", "not-an-address"],
            // Flags of the service installer setup no longer has.
            &["setup", "--no-service"],
            &["setup", "--yes"],
            &["frobnicate"],
        ] {
            let result = Cli::try_parse_from(std::iter::once(&"ement-e2ee").chain(args));
            assert!(result.is_err(), "{args:?}");
        }
    }
}
