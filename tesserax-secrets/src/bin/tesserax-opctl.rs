//! `tesserax-opctl`: operator CLI for services that accept signed operator
//! commands (feature `opctl`).
//!
//! ```text
//! tesserax-opctl keygen --out ./operator.key
//! tesserax-opctl pubkey --key ./operator.key
//! tesserax-opctl discover --url https://service.example
//! tesserax-opctl call --url https://service.example --key ./operator.key --signer-id alice \
//!                     --pin-fp <fingerprint> --pin-pubkey <b64> --payload-json '{"op":"list"}'
//! ```
//!
//! `call` accepts any JSON payload and prints the service's response body
//! after verifying its signature against the pinned identity.
//!
//! `discover` probes `/admin/identity` (an Admin route) first, then the
//! older `/admin/mesh/status` and `/manifest`. If the environment variable
//! `TESSERAX_OPCTL_BEARER` is set, every request carries it as
//! `Authorization: Bearer <value>` (an environment variable, not a flag,
//! so the credential stays out of the process list).

use std::path::PathBuf;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use tesserax_secrets::opctl::{Session, discover_daemon, generate, load_secret, save_secret};

#[derive(Parser, Debug)]
#[command(
    name = "tesserax-opctl",
    version,
    about = "Operator CLI for services that accept signed operator commands"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh ed25519 secret key file (raw 32 bytes, chmod 0600).
    Keygen {
        #[arg(long)]
        out: PathBuf,
        /// Refuse to overwrite if the file already exists.
        #[arg(long, default_value_t = true)]
        no_overwrite: bool,
    },
    /// Print the pubkey corresponding to a key file (b64-url-no-pad,
    /// ready to add to a service's trusted operator signers).
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Fetch the service identity (`/admin/identity`, then the older
    /// `/admin/mesh/status` and `/manifest`): name + pubkey_fingerprint.
    Discover {
        #[arg(long)]
        url: String,
    },
    /// Sign + ship one OperatorCommand v2, print the daemon's verified
    /// response body.
    Call {
        #[arg(long)]
        url: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        signer_id: String,
        /// JSON payload literal. The daemon deserialises this however
        /// it expects.
        #[arg(long)]
        payload_json: String,
        /// Pin the daemon's fingerprint (signed-response verification). Use
        /// `tesserax-opctl discover` first; copy that fingerprint here.
        #[arg(long)]
        pin_fp: String,
        /// Pin the raw 32-byte pubkey, b64-url-no-pad. Required for
        /// the ed25519 signature check on the response. Look it up
        /// in the daemon's `/manifest.daemon` block or operator's
        /// out-of-band trust list.
        #[arg(long)]
        pin_pubkey: String,
        /// TTL of the request (seconds). Daemon refuses past this.
        #[arg(long, default_value_t = 60)]
        ttl_secs: u64,
        /// Override the op-cmd path (default /admin/op-cmd).
        #[arg(long, default_value = "/admin/op-cmd")]
        op_cmd_path: String,
        /// Maximum allowed clock skew between operator and daemon
        /// (seconds). Default 300 (5 min). Set high if your operator
        /// clock is unreliable.
        #[arg(long, default_value_t = 300)]
        max_skew_secs: u64,
    },
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn ctx<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> Result<T, BoxError> {
    r.map_err(|e| format!("{what}: {e}").into())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out, no_overwrite } => {
            if no_overwrite && out.exists() {
                return Err(format!(
                    "refusing to overwrite {} (pass --no-overwrite=false to force)",
                    out.display()
                )
                .into());
            }
            if !no_overwrite && out.exists() {
                std::fs::remove_file(&out).ok();
            }
            let sk = ctx(generate(), "generate")?;
            ctx(save_secret(&out, &sk), "save")?;
            let pubkey_b64 = B64.encode(sk.verifying_key().to_bytes());
            let fp = blake3::hash(&sk.verifying_key().to_bytes());
            let fp_b64 = B64.encode(&fp.as_bytes()[..16]);
            println!("OK");
            println!("  secret_path        : {}", out.display());
            println!("  pubkey_b64         : {}", pubkey_b64);
            println!(
                "  pubkey_fingerprint : {}  (16-byte BLAKE3 prefix, b64url)",
                fp_b64
            );
            println!();
            println!("Add to the service's trusted operator signers:");
            println!();
            println!("  id          = <operator name>");
            println!("  pubkey_b64  = {pubkey_b64}");
        }
        Cmd::Pubkey { key } => {
            let sk = ctx(load_secret(&key), "load")?;
            let pubkey_b64 = B64.encode(sk.verifying_key().to_bytes());
            println!("{}", pubkey_b64);
        }
        Cmd::Discover { url } => {
            let http = build_http()?;
            let info = ctx(discover_daemon(&http, &url).await, "discover")?;
            println!("OK");
            println!("  source              : {}", info.source_url);
            println!("  daemon_name         : {}", info.name);
            println!("  pubkey_fingerprint  : {}", info.pubkey_fingerprint);
            if let Some(pk) = info.pubkey_b64.as_deref() {
                println!("  pubkey_b64          : {pk}");
                println!();
                println!("Pass these into `tesserax-opctl call`:");
                println!("  --pin-fp     {}", info.pubkey_fingerprint);
                println!("  --pin-pubkey {}", pk);
                eprintln!(
                    "note: discovered via {}; pubkey came from the daemon itself. \
                     For production trust, cross-check against your audited install channel \
                     (the daemon's pubkey is also printed in its boot log).",
                    info.source_url
                );
            } else {
                println!("  pubkey_b64          : (not exposed by this endpoint)");
                eprintln!(
                    "note: {} did not include the raw pubkey. Obtain it via the daemon's \
                     boot log or audited install channel and pass --pin-pubkey explicitly.",
                    info.source_url
                );
            }
        }
        Cmd::Call {
            url,
            key,
            signer_id,
            payload_json,
            pin_fp,
            pin_pubkey,
            ttl_secs,
            op_cmd_path,
            max_skew_secs,
        } => {
            // Validate payload is valid JSON (give a nicer error than
            // letting the daemon reject it).
            let _: serde_json::Value = ctx(
                serde_json::from_str(&payload_json),
                "--payload-json is not valid JSON",
            )?;

            let sk = ctx(load_secret(&key), "load secret key")?;

            let pubkey_bytes = ctx(B64.decode(pin_pubkey.as_bytes()), "decode --pin-pubkey")?;
            if pubkey_bytes.len() != 32 {
                return Err(format!(
                    "--pin-pubkey must decode to 32 bytes (got {})",
                    pubkey_bytes.len()
                )
                .into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pubkey_bytes);
            let pubkey = ctx(VerifyingKey::from_bytes(&arr), "parse --pin-pubkey")?;

            let session = ctx(
                Session::new(sk, signer_id.clone(), &url, pubkey, pin_fp.clone()),
                "http client",
            )?
            .with_op_cmd_path(op_cmd_path)
            .with_default_ttl(Duration::from_secs(ttl_secs))
            .with_max_skew(max_skew_secs);
            eprintln!(
                "sending signed command to {} as {signer_id}",
                session.op_cmd_url()
            );
            let verified = ctx(session.call(payload_json.as_bytes()).await, "signed call")?;
            let body_str = String::from_utf8_lossy(&verified.body);
            eprintln!(
                "verified: status={} fp={} stamped_unix={}",
                verified.status, verified.fingerprint, verified.daemon_stamped_unix
            );
            // Print to stdout so caller can pipe through jq.
            println!("{}", body_str);
            if !(200..300).contains(&verified.status) {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

fn build_http() -> Result<reqwest::Client, BoxError> {
    let mut b = reqwest::Client::builder()
        .user_agent(concat!("tesserax-opctl/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20));
    if let Ok(token) = std::env::var("TESSERAX_OPCTL_BEARER") {
        let mut v = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        v.set_sensitive(true);
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(reqwest::header::AUTHORIZATION, v);
        b = b.default_headers(h);
    }
    Ok(b.build()?)
}
