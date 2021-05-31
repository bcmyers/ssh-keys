//! ssh-keys

#![cfg(unix)]
#![deny(clippy::all)]
#![deny(dead_code)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(rust_2018_idioms)]
#![deny(unsafe_code)]
#![deny(unused_imports)]

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::process::exit;

use anyhow::Context as _;
use rusoto_core::Region;
use rusoto_credential::ProfileProvider;
use rusoto_secretsmanager::*;
use uuid::Uuid;

use std::path::PathBuf;
use structopt::StructOpt;

type Files = HashMap<String, String>;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Name of AWS profile (defined in ~/.aws/config) to use for credentials
    #[structopt(long, default_value = "bcmyers")]
    aws_profile: String,

    /// ID of AWS secret where ssh keys are stored
    #[structopt(long, default_value = "ssh-keys")]
    secret_id: String,

    /// Command
    #[structopt(subcommand)]
    command: Command,
}

/// Command
#[derive(Debug, StructOpt)]
enum Command {
    Get {
        /// An empty output directory
        outdir: PathBuf,
    },

    /// Put ssh keys
    Put {
        /// Directory containing ssh keys to put
        indir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let Opt {
        aws_profile,
        command,
        secret_id,
    } = Opt::from_args();

    let dispatcher = rusoto_core::request::HttpClient::new()?;
    let provider = ProfileProvider::with_default_credentials(aws_profile)?;
    let client = SecretsManagerClient::new_with(dispatcher, provider, Region::UsEast1);

    match command {
        Command::Get { outdir } => get(&client, outdir, secret_id).await?,
        Command::Put { indir } => put(&client, indir, secret_id).await?,
    }

    Ok(())
}

async fn get(
    client: &SecretsManagerClient,
    outdir: PathBuf,
    secret_id: String,
) -> Result<(), anyhow::Error> {
    if outdir.exists() {
        if !outdir
            .metadata()
            .with_context(|| format!("{}", outdir.display()))?
            .is_dir()
        {
            anyhow::bail!(
                "Provided outdir {} is not an empty directory",
                outdir.display()
            );
        }
        if fs::read_dir(&outdir)?.count() != 0 {
            anyhow::bail!(
                "Provided outdir {} is not an empty directory",
                outdir.display()
            );
        }
    } else {
        fs::create_dir_all(&outdir).with_context(|| format!("{}", outdir.display()))?;
    }
    let request = {
        let mut r = GetSecretValueRequest::default();
        r.secret_id = secret_id;
        r
    };
    let response = client.get_secret_value(request).await?;
    let s = response
        .secret_string
        .ok_or_else(|| anyhow::anyhow!("Expected secret_string in response but did not get one"))?;
    let files = serde_json::from_str::<Files>(&s)?;
    for (k, v) in files {
        let path = outdir.join(&k);
        let mode = if k.ends_with(".pub") || k.ends_with(".public") {
            0o444
        } else {
            0o400
        };
        let f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&path)
            .with_context(|| format!("{}", path.display()))?;
        let mut writer = io::BufWriter::new(f);
        writer.write_all(v.as_bytes())?;
    }
    Ok(())
}

async fn put(
    client: &SecretsManagerClient,
    indir: PathBuf,
    secret_id: String,
) -> Result<(), anyhow::Error> {
    if !indir.metadata()?.is_dir() {
        anyhow::bail!("Provided indir {} is not a directory", indir.display());
    }
    let mut map = HashMap::new();
    for entry in fs::read_dir(&indir)? {
        let entry = entry?;
        if !entry
            .metadata()
            .with_context(|| format!("{}", entry.path().display()))?
            .is_file()
        {
            continue;
        }
        let k = entry
            .path()
            .file_name()
            .expect("Cannot fail")
            .to_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "File {} contains invalid utf-8 in it's filename",
                    entry.path().display()
                )
            })?
            .to_string();
        let v = fs::read_to_string(entry.path())
            .with_context(|| format!("{}", entry.path().display()))?;
        map.insert(k, v);
    }
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all("Are you sure you want to override ssh-keys with the following:\n".as_bytes())?;
    let mut keys = map.keys().collect::<Vec<_>>();
    keys.sort();
    for k in keys {
        stdout.write_all(format!("  - {}\n", k).as_bytes())?;
    }
    stdout.write_all("This will delete the existing contents of ssh-keys\n".as_bytes())?;
    drop(stdout);
    let mut answer = String::new();
    loop {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        stdout.write_all("yes/no: ".as_bytes())?;
        stdout.flush()?;
        drop(stdout);
        io::stdin().read_line(&mut answer)?;
        match answer.trim() {
            "yes" | "y" | "Yes" | "YES" => break,
            "no" | "n" | "No" | "NO" => {
                println!("Cancelling and exiting.");
                exit(0);
            }
            _ => answer.clear(),
        }
    }
    let s = serde_json::to_string_pretty(&map)?;
    let request = {
        let mut r = PutSecretValueRequest::default();
        r.client_request_token = Some(Uuid::new_v4().to_string());
        r.secret_id = secret_id;
        r.secret_string = Some(s);
        r
    };
    let response = client.put_secret_value(request).await?;
    if let Some(version) = response.version_id {
        println!("Secret version: {}", version);
    }
    Ok(())
}
