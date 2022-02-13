use firestore_db_and_auth::{documents, errors, Credentials, ServiceSession};
use firestore_db_and_auth::jwt::{download_google_jwks, JWKSetDTO};

use serde::{Deserialize, Serialize};

use clap::Parser;
use chrono::NaiveDateTime;

use std::env;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// collection name
    #[clap(short, long)]
    collection_name: String,

    /// data json string
    #[clap(short, long)]
    json: String    
}

#[derive(Debug, Serialize, Deserialize)]
struct HomeEnv {
    datetime: String,
    temperature: f64,
    humidity: f64,
    pressure: f64,
    co2: u64,
}

/// Download the two public key JWKS files if necessary and cache the content at the given file path.
/// Only use this option in cloud functions if the given file path is persistent.
/// You can use [`Credentials::add_jwks_public_keys`] to manually add more public keys later on.
pub fn from_cache_file(cache_file: &std::path::Path, c: &Credentials) -> errors::Result<JWKSetDTO> {
    use std::fs::File;
    use std::io::BufReader;

    Ok(if cache_file.exists() {
        let f = BufReader::new(File::open(cache_file)?);
        let jwks_set: JWKSetDTO = serde_json::from_reader(f)?;
        jwks_set
    } else {
        // If not present, download the two jwks (specific service account + google system account),
        // merge them into one set of keys and store them in the cache file.
        // let mut jwks = JWKSetDTO::new(&download_google_jwks(&c.client_email)?)?;
        let mut jwks = download_google_jwks(&c.client_email)?;
        jwks.keys
            .append(&mut download_google_jwks("securetoken@system.gserviceaccount.com")?.keys);
        let f = File::create(cache_file)?;
        serde_json::to_writer_pretty(f, &jwks)?;
        jwks
    })
}

fn main() -> errors::Result<()> {
    // Parse arguments
    let args = Args::parse();

    // Parse home env json
    let home_env = serde_json::from_str::<HomeEnv>(&args.json)?;

    // Search for a credentials file in the current directory
    let mut cred_path = PathBuf::from(env::current_exe().unwrap());
    cred_path.pop();
    cred_path.push("home-env-firebase-adminsdk.json");

    let mut cred = Credentials::from_file(cred_path.to_str().unwrap())?;

    // Only download the public keys once, and cache them.
    let jwkset = from_cache_file(cred_path.with_file_name("cached_jwks.jwks").as_path(), &cred)?;
    cred.add_jwks_public_keys(jwkset);
    cred.verify()?;

    // Post home env data
    let datetime = NaiveDateTime::parse_from_str(&home_env.datetime, "%Y/%m/%d %H:%M:%S").unwrap();
    let id = datetime.format("%Y%m%d%H%M%S").to_string();

    let session = ServiceSession::new(cred).unwrap();
    documents::write(&session, &args.collection_name, Some(id), &home_env, documents::WriteOptions::default())?;
    Ok(())
}

