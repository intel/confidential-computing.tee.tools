// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

// TODO: Setup a quote retrieval HTTP(S) endpoint in the TD (by creating a variant of the fde-quote-gen code). Then, the script can retrieve the quote from outside the TD, handle the quote, send the necessary data to ITA KBS, and retrieve the key. This is very important for TD that do not offer any login capability!
// TODO: Allow the user to decide which Quote attributes should matter for key retrieval.

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::Path;

use rsa::{
    pkcs8::DecodePrivateKey,
    pkcs8::DecodePublicKey,
    RsaPrivateKey,
    RsaPublicKey,
};
use utils::{
    key_broker::{KBS, ItaKbs},
    quote::Quote,
    rsa_ext::RsaPublicKeyExt,
};
use zeroize::Zeroize;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    pk_kr_path: String,

    #[arg(long)]
    sk_kr_path: String,

    #[arg(long)]
    kbs_url: String,

    #[arg(long)]
    kbs_cert_path: String,

    #[arg(long)]
    kbs_env_file_path: String,

    #[arg(long)]
    quote_b64: String,
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let pk_kr_path: String = args.pk_kr_path;
    let sk_kr_path: String = args.sk_kr_path;
    let kbs_url: String = args.kbs_url;
    let kbs_cert_path: String = args.kbs_cert_path;
    let kbs_env_file_path: String = args.kbs_env_file_path;
    let quote_b64: String = args.quote_b64;

    // Check if public key file exists
    if !Path::new(&pk_kr_path).exists() {
        println!("Public key file \"{}\" that should be used for key retrieval does not exist. Please provide a valid public key file path.", pk_kr_path);
        return Ok(());
    }

    // Check if private key file exists
    if !Path::new(&sk_kr_path).exists() {
        println!("Private key file \"{}\" that should be used for key retrieval does not exist. Please provide a valid private key file path.", sk_kr_path);
        return Ok(());
    }

    let pk_kr: RsaPublicKey = DecodePublicKey::read_public_key_pem_file(&pk_kr_path)
        .map_err(|e| anyhow!("Failed to read public key: {}", e))?;
    let pk_kr_b64 = pk_kr.base64_encoded();

    if !Path::new(&kbs_cert_path).exists() {
        println!("KBS cert path \"{}\" does not exist. Please provide a valid KBS cert path.", kbs_cert_path);
        return Ok(())
    }

    if !Path::new(&kbs_env_file_path).exists() {
        println!("KBS env file path \"{}\" does not exist. Please provide a valid kbs env file path.", kbs_env_file_path);
        return Ok(())
    }

    // Initialize ITA KBS.
    let kbs = ItaKbs::new(kbs_url, kbs_cert_path)
        .map_err(|e| anyhow!("Failed to create ITA KBS: {}", e))?;

    // Retrieve credentials from the configuration file.
    let (username, password) = ItaKbs::retrieve_credentials(&kbs_env_file_path)
        .map_err(|e| anyhow!("Failed to read ITA KBS username and password: {}", e))?;

    // Get bearer token.
    let bearer_token = kbs.get_bearer_token(&username, &password).expect("Failed to get bearer token");

    // Convert incoming base64 encoded TD quote to a quote object and trigger key creation for this TD.
    let quote = Quote::from_b64(&quote_b64)?;
    let k_rfs_id = kbs.create_k_rfs(&bearer_token, &quote).expect("Failed to create root file key");

    // Prepare request body for root file key retrieval.
    // The public key used for key retrieval is read from file and converted to base64.
    // The hash of this key was used as report data in the TD quote generation.
    let req_body = format!(
        r#"{{"quote":"{}","user_data":"{}"}}"#,
        quote_b64,
        pk_kr_b64
    ).replace("\n", "");

    let sk_kr: RsaPrivateKey =
        DecodePrivateKey::read_pkcs8_pem_file(&sk_kr_path).expect("Failed to read private key");

    // Retrieve root file key from KBS.
    let mut k_rfs = kbs.retrieve_k_rfs(req_body, sk_kr, k_rfs_id.clone())
        .expect("Failed to retrieve root file key");

    // Print retrieved root file key as hex.
    let k_rfs_hex: String = k_rfs.iter().map(|n| format!("{:02x}", n)).collect::<Vec<String>>().join("");

    println!("export k_RFS={:?}", k_rfs_hex);
    println!("export ID_k_RFS={:?}", k_rfs_id);

    // Securely erase root file key from memory.
    k_rfs.zeroize();

    Ok(())
 }
