// Copyright (C) 2025 - 2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

// TODO: Allow the user to decide which Quote attributes should matter for key retrieval.

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::Path;
use std::fs;

use utils::{
    key_broker_client::{KBSClient, TrusteeKbsClient},
    quote::Quote,
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(disable_help_flag = true)]
struct Args {
    #[arg(long)]
    sk_kbs_admin_path: String,

    #[arg(long)]
    kbs_url: String,

    #[arg(long)]
    kbs_cert_path: String,

    #[arg(long)]
    k_rfs_id: String,

    #[arg(long)]
    quote_b64: String,

    #[arg(long)]
    k_rfs: String,

    // Custom help to remove the default help message added by clap
    #[arg(short, long, action = clap::ArgAction::Help, help = "")]
    help: Option<bool>,
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let sk_kbs_admin_path: String = args.sk_kbs_admin_path;
    let kbs_url: String = args.kbs_url;
    let kbs_cert_path: String = args.kbs_cert_path;
    let k_rfs_id: String = args.k_rfs_id;
    let quote_b64: String = args.quote_b64;
    let mut k_rfs: String = args.k_rfs;

    // Check if file exists, which contains private key for administrator access to KBS.
    if !Path::new(&sk_kbs_admin_path).exists() {
        println!("Private key file \"{}\" that should be used for admin access to KBS does not exist. Please provide a valid private key file path.", sk_kbs_admin_path);
        return Ok(());
    }

    // Check if KBS certificate file exists.
    if !Path::new(&kbs_cert_path).exists() {
        println!("KBS cert path \"{}\" does not exist. Please provide a valid KBS cert path.", kbs_cert_path);
        return Ok(())
    }

    // Read private key used for administrator access to KBS.
    let sk_kbs_admin = fs::read_to_string(&sk_kbs_admin_path).map_err(|e| anyhow!(
            "Failed to read private key used for administrator access to KBS from '{}': {}",
            sk_kbs_admin_path, e
        ))?;

    // Initialize Trustee KBS.
    let kbs = TrusteeKbsClient::new(kbs_url, kbs_cert_path)
        .map_err(|e| anyhow!("Failed to create Trustee KBS: {}", e))?;

    // Convert incoming base64 encoded TD quote to a quote object.
    let quote = Quote::from_b64(&quote_b64)?;

    // Send root filesystem encryption key to KBS, which will use KMS for storage.
    kbs.store_k_rfs(&k_rfs, &sk_kbs_admin, &quote, &k_rfs_id).expect("Failed to store root filesystem encryption key in KBS");

    // Securely erase root file key from memory.
    k_rfs.zeroize();

    Ok(())
 }
