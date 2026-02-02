// Copyright (C) 2025 - 2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Ok, Result};
use clap::Parser;

use zeroize::Zeroizing;
use utils::{
    key_broker_client::{KBSClient, TrusteeKbsClient},
    ovmf_var::{OvmfParamsFdeBoot},
    quote::*,
    disk::crypt_setup,
};

#[derive(Parser)]
struct Args {
    // Label of partition with encrypted root filesystem.
    #[arg(long)]
    label_part_rootfs_enc: String,

    // Label of device providing decrypted access to encrypted root partition.
    #[arg(long)]
    label_dev_rootfs_dec: String,

    // TD boot mode (GET_QUOTE or TD_FDE_BOOT).
    #[arg(long)]
    td_boot_mode: String,
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    // Read label of encrypted root filesystem partition, label of virtual device used for decrypted view of encrypted root filesystem partition, and TD boot mode from arguments.
    let args = Args::parse();
    let label_part_rootfs_enc = args.label_part_rootfs_enc;
    let label_dev_rootfs_dec: String = args.label_dev_rootfs_dec;
    let td_boot_mode: String = args.td_boot_mode;

    // Print input arguments.
    println!("Label Partition Rootfs Enc: {}", label_part_rootfs_enc);
    println!("Label Device Rootfs Dec: {}", label_dev_rootfs_dec);
    println!("TD Boot Mode: {}", td_boot_mode);

    // Check if TD boot mode is either GET_QUOTE or TD_FDE_BOOT.
    if td_boot_mode != "GET_QUOTE" && td_boot_mode != "TD_FDE_BOOT" {
        return Err(anyhow!("Unsupported TD boot mode: {}", td_boot_mode));
    }

    // In the GET_QUOTE boot mode, only retrieve the quote and end the boot.
    // In the TD_FDE_BOOT boot mode, retrieve the root filesystem encryption key from the KBS and unencrypt the root filesystem.
    if td_boot_mode == "GET_QUOTE" {
        // Retrieve TD quote.
        let quote = Quote::retrieve_quote(None)?;

        // Print base 64 encoded TD Quote.
        let quote_b64 = quote.get_raw_base64().ok_or_else(|| anyhow!("Failed to get base64 quote"))?;
        println!("---------------------------------------------------------");
        println!("export QUOTE=\"{}\"", quote_b64);
        println!("---------------------------------------------------------");

        // Indicate planned exit without error
        println!("Stop further boot in GET_QUOTE boot mode");
        std::process::exit(1);
    } else if td_boot_mode == "TD_FDE_BOOT" {
        // Prepare retrieval request for root filesystem encryption key.
        let fde_boot_params = OvmfParamsFdeBoot::new()?;
        let kbs_url = String::from_utf8(fde_boot_params.kbs_url)?;
        let kbs_k_rfs_id = String::from_utf8(fde_boot_params.kbs_k_rfs_id)?;

        // Retrieve root filesystem encryption key from KBS.
        let kbs_cert_path = String::from("/etc/kbs.crt");
        let kbs = TrusteeKbsClient::new(kbs_url, kbs_cert_path)?;
        let k_rfs = Zeroizing::new(
            kbs.retrieve_k_rfs(kbs_k_rfs_id).await
                .map_err(|e| anyhow!("Failed to retrieve root filesystem encryption key: {}", e))?
        );

        // Decrypt root filesystem partition using retrieved root filesystem encryption key.
        // k_rfs is automatically zeroized when dropped (on success, error, or panic).
        crypt_setup(label_part_rootfs_enc, label_dev_rootfs_dec, &k_rfs);

        Ok(())
    } else {
        println!("Unsupported boot mode");
        Ok(())
    }
}
