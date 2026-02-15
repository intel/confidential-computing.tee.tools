// Copyright (C) 2025 - 2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Ok, Result};
use clap::Parser;

use rsa::{RsaPrivateKey, RsaPublicKey, rand_core::OsRng};
use zeroize::Zeroize;
use utils::{
    key_broker_client::{KBS, ItaKbs},
    ovmf_var::{OvmfParamsBootMode, OvmfParamsGetQuote, OvmfParamsFdeBoot},
    quote::*,
    rsa_ext::RsaPublicKeyExt,
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
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    // Read label of encrypted root filesystem partition, label of virtual device used for decrypted view of encrypted root filesystem partition, and TD boot mode from arguments.
    let args = Args::parse();
    let label_part_rootfs_enc = args.label_part_rootfs_enc;
    let label_dev_rootfs_dec: String = args.label_dev_rootfs_dec;

    // Print input arguments.
    println!("Label Partition Rootfs Enc: {}", label_part_rootfs_enc);
    println!("Label Device Rootfs Dec: {}", label_dev_rootfs_dec);

    // Extract TD boot mode from OVMF parameters and print it.
    let td_boot_mode = OvmfParamsBootMode::new()?.mode;
    println!("TD Boot Mode: {}", td_boot_mode);

    // Check if TD boot mode is either GET_QUOTE or TD_FDE_BOOT.
    if td_boot_mode != "GET_QUOTE" && td_boot_mode != "TD_FDE_BOOT" {
        return Err(anyhow!("Unsupported TD boot mode: {}", td_boot_mode));
    }

    // In the GET_QUOTE boot mode, only retrieve the quote and end the boot.
    // In the TD_FDE_BOOT boot mode, retrieve the root filesystem key from the KBS and unencrypt the root filesystem.
    if td_boot_mode == "GET_QUOTE" {
        let get_quote_params = OvmfParamsGetQuote::new()?;
        // Put hash of public part of key retrieval key into report data structure.
        let report_data = tdx_attest_rs::tdx_report_data_t {
            d: get_quote_params.pk_kr.sha512_digest(),
        };

        // Retrieve TD quote using the prepared report data.
        let quote = Quote::retrieve_quote(&report_data)?;

        // Print base 64 encoded TD Quote.
        let quote_b64 = quote.get_raw_base64().ok_or_else(|| anyhow!("Failed to get base64 quote"))?;
        println!("---------------------------------------------------------");
        println!("export QUOTE=\"{}\"", quote_b64);
        println!("---------------------------------------------------------");

        // Indicate planned exit without error
        println!("Stop further boot in GET_QUOTE boot mode");
        std::process::exit(1);
    } else if td_boot_mode == "TD_FDE_BOOT" {

       // Generate RSA key pair used for key retrieval.
       let sk_kr = RsaPrivateKey::new(&mut OsRng, 3072).expect("Failed to generate private key");
       let pk_kr = RsaPublicKey::from(&sk_kr);

           // Put hash of public part of key retrieval key into report data structure.
           let report_data = tdx_attest_rs::tdx_report_data_t {
            d: pk_kr.sha512_digest(),
        };

        // Retrieve TD quote using the prepared report data.
        let quote = Quote::retrieve_quote(&report_data)?;

        // Prepare retrieval request for root filesystem key.
        let fde_boot_params = OvmfParamsFdeBoot::new()?;
        let kbs_url = String::from_utf8(fde_boot_params.kbs_url)?;
        let kbs_k_rfs_id = String::from_utf8(fde_boot_params.kbs_k_rfs_id)?;

        let req_body = format!(
            r#"{{"quote":"{}","user_data":"{}"}}"#,
            quote.get_raw_base64().expect("Failed to get base64 quote"),
            pk_kr.base64_encoded()
        )
        .replace("\n", "");

        // Retrieve root filesystem key from KBS.
        let kbs_cert_path = String::from("/etc/kbs.crt");
        let kbs = ItaKbs::new(kbs_url, kbs_cert_path)?;
        let mut k_rfs = kbs.retrieve_k_rfs(req_body, sk_kr, kbs_k_rfs_id)
            .expect("Failed to retrieve root filesystem key");

        // Decrypt root filesystem partition using retrieved root filesystem key.
        crypt_setup(label_part_rootfs_enc.to_string(), label_dev_rootfs_dec.to_string(), &k_rfs);

        // Securely erase root filesystem key from memory.
        k_rfs.zeroize();

        Ok(())
    } else {
        println!("Unsupported boot mode");
        Ok(())
    }
}
