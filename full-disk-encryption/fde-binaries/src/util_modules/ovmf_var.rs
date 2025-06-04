// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::Result;
use efivar::efi::Variable;
use efivar::system;
use std::str::FromStr;

use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};

const KBS_URL_GUID: &str = "KBSURL-0d9b4a60-e0bf-4a66-b9b1-db1b98f87770";
const KBS_K_RFS_ID_GUID: &str = "KBSKRFSID-dc001d1f-60a1-4e1e-853e-42e9ab0e8b88";
const TDBOOTMODE_GUID: &str = "TDBOOTMODE-8093baf3-b42c-4a46-9c60-02888f011f03";
const PK_KR_GUID: &str = "PK_KR-4517e507-9b4b-479d-b422-2562900361e3";

#[derive(Debug)]
pub struct OvmfParamsBootMode {
    pub mode: String,
}

#[derive(Debug)]
pub struct OvmfParamsGetQuote {
    pub pk_kr: RsaPublicKey,
}

#[derive(Debug)]
pub struct OvmfParamsFdeBoot {
    pub kbs_url: Vec<u8>,
    pub kbs_k_rfs_id: Vec<u8>,
}

impl OvmfParamsBootMode {
    /// Retrieves parameters from OVMF (Open Virtual Machine Firmware).
    ///
    /// # Parameters
    ///
    /// - `td_boot_mode`: A string representing the TD boot mode.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to read the UEFI variables.
    ///
    /// # Panics
    ///
    /// This function will panic if it fails to create a `Variable` from the provided GUID strings.
    pub fn new() -> Result<Self> {
        let var_manager = system();

        // Read TD boot mode from OVMF.
        let td_boot_mode_variable =
            Variable::from_str(TDBOOTMODE_GUID).expect("Failed to create variable for TD boot mode");
        let (td_boot_mode_bytes, _td_boot_mode_flags) = var_manager
            .read(&td_boot_mode_variable)
            .expect("Failed to read TD boot mode");
        let td_boot_mode =
            String::from_utf8(td_boot_mode_bytes).expect("Failed to convert TD boot mode to string");

        Ok(Self {
            mode: td_boot_mode,
        })
    }
}

impl OvmfParamsGetQuote {
    /// Retrieves parameters from OVMF (Open Virtual Machine Firmware) for GET_QUOTE mode.
    ///
    /// # Parameters
    ///
    /// - `pk_kr`: A public key used for key retrieval for KBS.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to read the UEFI variables.
    ///
    /// # Panics
    ///
    /// This function will panic if it fails to create a `Variable` from the provided GUID strings.
    pub fn new() -> Result<Self> {
        let var_manager = system();

        // Read public key for key retrieval from OVMF.
        let pk_kr_variable =
            Variable::from_str(PK_KR_GUID).expect("Failed to create variable for PK_KR");
        let (td_pk_kr_bytes, _td_boot_mode_flags) = var_manager
            .read(&pk_kr_variable)
            .expect("Failed to read PK_KR");
        let pk_kr_str = String::from_utf8(td_pk_kr_bytes).expect("Failed to convert PK_KR to string");
        let pk_kr = DecodePublicKey::from_public_key_pem(&pk_kr_str).expect("Failed to convert PK_KR");

        Ok(Self {
            pk_kr
        })
    }
}

impl OvmfParamsFdeBoot {
    /// Retrieves parameters from OVMF (Open Virtual Machine Firmware) for TD_FDE_BOOT mode.
    ///
    /// # Parameters
    ///
    /// - `kbs_url`: A vector of bytes representing the KBS URL.
    /// - `kbs_k_rfs_id`: A vector of bytes representing the RFS key ID used by the KBS.
    ///
    /// # Errors
    ///
    /// This function will return an error if it fails to read the UEFI variables.
    ///
    /// # Panics
    ///
    /// This function will panic if it fails to create a `Variable` from the provided GUID strings.
    pub fn new() -> Result<Self> {
        let var_manager = system();

        // Read KBS URL from OVMF.
        let kbs_url_variable =
            Variable::from_str(KBS_URL_GUID).expect("Failed to create variable for KBS URL");
        let (kbs_url_bytes, _url_data_flags) = var_manager
            .read(&kbs_url_variable)
            .expect("Failed to read KBS URL");

        // Read KBS RFS key ID from OVMF.
        let kbs_k_rfs_id_variable = Variable::from_str(KBS_K_RFS_ID_GUID)
            .expect("Failed to create variable for KBS RFS key ID");
        let (kbs_k_rfs_id_bytes, _key_id_data_flags) = var_manager
            .read(&kbs_k_rfs_id_variable)
            .expect("Failed to read KBS RFS key ID");

        Ok(Self {
            kbs_url: kbs_url_bytes,
            kbs_k_rfs_id: kbs_k_rfs_id_bytes,
        })
    }
}
