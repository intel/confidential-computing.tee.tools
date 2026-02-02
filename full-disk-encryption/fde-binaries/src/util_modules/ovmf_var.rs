// Copyright (C) 2025 - 2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::Result;
use efivar::efi::Variable;
use efivar::system;
use std::str::FromStr;

const KBS_URL_GUID: &str = "KBSURL-0d9b4a60-e0bf-4a66-b9b1-db1b98f87770";
const KBS_K_RFS_ID_GUID: &str = "KBSKRFSID-dc001d1f-60a1-4e1e-853e-42e9ab0e8b88";

#[derive(Debug)]
pub struct OvmfParamsFdeBoot {
    pub kbs_url: Vec<u8>,
    pub kbs_k_rfs_id: Vec<u8>,
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
