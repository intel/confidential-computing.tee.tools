// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use std::process::Command;
use std::io::Write;

pub const K_RFS_BIT_LENGTH: usize = 256;
pub const K_RFS_ALGO : &str = "AES";

/// Opens the root device and attempts to load it as a LUKS2 encrypted device.
///
/// # Parameters
///
/// - `label_part_rootfs_enc`: Label of partition with encrypted root filesystem.
/// - `label_dev_rootfs_dec`:  Label of device providing decrypted access to encrypted root partition.
/// - `key`: Key used to decrypt the encrypted device.
///
/// # Errors
///
/// - If the root device is not available, it will panic with the message "FDE: root device is not available".
/// - If loading LUKS2 fails, it will panic with the message "FDE: Loading LUKS2 failed".
pub fn crypt_setup(label_part_rootfs_enc: String, label_dev_rootfs_dec: String, key: &[u8]) {
    // Ensure that device has a valid name.
    // If none was provided, use last segment of name of partition with encrypted root filesystem
    let mut _label_dev_rootfs_dec = label_dev_rootfs_dec.as_str();
    if _label_dev_rootfs_dec.is_empty() {
        _label_dev_rootfs_dec = label_part_rootfs_enc
            .split('/')
            .next_back()
            .expect("FDE: Set device name failed.");
    }

    // Construct the bash command to open LUKS device.
    // Note: cryptsetup_rs crate cannot be used as it collides with key generation.
    let command = format!(
        "cryptsetup luksOpen --key-file - --key-size 256 {} {}",
        label_part_rootfs_enc, _label_dev_rootfs_dec
    );

    // Execute the bash command to open LUKS device.
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("FDE: Failed to execute cryptsetup command");

    child.stdin
        .as_mut()
        .expect("FDE: Failed to open stdin")
        .write_all(key)
        .expect("FDE: Failed to write key to stdin");

    // Check the output status
    child.wait_with_output()
        .expect("FDE: Failed to read cryptsetup command output");

    println!("LUKS device opened successfully");
}
