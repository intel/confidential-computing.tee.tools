// Copyright (C) 2025 - 2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use std::process::Command;
use std::io::Write;

pub const K_RFS_BIT_LENGTH: usize = 512;

/// Opens the root device and attempts to load it as a LUKS2 encrypted device.
///
/// # Parameters
///
/// - `label_part_rootfs_enc`: Label of partition with encrypted root filesystem.
/// - `label_dev_rootfs_dec`:  Label of device providing decrypted access to encrypted root partition.
/// - `key`: Key used to decrypt the encrypted device.
///
/// # Returns
///
/// - `Ok(())` if the LUKS device was successfully opened with the provided key.
///
/// # Errors
///
/// - If the device label from boot parameters is empty.
/// - If the cryptsetup command fails to execute.
/// - If writing the key to stdin of the cryptsetup process fails.
/// - If the cryptsetup process cannot be awaited for completion.
/// - If cryptsetup returns a non-zero exit code (e.g., wrong key, device not found).
pub fn crypt_setup(label_part_rootfs_enc: String, label_dev_rootfs_dec: String, key: &[u8]) {
    // Check if the device label from boot parameters is empty.
    if label_dev_rootfs_dec.is_empty() {
        panic!("FDE: Set device name failed.");
    }

    // Construct the bash command to open LUKS device.
    // Note: cryptsetup_rs crate cannot be used as it collides with key generation.
    let command = format!(
        "cryptsetup luksOpen --key-file - --key-size 512 {} {}",
        label_part_rootfs_enc, label_dev_rootfs_dec
    );

    // Execute the bash command to open LUKS device.
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("FDE: Failed to execute cryptsetup command: {}", e));

    // Write the key to the stdin of the cryptsetup command.
    child.stdin
        .as_mut()
        .unwrap_or_else(|| panic!("FDE: Failed to open stdin"))
        .write_all(key)
        .unwrap_or_else(|e| panic!("FDE: Failed to write key to stdin: {}", e));

    // Check the output status
    let output = child.wait_with_output()
        .unwrap_or_else(|e| panic!("FDE: Failed to read cryptsetup command output: {}", e));

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("FDE: cryptsetup luksOpen failed with exit code {:?}: {}",
               output.status.code(), stderr);
    }

    println!("LUKS device opened successfully");
}
