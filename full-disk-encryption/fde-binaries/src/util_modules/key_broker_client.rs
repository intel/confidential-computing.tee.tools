// Copyright (C) 2025 - 2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use reqwest::blocking::Client;
use reqwest::tls::Version;
use rsa::RsaPrivateKey;
use serde_json::Value;
use base64::prelude::*;

use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::{Aes256Gcm, KeyInit};
use rsa::sha2::Sha256;
use rsa::Oaep;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};

use crate::quote::Quote;

use super::disk::{
    K_RFS_BIT_LENGTH,
    K_RFS_ALGO
};

pub trait KBS {
    fn create_k_rfs(&self, bearer_token: &str, quote: &Quote) -> Result<String>;
    fn retrieve_k_rfs(&self, req: String, sk_kr: RsaPrivateKey, id_k_rfs: String) -> Result<Vec<u8>>;
}

pub struct ItaKbs {
    kbs_url: String,
    kbs_cert: reqwest::Certificate,
}

/// Parameters for key transfer policy creation
///
/// These parameters are used to create a key transfer policy in the ITA KBS.
/// The struct contains all measurement values from the quote that are required for attestation-based key release.
#[derive(Debug, Clone)]
struct KeyTransferPolicyParams {
    /// Authorization token for KBS API access
    bearer_token: String,
    /// Measurement of Intel TDX Module
    mrseam: String,
    /// The measurement of the signing key used for the Intel TDX Module.
    mrsignerseam: String,
    /// SVN of Intel TDX Module (as combination of major and minor)
    seamsvn: String,
    /// Measurement of the initial contents of the TD
    mrtd: String,
    /// Runtime measurement register 1
    rtmr1: String,
    /// Runtime measurement register 2
    rtmr2: String,
    /// Runtime measurement register 3
    rtmr3: String,
}

impl ItaKbs {
    /// Creates a new instance of an ITA KBS.
    ///
    /// # Parameters
    ///
    /// - `kbs_url`: The URL of the KBS.
    /// - `kbs_cert_path`: The file path to the KBS certificate.
    ///
    /// # Returns
    ///
    /// * `Result<Self>` - A result containing the new instance of an ITA KBS.
    pub fn new(kbs_url: String, kbs_cert_path: String) -> Result<Self> {
        // Try to open the KBS certificate file.
        let mut kbs_cert = File::open(kbs_cert_path.clone())
            .map_err(|_| anyhow!("Error opening KBS certificate file '{}'", kbs_cert_path.clone()))?;

        // Try to read the content into buffer.
        let mut buffer = Vec::new();
        kbs_cert.read_to_end(&mut buffer)
            .map_err(|_| anyhow!("Error reading file '{}'", kbs_cert_path.clone()))?;

        // Try to parse the certificate from PEM format.
        let kbs_cert = reqwest::Certificate::from_pem(&buffer)
            .map_err(|_| anyhow!("Error parsing certificate from file '{}'", kbs_cert_path.clone()))?;

        Ok(Self {
            kbs_url,
            kbs_cert,
        })
    }

    /// Reads the admin username and password from a configuration file.
    ///
    /// # Parameters
    ///
    /// - `kbs_env_file_path`: The path to the ITA KBS configuration file
    ///
    /// # Returns
    ///
    /// * `Result<(String, String)>` - A result containing a tuple with the username and password.
    pub fn retrieve_credentials(kbs_env_file_path: &str) -> Result<(String, String)> {
        // Read KBS enviornment file.
        let kbs_env_file = File::open(kbs_env_file_path)
            .map_err(|_| anyhow!("Failed to open KBS env file: {}", kbs_env_file_path))?;
        let reader = BufReader::new(kbs_env_file);

        // Read username and password from the KBS enviornment file.
        let mut username = String::new();
        let mut password = String::new();
        for line in reader.lines() {
            let line = line?;
            if let Some((key, value)) = line.split_once('=') {
                match key.trim() {
                    "ADMIN_USERNAME" => username = value.trim().to_string(),
                    "ADMIN_PASSWORD" => password = value.trim().to_string(),
                    _ => {}
                }
            }
        }

        if username.is_empty() || password.is_empty() {
            return Err(anyhow!("Failed to read ADMIN_USERNAME or ADMIN_PASSWORD from config"));
        }

        Ok((username, password))
    }

    /// Retrieves a bearer token from the ITA KBS using the provided username and password.
    ///
    /// # Parameters
    ///
    /// - `username`: The admin username.
    /// - `password`: The admin password.
    ///
    /// # Returns
    ///
    /// * `Result<String>` - A result containing the bearer token.
    pub fn get_bearer_token(&self, username: &str, password: &str) -> Result<String> {
        // Prepare request.
        let tls_client = self.default_tls_client();
        let req_url = format!("{}/kbs/v1/token", self.kbs_url);
        let mut req_headers = HeaderMap::new();
        req_headers.insert(ACCEPT, "application/jwt".parse()?);
        req_headers.insert(CONTENT_TYPE, "application/json".parse()?);
        let req_body = format!(
            r#"{{"username": "{}", "password": "{}"}}"#,
            username, password
        );

        // Send request.
        let resp = tls_client
            .post(&req_url)
            .headers(req_headers)
            .body(req_body)
            .send()
            .expect("Request failed");

        if resp.status() != 200 {
            return Err(anyhow!(
                "Failed to retrieve bearer token, Error: {:?}",
                resp.status()
            ));
        }

        // Read bearer token from response.
        let bearer_token: String = resp.text().expect("Failed to read bearer token");
        Ok(bearer_token)
    }

    /// Creates a default TLS client, which expects a connection using the provided ITA KBS cert.
    ///
    /// # Returns
    ///
    /// * `Result<Client>` - A result containing the configured client.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The certificate file cannot be read.
    /// - The certificate cannot be parsed from the PEM format.
    fn default_tls_client(&self) -> Client {
        // Setup a TLS client that enforces the expected KBS certificate.
        // We exclude the build in root certificates to ensure that only the provided KBS certificate is accepted.
        Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(self.kbs_cert.clone())
            .min_tls_version(Version::TLS_1_2)
            .build()
            .expect("Failed to build client")
    }

    fn create_key_transfer_policy(&self, params: KeyTransferPolicyParams) -> Result<String> {
        // Create key transfer policy creation request.
        let req_url = format!("{}/kbs/v1/key-transfer-policies", self.kbs_url);
        let mut req_headers = HeaderMap::new();
        req_headers.insert(ACCEPT, "application/json".parse()?);
        req_headers.insert(CONTENT_TYPE, "application/json".parse()?);
        req_headers.insert("Authorization", format!("Bearer {}", params.bearer_token).parse()?);
        let req_body = format!(
            r#"{{
                "attestation_type": "TDX",
                "tdx": {{
                    "attributes": {{
                        "mrseam": ["{}"],
                        "mrsignerseam": ["{}"],
                        "seamsvn": {},
                        "mrtd": ["{}"],
                        "rtmr1": "{}",
                        "rtmr2": "{}",
                        "rtmr3": "{}",
                        "enforce_tcb_upto_date": false
                    }}
                }}
            }}"#,
            params.mrseam,
            params.mrsignerseam,
            params.seamsvn,
            params.mrtd,
            params.rtmr1,
            params.rtmr2,
            params.rtmr3
        );

        // Send key transfer policy creation request.
        let tls_client = self.default_tls_client();
        let resp = tls_client
            .post(&req_url)
            .headers(req_headers)
            .body(req_body)
            .send()
            .expect("Request failed");
        if resp.status() != 201 {
            return Err(anyhow!(
                "Failed to create key transfer policy, Error: {:?}",
                resp.status()
            ));
        }

        // Read ID of created key transfer policy.
        let res_json: Value = resp.json().expect("Failed to parse response");
        let policy_id = res_json["id"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to parse policy ID from response"))?
            .to_string();

        Ok(policy_id)
    }
}

impl KBS for ItaKbs {
    fn create_k_rfs(&self, bearer_token: &str, quote: &Quote) -> Result<String> {
        // Extract values from the Quote object
        let (mrseam, mrsignerseam, seamsvn, mrtd, rtmr1, rtmr2, rtmr3) = match quote {
            Quote::V4(q) => (
                hex::encode(q.report_body.mr_seam.m),
                hex::encode(q.report_body.mrsigner_seam.m),
                q.get_intel_tdx_module_version(),
                hex::encode(q.report_body.mr_td.m),
                hex::encode(q.report_body.rt_mr[1].m),
                hex::encode(q.report_body.rt_mr[2].m),
                hex::encode(q.report_body.rt_mr[3].m),
            ),
        };

        // Create key transfer policy and retrieve its ID.
        let policy_params = KeyTransferPolicyParams {
            bearer_token: bearer_token.to_string(),
            mrseam,
            mrsignerseam,
            seamsvn,
            mrtd,
            rtmr1,
            rtmr2,
            rtmr3,
        };
        let policy_id = self.create_key_transfer_policy(policy_params)
            .expect("Cannot create key transfer policy");

        // Trigger generation of root file system key (k_rfs).
        let tls_client = self.default_tls_client();
        let req_url = format!("{}/kbs/v1/keys", self.kbs_url);
        let mut req_headers = HeaderMap::new();
        req_headers.insert(ACCEPT, "application/json".parse()?);
        req_headers.insert(CONTENT_TYPE, "application/json".parse()?);
        req_headers.insert("Authorization", format!("Bearer {}", bearer_token).parse()?);
        let req_body = format!(
            r#"{{
                "key_information": {{ "algorithm":"{}", "key_length":{} }},
                "transfer_policy_id" : "{}"
            }}"#,
            K_RFS_ALGO,
            K_RFS_BIT_LENGTH,
            policy_id
        );

        // Send request.
        let resp = tls_client
            .post(&req_url)
            .headers(req_headers)
            .body(req_body)
            .send()
            .expect("Request failed");

        if resp.status() != 201 {
            return Err(anyhow!(
                "Failed to create key, Error: {:?}",
                resp.status()
            ));
        }

        // Read ID of root file system key (k_rfs).
        let res_json: Value = resp.json().expect("Failed to parse response");
        let k_rfs_id = res_json["id"]
            .as_str()
            .expect("Failed to parse key ID from response")
            .to_string();

        Ok(k_rfs_id)
    }

    fn retrieve_k_rfs(&self, req_body: String, sk_kr: RsaPrivateKey, id_k_rfs: String) -> Result<Vec<u8>> {
        // Create fde key retrieval request.
        let tls_client = self.default_tls_client();
        let req_url = format!("{}/kbs/v1/keys/{}/transfer", &self.kbs_url, id_k_rfs);
        let mut req_headers = HeaderMap::new();
        req_headers.insert(ACCEPT, "application/json".parse()?);
        req_headers.insert(CONTENT_TYPE, "application/json".parse()?);
        req_headers.insert("Attestation-type", "TDX".parse()?);

        // Send fde key retrieval request.
        let resp = tls_client
            .post(&req_url)
            .headers(req_headers)
            .body(req_body)
            .send()
            .expect("Request failed");

        if resp.status() != 200 {
            return Err(anyhow!(
                "Get key request failed, Error: {:?}",
                resp.status()
            ));
        }

        // Read wrapped keys from response.
        let res_json: Value = resp.json().expect("Failed to parse response");
        let wrapped_k_rfs = BASE64_STANDARD.decode(res_json["wrapped_key"].as_str().unwrap())?;
        let wrapped_k_rfs_bytes = wrapped_k_rfs.as_slice();
        let wrapped_k_swk = BASE64_STANDARD.decode(res_json["wrapped_swk"].as_str().unwrap())?;
        let wrapped_k_swk_bytes = wrapped_k_swk.as_slice();

        // Decrypt the wrapped key SWK using the private key SK_KR.
        let padding = Oaep::new::<Sha256>();
        let k_swk = sk_kr
            .decrypt(padding, wrapped_k_swk_bytes)
            .expect("Failed to decrypt wrapped k_swk");
        let k_swk_bytes = GenericArray::from_slice(&k_swk);

        // Decrypt the wrapped key RFS using the key SWK.
        const NONCE_LEN: usize = 12;
        const KBS_PADDING: usize = 12;
        let cipher = Aes256Gcm::new(k_swk_bytes);
        let wrapped_k_rfs_nonce = GenericArray::from_slice(&wrapped_k_rfs_bytes[KBS_PADDING..KBS_PADDING+NONCE_LEN]);
        let wrapped_k_rfs_ciphertext = &wrapped_k_rfs_bytes[KBS_PADDING+NONCE_LEN..];
        let k_rfs = cipher
            .decrypt(wrapped_k_rfs_nonce, wrapped_k_rfs_ciphertext)
            .expect("Failed to decrypt wrapped k_rfs");

        // Check for expected key length.
        let k_rfs_bits = k_rfs.len() * std::mem::size_of::<u8>() * 8;
        if k_rfs_bits != K_RFS_BIT_LENGTH {
            panic!("Length of k_rfs is not as expected");
        }

        Ok(k_rfs)
    }
}
