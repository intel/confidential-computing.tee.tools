// Copyright (C) 2025 - 2026 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Result};
use std::fs;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair, EdDSAKeyPairLike};
use kbs_protocol::ResourceUri;
use kbs_protocol::evidence_provider::NativeEvidenceProvider;
use kbs_protocol::KbsClientBuilder;
use kbs_protocol::KbsClientCapabilities;
use serde::Serialize;

use crate::quote::Quote;
use crate::disk::K_RFS_BIT_LENGTH;

pub trait KBSClient {
    // Send root filesystem encryption key to KBS, which will use KMS for storage.
    fn store_k_rfs(&self, k_rfs: &str, sk_kbs_admin: &str, quote: &Quote, k_rfs_id: &str) -> Result<()>;
    // Retrieve root filesystem encryption key from KBS.
    fn retrieve_k_rfs(&self, kbs_k_rfs_id: String) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

pub struct TrusteeKbsClient {
    kbs_url: String,
    kbs_cert: String,
}

/// Parameters for resource policy creation.
///
/// These parameters are used to create a resource policy in the Trustee KBS.
/// The struct contains all measurement values from the quote that are required for attestation-based key release.
#[derive(Debug, Clone)]
struct TrusteeResourcePolicy {
    /// Measurement of Intel TDX Module
    mrseam: String,
    /// The measurement of the signing key used for the Intel TDX Module.
    mrsignerseam: String,
    /// SVN of Intel TDX Module (as combination of major and minor)
    seamsvn: String,
    /// Measurement of the initial contents of the TD
    mrtd: String,
    /// Runtime measurement register 0
    rtmr0: String,
    /// Runtime measurement register 1
    rtmr1: String,
    /// Runtime measurement register 3
    rtmr3: String,
}

/// Request body for setting a resource policy in KBS.
///
/// This struct is used to set resource policy that controls access to resources after attestation succeeds.
#[derive(Clone, Serialize)]
struct ResourcePolicyRequest {
    // The actual policy content as a string.
    pub policy: String,
}

impl TrusteeKbsClient {
    const KBS_URL_PREFIX: &str = "kbs/v0";

    /// Creates a new instance of a Trustee KBS Client.
    ///
    /// # Parameters
    ///
    /// - `kbs_url`: The URL of the KBS.
    /// - `kbs_cert_path`: The file path to the KBS certificate.
    ///
    /// # Returns
    ///
    /// * `Result<Self>` - A result containing the new instance of a Trustee KBS Client.
    pub fn new(kbs_url: String, kbs_cert_path: String) -> Result<Self> {
        // Try to read KBS certificate file.
        let kbs_cert = fs::read_to_string(&kbs_cert_path)
            .map_err(|e| anyhow!(
                "Failed to read KBS certificate file '{}': {}",
                kbs_cert_path, e
            ))?;

        Ok(Self { kbs_url, kbs_cert })
    }

    /// Create a resource policy for Trustee KBS.
    ///
    /// # Parameters
    ///
    /// - `sk_kbs_admin`: Private key used for administrator access to KBS (in PEM format).
    /// - `params`: TrusteeResourcePolicy struct containing measurement values from the quote.
    /// - `k_rfs_id`: ID for the root filesystem encryption key resource in KBS.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A result indicating success or failure.
    fn create_trustee_resource_policy(&self, sk_kbs_admin: &str, params: TrusteeResourcePolicy, k_rfs_id: &str) -> Result<()> {
        // Concat resource with key id to check the resource path. e.g. "resource/keybroker/key/<key_id>"
        let key_id = format!("resource/{}", k_rfs_id);
        // Create policy in rego format
        let policy_content = format!(
            r#"package policy
                import rego.v1
                default allow = false

                allow if {{
                    data["resource-path"] == "{}"

                    input["submods"]["cpu0"]["ear.trustworthiness-vector"]["hardware"] == 3
                    input["submods"]["cpu0"]["ear.trustworthiness-vector"]["configuration"] == 3

                    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]["rtmr_0"] == "{}"
                    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]["rtmr_1"] == "{}"
                    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]["rtmr_3"] == "{}"
                    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]["mr_seam"] == "{}"
                    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]["mrsigner_seam"] == "{}"
                    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]["mr_td"] == "{}"
                    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]["tcb_svn"] == "{}"
                }}
                "#,
            key_id,
            params.rtmr0,
            params.rtmr1,
            params.rtmr3,
            params.mrseam,
            params.mrsignerseam,
            params.mrtd,
            params.seamsvn
        );

        let kbs_admin_key_pair = Ed25519KeyPair::from_pem(sk_kbs_admin)?;
        let claims = Claims::create(Duration::from_hours(2));
        let token = kbs_admin_key_pair.sign(claims)?;

        // Build HTTPs client for connection to KBS.
        let http_client = self.build_kbs_https_client()?;

        // Prepare API URL for setting a policy in the Key Broker Service.
        let set_policy_url = format!("{}/{}/resource-policy", self.kbs_url, Self::KBS_URL_PREFIX);

        // Prepare request body for setting a policy in the Key Broker Service.
        let policy_data = ResourcePolicyRequest {
            policy: URL_SAFE_NO_PAD.encode(policy_content.as_bytes()), // Base64 URL-safe encoding without padding
        };

        // Send request.
        let res = http_client
            .post(set_policy_url)
            .header("Content-Type", "application/json")
            .bearer_auth(token)
            .json(&policy_data)
            .send()?;

        match res.status() {
            reqwest::StatusCode::OK => {
                println!("Successfully set resource policy in Trustee KBS");
                Ok(())
            }
            status_code => Err(anyhow!(
                "Failed to create resource policy, Status: {}, Error: {}",
                status_code,
                res.text()?
            )),
        }
    }

    /// Create an attestation policy for Trustee KBS.
    ///
    /// # Parameters
    ///
    /// - `sk_kbs_admin`: Private key used for administrator access to KBS (in PEM format).
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A result indicating success or failure.
    fn create_trustee_attestation_policy(&self, sk_kbs_admin: &str) -> Result<()> {

        // Create policy in rego format
        let policy_content = r#"package policy
                import rego.v1

                default hardware := 97
                default configuration := 36

                trust_claims := {
                    "hardware": hardware,
                    "configuration": configuration,
                }

                hardware := 3 if {
                    input.tdx
                    input.tdx.quote.header.tee_type == "81000000"
                    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
                    input.tdx.tcb_status == "UpToDate"
                    input.tdx.collateral_expiration_status == "0"
                }

                configuration := 3 if {
                    input.tdx
                    input.tdx.td_attributes.debug == false
                }"#.to_string();

        let kbs_admin_key_pair = Ed25519KeyPair::from_pem(sk_kbs_admin)?;
        let claims = Claims::create(Duration::from_hours(2));
        let token = kbs_admin_key_pair.sign(claims)?;

        // Build HTTPs client for connection to KBS.
        let http_client = self.build_kbs_https_client()?;

        // Prepare API URL for setting a policy in the Key Broker Service.
        let set_policy_url = format!("{}/{}/attestation-policy", self.kbs_url, Self::KBS_URL_PREFIX);

        // Prepare request body for setting a policy in the Key Broker Service.
        let policy_data = format!(
            r#"{{"type": "{}", "policy": "{}", "policy_id": "{}"}}"#,
            "rego",
            URL_SAFE_NO_PAD.encode(policy_content.as_bytes()), // Base64 URL-safe encoding without padding
            "default_cpu"
            );

        // Send request.
        let res = http_client
            .post(set_policy_url)
            .header("Content-Type", "application/json")
            .bearer_auth(token)
            .body(policy_data)
            .send()?;

        match res.status() {
            reqwest::StatusCode::OK => {
                println!("Successfully set attestation policy in Trustee KBS");
                Ok(())
            }
            status_code => Err(anyhow!(
                "Failed to create attestation policy, Status: {}, Error: {}",
                status_code,
                res.text()?
            )),
        }
    }

    /// Send root filesystem encryption key (k_rfs) to Trustee KBS, which will store it at the location k_rfs_id in the KMS.
    /// Use private key used for administrator access to KBS for this operation.
    ///
    /// # Parameters
    ///
    /// - `k_rfs`: The root filesystem encryption key as a hex string.
    /// - `sk_kbs_admin`: Private key used for administrator access to KBS (in PEM format).
    /// - `k_rfs_id`: ID for the root filesystem encryption key resource in KBS.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A result indicating success or failure.
    fn set_k_rfs(&self, k_rfs: &str, sk_kbs_admin: &str, k_rfs_id: &str) -> Result<()> {
        // Create JWT token for administrator access to KBS.
        let kbs_admin_key_pair = Ed25519KeyPair::from_pem(sk_kbs_admin)?;
        let claims = Claims::create(Duration::from_hours(2));
        let token = kbs_admin_key_pair.sign(claims)?;

        // Build HTTPs client for connection to KBS.
        let http_client = self.build_kbs_https_client()?;

        // Construct URL used to set a resource in KBS.
        let resource_url = format!(
            "{}/{}/resource/{}",
            &self.kbs_url,
            Self::KBS_URL_PREFIX,
            k_rfs_id
        );

        // Send request.
        let res = http_client
            .post(resource_url)
            .header("Content-Type", "application/octet-stream")
            .bearer_auth(token)
            .body(k_rfs.to_string())
            .send()?;

        match res.status() {
            reqwest::StatusCode::OK => {
               println!("Successfully set k_rfs resource in Trustee KBS at location: {}", k_rfs_id);
               Ok(())
            },
            status_code => Err(anyhow!(
                "Failed to store root filesystem encryption key, Status: {}, Error: {}",
                status_code,
                res.text()?
            )),
        }
    }

    /// Get secret resources with attestation
    ///
    /// This method uses the KBS protocol to perform remote attestation and retrieve
    /// a secret resource after successful verification.
    ///
    /// # Parameters
    ///
    /// - `resource_id`: Resource id, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>>` - A result containing the resource bytes retrieved from the KBS.
    async fn get_resource_with_attestation(&self, resource_id: &str) -> Result<Vec<u8>> {
        // Build KBS client with evidence provider
        let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

        // Enforce the usage of the expected KBS certificate.
        let client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, &self.kbs_url)
                .add_kbs_cert(&self.kbs_cert);

        let mut client = client_builder.build()?;

        // ResourceUri is the identification information of all resources that need to be obtained from `get_resource` endpoint.
        // Convert resource id to ResourceUri format.
        let resource_kbs_uri = format!("kbs:///{resource_id}");
        let resource_uri = ResourceUri::try_from(resource_kbs_uri.as_str())
            .map_err(|e| anyhow!("Invalid resource URI '{}': {}", resource_kbs_uri, e))?;

        // Get resource from KBS in a complex process:
        // -  generate a random asymmetric key pair SK_TEE/PK_TEE used for key retrieval from Trustee KBS,
        // -  send an authentication request to Trustee KBS,
        // -  receive a nonce-based challenge from from Trustee KBS,
        // -  request a TD Quote using a hash of the nonce and PK_TEE as report data,
        // -  send the TD Quote, nonce, and PK_TEE to Trustee KBS,
        // -  receive an attestation token from Trustee KBS after quote verification by Attestation Service,
        // -  request resource from Trustee KBS using its ID,
        // -  receive encrypted resource from Trustee KBS,
        // -  decrypt the encrypted resource using SK_TEE.
        let resource_bytes = client.get_resource(resource_uri).await?;
        Ok(resource_bytes)
    }

    /// Build HTTPS client, which enforces the usage of the expected KBS certificate.
    ///
    /// # Returns
    ///
    /// * `Result<reqwest::blocking::Client>` - A result containing the configured client.
    fn build_kbs_https_client(&self) -> Result<reqwest::blocking::Client> {
        let cert = reqwest::Certificate::from_pem(self.kbs_cert.as_bytes())?;

        // Build a TLS client.
        // Enforce the usage of the expected KBS certificate.
        reqwest::blocking::Client::builder()
            .user_agent(format!("fde-agent/{}", env!("CARGO_PKG_VERSION")))
            .add_root_certificate(cert)
            .build()
            .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))
    }
}

impl KBSClient for TrusteeKbsClient {
    /// Send root filesystem encryption key to KBS, which will use KMS for storage.
    ///
    /// # Parameters
    ///
    /// - `k_rfs`: The root filesystem encryption key as a hex string.
    /// - `sk_kbs_admin`: Private key used for administrator access to KBS (in PEM format).
    /// - `quote`: The TD quote used for attestation.
    /// - `k_rfs_id`: ID for the root filesystem encryption key resource in KBS.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A result indicating success or failure.
    fn store_k_rfs(&self, k_rfs: &str, sk_kbs_admin: &str, quote: &Quote, k_rfs_id: &str) -> Result<()> {
        // Extract values from the Quote object
        let (mrseam, mrsignerseam, seamsvn, mrtd, rtmr0, rtmr1, rtmr3) = match quote {
            Quote::V4(q) => (
                hex::encode(q.report_body.mr_seam.m),
                hex::encode(q.report_body.mrsigner_seam.m),
                q.get_intel_tdx_module_version(),
                hex::encode(q.report_body.mr_td.m),
                hex::encode(q.report_body.rt_mr[0].m),
                hex::encode(q.report_body.rt_mr[1].m),
                hex::encode(q.report_body.rt_mr[3].m),
            ),
        };

        // Construct parameters to set resource policy.
        let trustee_resource_policy = TrusteeResourcePolicy {
            mrseam,
            mrsignerseam,
            seamsvn,
            mrtd,
            rtmr0,
            rtmr1,
            rtmr3,
        };

        // Create a resource policy for Trustee KBS.
        self.create_trustee_resource_policy(sk_kbs_admin, trustee_resource_policy, k_rfs_id)?;

        // Create an attestation policy for Trustee KBS.
        self.create_trustee_attestation_policy(sk_kbs_admin)?;

        // Store root filesystem encryption key in Trustee KBS.
        self.set_k_rfs(k_rfs, sk_kbs_admin, k_rfs_id)?;

        Ok(())
    }

    /// Retrieve root filesystem encryption key (k_rfs) after successful attestation.
    ///
    /// # Parameters
    ///
    /// - `kbs_k_rfs_id`: ID for the root filesystem encryption key resource in KBS.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>>` - A result containing the retrieved root filesystem encryption key (k_rfs) as bytes.
    async fn retrieve_k_rfs(&self, kbs_k_rfs_id: String) -> Result<Vec<u8>> {
        // Request root filesystem encryption key (k_rfs).
        let resource_bytes = self.get_resource_with_attestation(&kbs_k_rfs_id).await?;

        // Convert received root filesystem encryption key from bytes to String.
        let hex_string = String::from_utf8(resource_bytes)
            .map_err(|e| anyhow!("Retrieved resource is not valid UTF-8: {}", e))?;

        let k_rfs = hex::decode(hex_string.trim()).map_err(|e| anyhow!("Retrieved key is not valid hex: {}", e))?;

        // Check for expected key length.
        if k_rfs.len() != (K_RFS_BIT_LENGTH / 8) {
            return Err(anyhow!(
                "Length of k_rfs is not as expected: got {}, expected {}",
                k_rfs.len(),
                K_RFS_BIT_LENGTH / 8
            ));
        }

        println!("Successfully retrieved k_rfs from Trustee KBS");
        Ok(k_rfs)
    }
}
