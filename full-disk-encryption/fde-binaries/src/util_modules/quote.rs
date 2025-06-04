// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{anyhow, Ok, Result};
use base64::prelude::*;

/// TEE Attributes structure.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TeeAttributes {
    /// Attributes array.
    pub a: [u32; 2],
}

/// TEE Measurement structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TeeMeasurement {
    /// Measurement array.
    pub m: [u8; 48],
}

/// TEE TCB SVN structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TeeTcbSvn {
    /// TCB SVN array.
    pub tcb_svn: [u8; 16],
}

/// TEE Report Data structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TeeReportData {
    /// Report data array.
    pub d: [u8; 64],
}

/// Quote Header structure for version 4.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Quote4Header {
    /// Quote version.
    pub version: u16,
    /// Attestation key type.
    pub att_key_type: u16,
    /// TEE type.
    pub tee_type: u32,
    /// Reserved field.
    pub reserved: u32,
    /// Vendor ID.
    pub vendor_id: [u8; 16],
    /// User data.
    pub user_data: [u8; 20],
}

/// Report Body structure for version 1.0.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReportBodyV1_0 {
    /// TEE TCB SVN.
    pub tee_tcb_svn: TeeTcbSvn,
    /// Measurement of SEAM module.
    pub mr_seam: TeeMeasurement,
    /// Measurement of SEAM module signer.
    pub mrsigner_seam: TeeMeasurement,
    /// SEAM attributes.
    pub seam_attributes: TeeAttributes,
    /// TD attributes.
    pub td_attributes: TeeAttributes,
    /// XFAM attributes.
    pub xfam: TeeAttributes,
    /// Measurement of TD.
    pub mr_td: TeeMeasurement,
    /// Measurement of configuration ID.
    pub mr_config_id: TeeMeasurement,
    /// Measurement of owner.
    pub mr_owner: TeeMeasurement,
    /// Measurement of owner configuration.
    pub mr_owner_config: TeeMeasurement,
    /// Runtime measurements.
    pub rt_mr: [TeeMeasurement; 4],
    /// Report data.
    pub report_data: TeeReportData,
}

/// Quote structure for version 4.
#[repr(C)]
#[derive(Debug)]
pub struct QuoteV4 {
    /// Quote header.
    pub header: Quote4Header,
    /// Report body.
    pub report_body: ReportBodyV1_0,
    /// Length of signature data.
    pub signature_data_len: u32,
    /// Signature data.
    pub signature_data: Vec<u8>,
    /// Raw quote data.
    raw_quote: Vec<u8>,
}

pub trait QuoteT: Sized {
    /// Creates a TD quote from a byte vector.
    ///
    /// # Parameters
    ///
    /// - `bytes`: A vector of bytes representing a raw TD quote.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` which is:
    /// - `Ok(Self)` containing a TD quote if the operation is successful.
    /// - `Err(anyhow::Error)` if the operation fails, with an error message indicating the failure reason.
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, anyhow::Error>;

    /// Get the raw quote in base64 encoding.
    ///
    /// # Returns
    ///
    /// This function returns a `String` containing the base64 encoded raw quote.
    fn get_raw_base64(&self) -> String;
}

impl QuoteT for QuoteV4 {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, anyhow::Error> {
        if bytes.len() < 632 {
            return Err(anyhow!("Input data is too short to be a valid SgxQuote4"));
        }

        let header = Quote4Header {
            version: u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
            att_key_type: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            tee_type: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            reserved: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            vendor_id: bytes[12..28].try_into().unwrap(),
            user_data: bytes[28..48].try_into().unwrap(),
        };

        let report_body = ReportBodyV1_0 {
            tee_tcb_svn: TeeTcbSvn { tcb_svn: bytes[48..64].try_into().unwrap() },
            mr_seam: TeeMeasurement { m: bytes[64..112].try_into().unwrap() },
            mrsigner_seam: TeeMeasurement { m: bytes[112..160].try_into().unwrap() },
            seam_attributes: TeeAttributes { a: [
                u32::from_le_bytes(bytes[160..164].try_into().unwrap()),
                u32::from_le_bytes(bytes[164..168].try_into().unwrap())
            ] },
            td_attributes: TeeAttributes { a: [
                u32::from_le_bytes(bytes[168..172].try_into().unwrap()),
                u32::from_le_bytes(bytes[172..176].try_into().unwrap())
            ] },
            xfam: TeeAttributes { a: [
                u32::from_le_bytes(bytes[176..180].try_into().unwrap()),
                u32::from_le_bytes(bytes[180..184].try_into().unwrap())
            ] },
            mr_td: TeeMeasurement { m: bytes[184..232].try_into().unwrap() },
            mr_config_id: TeeMeasurement { m: bytes[232..280].try_into().unwrap() },
            mr_owner: TeeMeasurement { m: bytes[280..328].try_into().unwrap() },
            mr_owner_config: TeeMeasurement { m: bytes[328..376].try_into().unwrap() },
            rt_mr: [
                TeeMeasurement { m: bytes[376..424].try_into().unwrap() },
                TeeMeasurement { m: bytes[424..472].try_into().unwrap() },
                TeeMeasurement { m: bytes[472..520].try_into().unwrap() },
                TeeMeasurement { m: bytes[520..568].try_into().unwrap() },
            ],
            report_data: TeeReportData { d: bytes[568..632].try_into().unwrap() },
        };

        let signature_data_len = u32::from_le_bytes(bytes[632..636].try_into().unwrap());

        if bytes.len() < 632 + signature_data_len as usize {
            return Err(anyhow!("Input data is too short to contain the specified signature data size"));
        }

        let signature_data = bytes[636..636 + signature_data_len as usize].to_vec();

        Ok(QuoteV4 {
            header,
            report_body,
            signature_data_len,
            signature_data,
            raw_quote: bytes, // Store the raw quote
        })
    }

    /// Get the raw quote in base64 encoding.
    fn get_raw_base64(&self) -> String {
        BASE64_STANDARD.encode(&self.raw_quote)
    }
}

impl QuoteV4 {
    /// Get the SEAM version from the TEE TCB SVN.
    ///
    /// # Returns
    ///
    /// This function returns a `String` representing the SEAM version
    pub fn get_intel_tdx_module_version(&self) -> String {
        let tcb_svn = &self.report_body.tee_tcb_svn.tcb_svn;

        let seam_minor_version = tcb_svn[0];
        let seam_major_version = tcb_svn[1];

        let seam_version = (seam_major_version as u16 * 256) + seam_minor_version as u16;
        seam_version.to_string()
    }
}

pub enum Quote {
    V4(QuoteV4),
}

impl Quote {
    /// Retrieve TD quote from the TD.
    ///
    /// This function interacts with the Intel TDX DCAP library to retrieve a TD quote that cryptographically binds the provided report data.
    /// The quote can be used for attestation purposes.
    ///
    /// # Parameters
    ///
    /// - `tdx_report_data`: Contains the report data that the caller wants to cryptographically bind to the TD quote, e.g., a hash.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` which is:
    /// - `Ok(Vec<u8>)` containing the quote bytes if the operation is successful.
    /// - `Err(anyhow::Error)` if the operation fails, with an error message indicating the failure reason.
    ///
    /// # Errors
    ///
    /// This function will return an error if the attestation library fails to generate the quote.
    /// The error message will indicate that the quote retrieval has failed.
    pub fn retrieve_quote(tdx_report_data: &tdx_attest_rs::tdx_report_data_t) -> Result<Self> {
        // Retrieve quote with provided report data.
        // A list of attestation key IDs is not provided resulting in the usage of the default attestation key ID, which will be returned in selected_att_key_id.
        let mut selected_att_key_id = tdx_attest_rs::tdx_uuid_t { d: [0; 16usize] };
        let (result, quote) = tdx_attest_rs::tdx_att_get_quote(
            Some(tdx_report_data),
            None,
            Some(&mut selected_att_key_id),
            0,
        );

        // Check that TD quote generation was a success.
        if result != tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS {
            return Err(anyhow!("Failed to get the quote."));
        }

        // Unwrap quote content or fail gracefully on error.
        let quote_bytes = quote.expect("Failed to parse the quote");

        // Return TD quote as object.
        Quote::from_bytes(quote_bytes).map_err(|e| anyhow!(e))
    }

    fn from_bytes(bytes: Vec<u8>) -> Result<Self, anyhow::Error> {
        if bytes.len() < 2 {
            return Err(anyhow!("Input data is too short to determine the quote version"));
        }

        let version = u16::from_le_bytes(bytes[0..2].try_into().unwrap());

        match version {
            4 => Ok(Quote::V4(QuoteV4::from_bytes(bytes)?)),
            _ => Err(anyhow!("Unsupported Quote version: {}", version)),
        }
    }

    /// Creates a TD quote from a base64 encoded string.
    ///
    /// # Parameters
    ///
    /// - `b64`: A base64 encoded string representing a TD quote.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` which is:
    /// - `Ok(Self)` containing a TD quote if the operation is successful.
    /// - `Err(anyhow::Error)` if the operation fails, with an error message indicating the failure reason.
    pub fn from_b64(b64: &str) -> Result<Self, anyhow::Error> {
        let bytes = BASE64_STANDARD.decode(b64).map_err(|e| anyhow!("Failed to decode base64: {}", e))?;
        Self::from_bytes(bytes)
    }

    /// Get the raw quote in base64 encoding.
    ///
    /// # Returns
    ///
    /// This function returns an `Option<String>` containing the base64 encoded raw quote if available.
    pub fn get_raw_base64(&self) -> Option<String> {
        match self {
            Quote::V4(quote) => Some(quote.get_raw_base64()),
        }
    }
}

use std::convert::TryInto;
