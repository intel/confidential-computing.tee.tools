# Security Policy
Intel is committed to rapidly addressing security vulnerabilities affecting our customers and providing clear guidance on the solution, impact, severity and mitigation.

## Reporting a Vulnerability
Please report any security vulnerabilities in this project utilizing the guidelines [here](https://www.intel.com/content/www/us/en/security-center/vulnerability-handling-guidelines.html).

## Full Disk Encryption Solution

This repository contains a functional reference demonstrating a Full Disk Encryption (FDE) solution.
The following sub-sections are about this FDE solution.

### Security Considerations

The setup instructions in the `README.md` are for **development, testing, and demo purposes ONLY**.
For a production setup, please apply appropriate security measures.

The secure management of cryptographic keys, certificates, and other secrets is a critical user responsibility and is **out of scope** for this solution's setup guide.
The methods shown, such as storing keys as plaintext files or using environment variables, are for convenience in a development setting and are not representative of a secure production deployment.

Users are responsible for securing sensitive assets, including but not limited to:
- **Private Keys**: `sk_kr.pem`
- **Secrets**: `VAULT_ROOT_TOKEN`, `tmp_k_rfs`, `k_rfs`
- **Certificates**: `tls.crt`

Users should evaluate security, performance, and suitability requirements before deployment.

### Suggestions for Production Environments

For users planning to build a production system based on this solution, we strongly recommend implementing security best practices, including but not limited to:

- Key generation and provisioning **must be done in secure facility** to ensure security of the key(s) is not compromised.
- **Avoid storing secrets in environment variables**.
    Instead, use secure device provisioning solutions (e.g., Kubernetes Secrets, Docker Secrets, and HSMs) or fetch them from a Key Management Service (KMS) at runtime.
- Use **TLS certificates issued by a trusted internal or public Certificate Authority (CA)** instead of self-signed certificates.
- Run all third-party services, such as **HashiCorp Vault**, in a production-hardened configuration.
    This includes using persistent storage, enabling TLS, configuring proper authentication and authorization policies, and complying to license requirements.
- Current configuration is not PQC ready and the customer must do their due diligence for PQC security needs.
- Adhere to applicable cryptographic standards, such as those mandated by NIST and FIPS.
- Conduct a comprehensive threat assessment to identify and implement necessary security mitigations.
- Carry out robust security validation to ensure all security requirements are thoroughly tested.
