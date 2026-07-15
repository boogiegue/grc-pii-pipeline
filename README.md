# grc-pii-pipeline
This lightweight, dependency-free script simulates receiving a customer or client payload, auditing it for GDPR residency restrictions, masking sensitive PII (Personally Identifiable Information) using SHA-256 hashing and regex, and routing it to a secure database.
# Secure GRC Data-Routing Pipeline

An enterprise-grade Python data routing engine designed to automate GRC (Governance, Risk, and Compliance) compliance, protect user privacy, and secure high-throughput data streams.

## Technical Highlights & TPM Architecture

*   **GDPR & HIPAA Compliance Routing:** Automatically audits incoming payloads based on country codes and routes EU-resident data to localized secure database structures to enforce strict data residency laws.
*   **Cryptographic PII Protection:** Automatically masks sensitive email strings and secures user IDs using salted SHA-256 cryptographic hashing to defeat rainbow table and brute-force attacks.
*   **System Resilience (Dead Letter Queue):** Employs a robust error-handling architecture to capture, tag, and quarantine malformed JSON payloads or missing schemas into a Dead Letter Queue (DLQ) without crashing the main pipeline.
*   **Feature Flag Staged Rollouts:** Implements conditional routing logic to gracefully geoblock or defer traffic when specific downstream infrastructure nodes are offline, eliminating compliance risk during phased deployments.

## How to Run Locally

```bash
python secure_router.py