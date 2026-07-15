import re
import json
import hashlib
import logging
import os
from datetime import datetime

# Setup professional structured logging for audit trails
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [SECURE-ROUTER] - %(levelname)s - %(message)s'
)

class SecureDataRouter:
    def __init__(self):
        # EU Country Codes for GDPR compliance routing
        self.eu_countries = {"AT", "BE", "FR", "DE", "IE", "IT", "NL", "ES", "SE"} 
        self.email_regex = r'[\w\.-]+@[\w\.-]+\.\w+'
        
        # ---------------------------------------------------------
        # ENTERPRISE UPGRADES INITIALIZED HERE
        # ---------------------------------------------------------
        # 1. Cryptographic Salt (Simulating a secure environment variable)
        self.salt = os.getenv("SECURE_SALT", "tpm_enterprise_salt_2026")
        
        # 2. Dead Letter Queue (DLQ) memory buffer for failed payloads
        self.dead_letter_queue = []
        
        # 3. Feature Flag: EU Database is currently delayed
        self.feature_flag_eu_db_ready = False 

    def _send_to_dlq(self, raw_data, reason: str) -> dict:
        """Quarantine bad payloads without crashing the main application pipeline."""
        quarantine_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error_reason": reason,
            "payload": raw_data
        }
        self.dead_letter_queue.append(quarantine_record)
        logging.error(f"Payload routed to DLQ. Reason: {reason}")
        return {"status": "QUARANTINED", "reason": reason}

    def _hash_pii(self, value: str) -> str:
        """Pseudonymize using SHA-256 AND a cryptographic salt to defeat rainbow tables."""
        if not value:
            return ""
        # Append the secret salt to the user ID before hashing
        salted_value = str(value).strip().lower() + self.salt
        return hashlib.sha256(salted_value.encode('utf-8')).hexdigest()

    def _mask_email(self, email: str) -> str:
        """Mask local email parts while preserving domain architecture."""
        if not re.match(self.email_regex, email):
            return "[INVALID_EMAIL_FORMAT]"
        
        local_part, domain = email.split('@', 1)
        if len(local_part) > 2:
            masked_local = f"{local_part[0]}{'*' * (len(local_part) - 2)}{local_part[-1]}"
        else:
            masked_local = "**"
        return f"{masked_local}@{domain}"

    def process_payload(self, raw_json: str) -> dict:
        """Validate, clean, protect, and route incoming data payloads."""
        # --- DLQ UPGRADE: Graceful Error Handling ---
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError:
            return self._send_to_dlq(raw_json, "Invalid JSON format")

        required_fields = {"user_id", "email", "country_code", "ip_address"}
        if not required_fields.issubset(payload.keys()):
            missing = required_fields - payload.keys()
            return self._send_to_dlq(raw_json, f"Missing critical schema fields: {missing}")

        processed_data = payload.copy()
        
        # 1. GDPR Audit Control: Check data residency
        country = processed_data["country_code"].upper()
        is_eu_resident = country in self.eu_countries
        processed_data["gdpr_scope"] = is_eu_resident

        # --- FEATURE FLAG UPGRADE: Staged Rollout ---
        if is_eu_resident and not self.feature_flag_eu_db_ready:
            return self._send_to_dlq(
                raw_json, 
                "GEO-BLOCK: EU database infrastructure not ready. Registration deferred."
            )

        # 2. PII Sanitization (Now using Salted Hash)
        processed_data["raw_email"] = processed_data["email"] 
        processed_data["email"] = self._mask_email(processed_data["email"])
        processed_data["user_id_hash"] = self._hash_pii(processed_data["user_id"])
        
        del processed_data["user_id"]

        # 3. Secure Routing Destination Determination
        if is_eu_resident:
            processed_data["target_db"] = "DB_EU_FRANKFURT_VAULT"
            del processed_data["raw_email"]
            logging.info("GDPR Route Triggered. Payload routed to EU Frankfurt Vault.")
        else:
            processed_data["target_db"] = "DB_US_EAST_STANDARD"
            logging.info("Standard Route Triggered. Payload routed to US East Standard.")

        processed_data["processed_at"] = datetime.utcnow().isoformat() + "Z"
        processed_data["status"] = "SUCCESS"
        return processed_data


# --- LOCAL TEST EXECUTION ---
if __name__ == "__main__":
    router = SecureDataRouter()

    # Payload 1: Standard US Client (Should Succeed)
    us_data = '{"user_id": 11204, "email": "hiring_manager@cisco.com", "country_code": "US", "ip_address": "10.0.0.12"}'
    
    # Payload 2: EU Client (Should hit the Feature Flag & route to DLQ)
    eu_data = '{"user_id": 98452, "email": "isaac@uconn.edu", "country_code": "FR", "ip_address": "192.168.1.50"}'
    
    # Payload 3: Hacker/Malformed Data (Should hit the DLQ safely)
    bad_data = '{"user_id": 9999, "email": "hacker@evil.com"}' # Missing fields

    print("\n--- 1. PROCESSING US DATA ---")
    print(json.dumps(router.process_payload(us_data), indent=2))
    
    print("\n--- 2. PROCESSING EU DATA (Feature Flag OFF) ---")
    print(json.dumps(router.process_payload(eu_data), indent=2))
    
    print("\n--- 3. PROCESSING MALFORMED DATA ---")
    print(json.dumps(router.process_payload(bad_data), indent=2))

    print("\n--- DEAD LETTER QUEUE (DLQ) CONTENTS ---")
    print(json.dumps(router.dead_letter_queue, indent=2))