/**
 * Privatiser — Browser-native content anonymizer.
 * Ports the Python anonymization engine to JavaScript.
 */

// === Category Definitions ===
const CATEGORY_GROUPS = {
  secrets: ["secret"],
  network: ["ip", "domain", "email", "mac", "url"],
  pii: ["phone", "credit_card", "ssn", "passport", "iban"],
  aws: ["account", "arn", "bucket"],
  cloud: ["cloud"],
  identifiers: ["uuid", "identifier"],
};

const DEFAULT_ENABLED_CATEGORIES = {
  secrets: true,
  network: true,
  pii: true,
  aws: true,
  cloud: true,
  identifiers: true,
};

// === Pattern Definitions ===

const SKIP_IPS = new Set(["0.0.0.0", "127.0.0.1", "255.255.255.255", "::1", "::"]);

const SKIP_DOMAINS = new Set([
  "amazonaws.com", "aws.amazon.com", "azure.com",
  "googleapis.com", "google.com", "cloudflare.com",
  "terraform.io", "hashicorp.com", "github.com",
  "docker.io", "docker.com", "gcr.io", "ghcr.io",
  "example.com", "example.org", "example.net",
  "googleusercontent.com",
]);

function luhnCheck(numStr) {
  const digits = numStr.replace(/\D/g, "").split("").map(Number);
  if (digits.length < 13) return false;
  let sum = 0;
  for (let i = digits.length - 1, alt = false; i >= 0; i--, alt = !alt) {
    let d = digits[i];
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

const PATTERNS = [
  // Connection strings
  {
    name: "connection_string",
    category: "secret",
    confidence: "high",
    regex: /(mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp):\/\/[^\s"'`\]}>)]+/gi,
    pseudonym: (n) => `REDACTED_CONNSTR_${n}`,
  },
  // Hex secrets (32-64 char hex in key/secret context)
  {
    name: "hex_secret",
    category: "secret",
    confidence: "medium",
    regex: /((?:webhook_secret|signing_secret|secret_key|hmac_key|encryption_key|hash_key)\s*[=:]\s*["']?)([a-fA-F0-9]{32,64})["']?/gi,
    pseudonym: (n) => `REDACTED_HEX_${n}`,
    hasPrefix: true,
  },
  // JWT tokens
  {
    name: "jwt",
    category: "secret",
    confidence: "high",
    regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    pseudonym: (n) => `REDACTED_JWT_${n}`,
  },
  // Bearer tokens
  {
    name: "bearer_token",
    category: "secret",
    confidence: "high",
    regex: /((?:Authorization:\s*)?Bearer\s+)([a-zA-Z0-9._\-+/=]{20,})/gi,
    pseudonym: (n) => `REDACTED_BEARER_${n}`,
    hasPrefix: true,
  },
  // SSH public keys
  {
    name: "ssh_public_key",
    category: "secret",
    confidence: "high",
    regex: /(ssh-(?:rsa|ed25519|ecdsa|dsa))\s+(AAAA[0-9A-Za-z+/]+={0,2})/g,
    pseudonym: (n) => `REDACTED_SSH_KEY_${n}`,
    hasPrefix: true,
    prefixFromGroup1: true,
  },
  // PEM/PGP armored blocks. Backreference ties BEGIN/END labels together so
  // this covers RSA/EC/OPENSSH private keys *and* PGP PRIVATE KEY BLOCK /
  // PUBLIC KEY BLOCK / MESSAGE / SIGNATURE, which don't end in "KEY-----".
  {
    name: "pem_key",
    category: "secret",
    confidence: "high",
    regex: /-----BEGIN([A-Z ]+)-----[\s\S]*?-----END\1-----/g,
    pseudonym: (n) => `REDACTED_PEM_KEY_${n}`,
  },
  // Specific API key formats (with or without quotes)
  {
    name: "api_key",
    category: "secret",
    confidence: "high",
    regex: /\b(?:AKIA[0-9A-Z]{16}|sk-ant-[a-zA-Z0-9\-_]{20,}|sk-proj-[a-zA-Z0-9\-_]{20,}|sk-[a-zA-Z0-9\-_]{20,}|AIza[a-zA-Z0-9\-_]{20,}|gsk_[a-zA-Z0-9]{20,}|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[0-9\-a-zA-Z]{20,}|hf_[a-zA-Z0-9]{20,})\b/g,
    pseudonym: (n) => `REDACTED_SECRET_${n}`,
  },
  // Sentry DSN: embeds a project API key directly in a URL, near-universal
  // in any error-tracking config someone would paste for debugging.
  {
    name: "sentry_dsn",
    category: "secret",
    confidence: "high",
    regex: /https:\/\/[a-f0-9]{32}@(?:o\d+\.)?ingest(?:\.[a-z]{2})?\.sentry\.io\/\d+/g,
    pseudonym: (n) => `https://REDACTED_SENTRY_DSN_${n}@ingest.sentry.io/0`,
  },
  // Azure subscription IDs
  {
    name: "azure_subscription",
    category: "cloud",
    confidence: "medium",
    regex: /(\/subscriptions\/)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/g,
    pseudonym: (n) => `00000000-0000-4000-a000-${String(n).padStart(12, "0")}`,
    hasPrefix: true,
  },
  // ARNs
  {
    name: "arn",
    category: "arn",
    confidence: "high",
    regex: /arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"'`\]}>),$]+/g,
    pseudonym: null, // handled specially
  },
  // GCP project IDs
  {
    name: "gcp_project",
    category: "cloud",
    confidence: "medium",
    regex: /(projects\/)([a-z][a-z0-9\-]{4,28}[a-z0-9])/g,
    pseudonym: (n) => `redacted-project-${n}`,
    hasPrefix: true,
  },
  // S3 bucket names
  {
    name: "s3_bucket",
    category: "bucket",
    confidence: "medium",
    regex: /(s3:\/\/|s3:::)([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])/g,
    pseudonym: (n) => `redacted-bucket-${n}`,
    hasPrefix: true,
  },
  // AWS Account IDs
  {
    name: "aws_account_id",
    category: "account",
    confidence: "medium",
    regex: /([:"/])(\d{12})(?=[:/"\s])/g,
    pseudonym: (n) => `${100000000000 + n}`,
    hasPrefix: true,
  },
  // Private/internal URLs with ports
  {
    name: "private_url",
    category: "url",
    confidence: "low",
    regex: /https?:\/\/[a-zA-Z0-9.\-]+:[1-9]\d{2,4}(?:\/[^\s"'`\]}>)]*)?\b/g,
    pseudonym: (n) => `http://redacted-internal-${n}.local:8080`,
  },
  // Generic secrets: password/secret/token = "value" (quoted)
  {
    name: "generic_secret",
    category: "secret",
    confidence: "low",
    regex: /((?:password|passwd|pwd|pass|passphrase|passkey|secret|secret_key|secretkey|api_key|apikey|api_secret|apisecret|api_token|apitoken|token|auth_token|authtoken|access_token|accesstoken|refresh_token|refreshtoken|bearer_token|session_token|sessiontoken|access_key|accesskey|access_key_id|secret_access_key|private_key|privatekey|public_key|publickey|client_secret|clientsecret|client_id|clientid|client_key|app_secret|appsecret|app_key|appkey|consumer_key|consumer_secret|signing_key|signing_secret|encryption_key|encryptionkey|decrypt_key|master_key|masterkey|master_secret|master_password|root_password|admin_password|admin_key|db_password|db_pass|database_password|database_pass|mysql_password|mysql_pwd|postgres_password|pgpassword|mongo_password|redis_password|redis_auth|auth_key|authkey|auth_secret|webhook_secret|webhook_key|signing_secret|hmac_key|hmac_secret|jwt_secret|jwt_key|session_secret|cookie_secret|csrf_secret|csrf_token|xsrf_token|oauth_token|oauth_secret|oauth_key|ssh_key|ssh_passphrase|gpg_passphrase|ssl_password|tls_password|keystore_password|truststore_password|cert_password|certificate_password|pfx_password|p12_password|smtp_password|ftp_password|proxy_password|vpn_password|wifi_password|login_password|user_password|account_password|credentials|creds|credential|service_key|service_account_key|deploy_key|deploy_token|ci_token|npm_token|nuget_key|pypi_token|docker_password|registry_password|vault_token|consul_token|nomad_token|encryption_password|decryption_key|pin|pincode|pin_code|security_code|verification_code|otp|one_time_password|mfa_secret|totp_secret|2fa_secret|recovery_key|backup_key|license_key|licensekey|licence_key|activation_key|product_key|serial_key|registration_key)\s*(?:[=:]|is|are|was|were|will be|would be|should be|shall be|is set to|is set as|set to|set as|equals)\s*["'])([^"']{4,500})(?=["'])/gi,
    pseudonym: (n) => `REDACTED_SECRET_${n}`,
    hasPrefix: true,
  },
  // Generic secrets: password/secret/token = value (unquoted)
  {
    name: "generic_secret_unquoted",
    category: "secret",
    confidence: "low",
    regex: /((?:password|passwd|pwd|pass|passphrase|passkey|secret|secret_key|secretkey|api_key|apikey|api_secret|apisecret|api_token|apitoken|token|auth_token|authtoken|access_token|accesstoken|refresh_token|refreshtoken|bearer_token|session_token|sessiontoken|access_key|accesskey|access_key_id|secret_access_key|private_key|privatekey|public_key|publickey|client_secret|clientsecret|client_id|clientid|client_key|app_secret|appsecret|app_key|appkey|consumer_key|consumer_secret|signing_key|signing_secret|encryption_key|encryptionkey|decrypt_key|master_key|masterkey|master_secret|master_password|root_password|admin_password|admin_key|db_password|db_pass|database_password|database_pass|mysql_password|mysql_pwd|postgres_password|pgpassword|mongo_password|redis_password|redis_auth|auth_key|authkey|auth_secret|webhook_secret|webhook_key|signing_secret|hmac_key|hmac_secret|jwt_secret|jwt_key|session_secret|cookie_secret|csrf_secret|csrf_token|xsrf_token|oauth_token|oauth_secret|oauth_key|ssh_key|ssh_passphrase|gpg_passphrase|ssl_password|tls_password|keystore_password|truststore_password|cert_password|certificate_password|pfx_password|p12_password|smtp_password|ftp_password|proxy_password|vpn_password|wifi_password|login_password|user_password|account_password|credentials|creds|credential|service_key|service_account_key|deploy_key|deploy_token|ci_token|npm_token|nuget_key|pypi_token|docker_password|registry_password|vault_token|consul_token|nomad_token|encryption_password|decryption_key|pin|pincode|pin_code|security_code|verification_code|otp|one_time_password|mfa_secret|totp_secret|2fa_secret|recovery_key|backup_key|license_key|licensekey|licence_key|activation_key|product_key|serial_key|registration_key)\s*(?:[=:]|is|are|was|were|will be|would be|should be|shall be|is set to|is set as|set to|set as|equals)\s*)([^\s"']{4,500})/gi,
    pseudonym: (n) => `REDACTED_SECRET_${n}`,
    hasPrefix: true,
  },
  // US SSN
  {
    name: "ssn",
    category: "ssn",
    confidence: "high",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    pseudonym: (n) => `078-05-${String(n).padStart(4, "0")}`,
    validator: (match) => {
      const area = parseInt(match.substring(0, 3));
      return area !== 0 && area !== 666 && area < 900;
    },
  },
  // US phone numbers
  {
    name: "phone_us",
    category: "phone",
    confidence: "medium",
    regex: /(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]\d{3}[-.\s]?\d{4}(?!\d)/g,
    pseudonym: (n) => `(555) 000-${String(n).padStart(4, "0")}`,
  },
  // UK phone numbers
  {
    name: "phone_uk",
    category: "phone",
    confidence: "medium",
    regex: /\+44[-.\s]?\d{4}[-.\s]?\d{6}(?!\d)/g,
    pseudonym: (n) => `+44 7700 900${String(n).padStart(3, "0")}`,
  },
  // Credit cards (Luhn validated)
  {
    name: "credit_card",
    category: "credit_card",
    confidence: "high",
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    pseudonym: (n) => `4000-0000-0000-${String(n).padStart(4, "0")}`,
    validator: (match) => luhnCheck(match),
  },
  // MAC addresses
  {
    name: "mac_address",
    category: "mac",
    confidence: "high",
    regex: /\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
    pseudonym: (n) => `AA:BB:CC:00:00:${(n % 256).toString(16).toUpperCase().padStart(2, "0")}`,
  },
  // Email
  {
    name: "email",
    category: "email",
    confidence: "medium",
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    pseudonym: (n) => `user-${n}@redacted.example.net`,
  },
  // UUIDs
  {
    name: "uuid",
    category: "uuid",
    confidence: "medium",
    regex: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    pseudonym: (n) => `00000000-0000-4000-a000-${String(n).padStart(12, "0")}`,
  },
  // IPv4 with optional CIDR
  {
    name: "ipv4",
    category: "ip",
    confidence: "medium",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/\d{1,2})?\b/g,
    pseudonym: (n) => `10.${Math.floor(n / 256) % 256}.${n % 256}.${((n * 7) % 254) + 1}`,
    validator: (match) => {
      const ip = match.includes("/") ? match.split("/")[0] : match;
      return !SKIP_IPS.has(ip);
    },
  },
  // Domain names
  {
    name: "domain",
    category: "domain",
    confidence: "low",
    regex: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}(?:com|org|net|io|dev|co|app|cloud|internal|local|corp)\b/g,
    pseudonym: (n) => `redacted-host-${n}.example.net`,
    validator: (match) => {
      for (const skip of SKIP_DOMAINS) {
        if (match.endsWith(skip) || match === skip) return false;
      }
      return true;
    },
  },
  // Passport (US)
  {
    name: "passport",
    category: "passport",
    confidence: "medium",
    regex: /\b[A-Z]\d{8}\b/g,
    pseudonym: (n) => `X0000${String(n).padStart(4, "0")}`,
  },
  // IBAN
  {
    name: "iban",
    category: "iban",
    confidence: "high",
    regex: /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b/g,
    pseudonym: (n) => `GB00XXXX0000000${String(n).padStart(5, "0")}`,
  },
  // Generic identifiers: hostname/user/account/etc = "value" (quoted)
  {
    name: "generic_identifier",
    category: "identifier",
    confidence: "low",
    regex: /((?:hostname|host_name|host|server|server_name|server_address|server_host|server_addr|fqdn|domain|domain_name|dns_name|subdomain|db_host|database_host|redis_host|mongo_host|mysql_host|postgres_host|proxy_host|gateway_host|load_balancer|lb_host|cdn_host|origin_host|upstream_host|backend_host|frontend_host|mail_server|smtp_host|smtp_server|imap_server|pop_server|ntp_server|dns_server|syslog_host|log_host|username|user_name|user|login|login_name|login_id|admin_user|admin_username|db_user|db_username|database_user|mysql_user|postgres_user|mongo_user|redis_user|ssh_user|ftp_user|smtp_user|proxy_user|vpn_user|service_account|service_user|system_user|owner|created_by|modified_by|assigned_to|author|account|account_name|account_number|account_id|customer_id|customer_number|client_number|member_id|member_number|subscriber_id|employee_id|employee_number|staff_id|patient_id|student_id|tenant_id|tenant_name|org_id|org_name|organization|organisation|organization_id|organisation_id|workspace_id|workspace_name|workspace|team_id|team_name|group_id|group_name|project_name|project_id|project|company|company_name|company_id|department|department_id|department_name|division|division_id|cost_center|cost_centre|cluster|cluster_name|cluster_id|instance|instance_id|instance_name|container|container_id|container_name|pod|pod_name|pod_id|node|node_name|node_id|namespace|namespace_name|deployment|deployment_name|deployment_id|service_name|service_id|stack|stack_name|stack_id|resource|resource_id|resource_name|resource_group|vpc|vpc_id|vpc_name|subnet|subnet_id|subnet_name|security_group|sg_id|region|zone|availability_zone|az|environment|env|env_name|stage|replica|replica_set|shard|volume|volume_id|volume_name|snapshot|snapshot_id|image|image_id|image_name|ami|ami_id|registry|registry_url|repository|repo|repo_name|repo_url|endpoint|url|uri|base_url|api_url|api_endpoint|callback_url|redirect_url|redirect_uri|webhook_url|health_check_url|healthcheck_url|status_url|proxy_url|proxy_address|connection_string|connection_url|connect_url|broker_url|broker_address|queue_url|topic_arn|frontend_url|backend_url|site_url|website_url|download_url|upload_url|grafana_url|kibana_url|prometheus_url|jenkins_url|ci_url|cd_url|database|database_name|db_name|db|schema|schema_name|table|table_name|collection|collection_name|keyspace|keyspace_name|index|index_name|catalog|catalog_name|path|file_path|filepath|file|filename|file_name|directory|dir|dir_path|folder|log_file|log_path|config_file|config_path|cert_file|cert_path|key_file|key_path|data_dir|data_path|backup_path|backup_dir|mount_path|mount_point|home_dir|home_directory|working_dir|work_dir|name|full_name|first_name|last_name|surname|display_name|real_name|legal_name|contact|contact_name|contact_person|recipient|sender|beneficiary|payee|payer|address|street|street_address|city|town|state|province|zip|zip_code|zipcode|postal_code|postcode|country|location|geo|latitude|longitude|coordinates|lat|lng|lon)\s*(?:[=:]|is|are|was|were|will be|would be|should be|shall be|is set to|is set as|set to|set as|equals)\s*["'])([^"']{2,})(?=["'])/gi,
    pseudonym: (n) => `REDACTED_IDENTIFIER_${n}`,
    hasPrefix: true,
    validator: (match) => {
      if (match.startsWith("REDACTED_")) return false;
      const skip = ["true", "false", "null", "none", "nil", "undefined", "default", "auto", "yes", "no"];
      if (skip.includes(match.toLowerCase())) return false;
      for (const d of SKIP_DOMAINS) { if (match.endsWith(d) || match === d) return false; }
      return true;
    },
  },
  // Generic identifiers: hostname/user/account/etc = value (unquoted)
  {
    name: "generic_identifier_unquoted",
    category: "identifier",
    confidence: "low",
    regex: /((?:hostname|host_name|host|server|server_name|server_address|server_host|server_addr|fqdn|domain|domain_name|dns_name|subdomain|db_host|database_host|redis_host|mongo_host|mysql_host|postgres_host|proxy_host|gateway_host|load_balancer|lb_host|cdn_host|origin_host|upstream_host|backend_host|frontend_host|mail_server|smtp_host|smtp_server|imap_server|pop_server|ntp_server|dns_server|syslog_host|log_host|username|user_name|user|login|login_name|login_id|admin_user|admin_username|db_user|db_username|database_user|mysql_user|postgres_user|mongo_user|redis_user|ssh_user|ftp_user|smtp_user|proxy_user|vpn_user|service_account|service_user|system_user|owner|created_by|modified_by|assigned_to|author|account|account_name|account_number|account_id|customer_id|customer_number|client_number|member_id|member_number|subscriber_id|employee_id|employee_number|staff_id|patient_id|student_id|tenant_id|tenant_name|org_id|org_name|organization|organisation|organization_id|organisation_id|workspace_id|workspace_name|workspace|team_id|team_name|group_id|group_name|project_name|project_id|project|company|company_name|company_id|department|department_id|department_name|division|division_id|cost_center|cost_centre|cluster|cluster_name|cluster_id|instance|instance_id|instance_name|container|container_id|container_name|pod|pod_name|pod_id|node|node_name|node_id|namespace|namespace_name|deployment|deployment_name|deployment_id|service_name|service_id|stack|stack_name|stack_id|resource|resource_id|resource_name|resource_group|vpc|vpc_id|vpc_name|subnet|subnet_id|subnet_name|security_group|sg_id|region|zone|availability_zone|az|environment|env|env_name|stage|replica|replica_set|shard|volume|volume_id|volume_name|snapshot|snapshot_id|image|image_id|image_name|ami|ami_id|registry|registry_url|repository|repo|repo_name|repo_url|endpoint|url|uri|base_url|api_url|api_endpoint|callback_url|redirect_url|redirect_uri|webhook_url|health_check_url|healthcheck_url|status_url|proxy_url|proxy_address|connection_string|connection_url|connect_url|broker_url|broker_address|queue_url|topic_arn|frontend_url|backend_url|site_url|website_url|download_url|upload_url|grafana_url|kibana_url|prometheus_url|jenkins_url|ci_url|cd_url|database|database_name|db_name|db|schema|schema_name|table|table_name|collection|collection_name|keyspace|keyspace_name|index|index_name|catalog|catalog_name|path|file_path|filepath|file|filename|file_name|directory|dir|dir_path|folder|log_file|log_path|config_file|config_path|cert_file|cert_path|key_file|key_path|data_dir|data_path|backup_path|backup_dir|mount_path|mount_point|home_dir|home_directory|working_dir|work_dir|name|full_name|first_name|last_name|surname|display_name|real_name|legal_name|contact|contact_name|contact_person|recipient|sender|beneficiary|payee|payer|address|street|street_address|city|town|state|province|zip|zip_code|zipcode|postal_code|postcode|country|location|geo|latitude|longitude|coordinates|lat|lng|lon)\s*(?:[=:]|is|are|was|were|will be|would be|should be|shall be|is set to|is set as|set to|set as|equals)\s*)([^\s"']{2,})/gi,
    pseudonym: (n) => `REDACTED_IDENTIFIER_${n}`,
    hasPrefix: true,
    validator: (match) => {
      if (match.startsWith("REDACTED_")) return false;
      const skip = ["true", "false", "null", "none", "nil", "undefined", "default", "auto", "yes", "no"];
      if (skip.includes(match.toLowerCase())) return false;
      for (const d of SKIP_DOMAINS) { if (match.endsWith(d) || match === d) return false; }
      return true;
    },
  },
];

// === Name Dictionaries ===

const _NAME_FIRST = new Set([
  "aaron","adam","alan","albert","alexander","alexis","alfred","andrew","anthony","antonio",
  "arthur","austin","benjamin","billy","bobby","brandon","brian","bruce","bryan","carl",
  "carlos","charles","christian","christopher","clarence","claude","clayton","clifford",
  "clinton","cody","colin","corey","craig","curtis","dallas","daniel","david","dean",
  "dennis","derek","donald","douglas","dylan","edward","eric","eugene","evan","frank",
  "gary","george","gerald","gilbert","gordon","graham","gregory","harold","harry","henry",
  "howard","hunter","jacob","james","jason","jeffrey","jeremy","jesse","joel","john",
  "johnnie","johnny","jonathan","jordan","joseph","joshua","juan","justin","keith",
  "kenneth","kevin","kyle","larry","lawrence","liam","lloyd","logan","louis","lucas",
  "mark","martin","matthew","michael","miguel","nathan","nicholas","noah","norman",
  "oliver","oscar","patrick","paul","peter","philip","ralph","randy","raymond","richard",
  "robert","roger","ronald","roy","russell","ryan","samuel","scott","sean","simon",
  "stanley","stephen","steven","terry","thomas","timothy","todd","tommy","tony","travis",
  "tyler","victor","vincent","walter","warren","wayne","william","willie","zachary",
  "abigail","alice","allison","amanda","amber","amy","andrea","angela","anna","annie",
  "ashley","audrey","aurora","ava","barbara","betty","beverly","brenda","brittany",
  "camila","carol","carolyn","catherine","charlotte","cheryl","chloe","christine",
  "cynthia","danielle","deborah","debra","diana","diane","donna","dorothy","elena",
  "eleanor","elizabeth","ella","emily","emma","evelyn","faith","frances","gabriella",
  "gloria","grace","hannah","harper","hazel","heather","helen","isabella","jacqueline",
  "jane","janet","janice","jennifer","jessica","joan","joyce","judith","julia","julie","karen",
  "katherine","kathleen","kelly","kimberly","kristin","laura","layla","leah","lillian",
  "lily","linda","lisa","lucy","luna","madison","margaret","maria","marilyn","martha",
  "mary","megan","melissa","michelle","mia","natalie","nicole","nora","olivia","pamela",
  "patricia","penelope","rachel","rebecca","riley","rosa","rose","ruth","samantha",
  "sandra","sara","sarah","scarlett","sharon","shirley","skylar","sophia","stephanie",
  "stella","susan","teresa","theresa","tiffany","victoria","violet","virginia","zoey",
]);

const _NAME_LAST = new Set([
  "adams","aguilar","alexander","allen","alvarado","alvarez","anderson","andrews",
  "armstrong","arnold","austin","bailey","baker","banks","barnes","barnett","barrett",
  "bell","bennett","berry","bishop","black","booth","boyd","bradley","brooks","brown",
  "bryant","burke","burns","burton","butler","campbell","carlson","carpenter","carr",
  "carroll","carter","castillo","castro","chambers","chapman","chavez","chen","clark",
  "cole","coleman","collins","cook","cooper","cox","crawford","cunningham","daniels",
  "davis","dean","delgado","diaz","dixon","dominguez","dunn","duncan","edwards","elliott",
  "ellis","espinoza","evans","fisher","flores","ford","foster","fox","franklin","freeman",
  "fuller","garcia","gardner","garrett","george","gibson","gilbert","gomez","gonzalez",
  "gordon","graham","grant","graves","gray","green","griffin","guerrero","gutierrez",
  "guzman","hall","hamilton","hansen","harper","harris","harrison","hart","harvey",
  "hayes","henderson","henry","hernandez","herrera","hicks","hill","hoffman","holmes",
  "howard","howell","hudson","hughes","hunt","hunter","jackson","jacobs","james",
  "jenkins","jensen","jimenez","johnson","jones","jordan","kelly","kennedy","kim","king",
  "knight","lane","larson","lawson","lee","lewis","li","long","lopez","lucas","lynch",
  "maldonado","marquez","marshall","martin","martinez","mason","matthews","mcdonald",
  "medina","mendez","mendoza","meyer","miller","mills","mitchell","montgomery","moore",
  "morales","moreno","morgan","morris","morrison","munoz","murphy","murray","myers",
  "nelson","nguyen","nichols","nunez","obrien","oliver","olson","ortega","ortiz","owens",
  "palmer","park","patel","payne","pena","perez","perkins","perry","peters","peterson",
  "phillips","pierce","porter","powell","price","ramirez","ramos","ray","reed","reid",
  "reyes","reynolds","rice","richardson","riley","rios","rivera","roberts","robinson",
  "rodriguez","rogers","romero","rose","ross","ruiz","russell","ryan","salazar","sanchez",
  "sandoval","santiago","santos","schmidt","scott","shaw","silva","simmons","simpson",
  "singh","sims","smith","snyder","soto","spencer","stephens","stewart","stone",
  "sullivan","taylor","thomas","thompson","tran","tucker","turner","valdez","vargas",
  "vasquez","vega","walker","wang","ward","warren","watson","webb","weber","weaver",
  "wells","west","white","williams","williamson","willis","wilson","wood","woods",
  "wright","young",
]);

// === International Patterns ===

const INTL_PATTERNS = [
  // French phone
  { name: "phone_fr", category: "phone", confidence: "medium",
    regex: /(?<!\d)(?:\+33[-.\s]?|0)[1-9](?:[-.\s]?\d{2}){4}(?!\d)/g,
    pseudonym: (n) => `+33 6 00 00 ${String(n).padStart(4, "0")}` },
  // German phone
  { name: "phone_de", category: "phone", confidence: "medium",
    regex: /(?<!\w)(?:\+49[-.\s]?|0)\d{2,5}[-.\s]?\d{3,8}(?!\d)/g,
    pseudonym: (n) => `+49 30 000${String(n).padStart(4, "0")}` },
  // Spanish phone
  { name: "phone_es", category: "phone", confidence: "medium",
    regex: /(?<!\d)\+34[-.\s]?[6-9]\d{2}[-.\s]?\d{3}[-.\s]?\d{3}(?!\d)/g,
    pseudonym: (n) => `+34 600 000 ${String(n).padStart(3, "0")}` },
  // Italian phone
  { name: "phone_it", category: "phone", confidence: "medium",
    regex: /(?<!\d)\+39[-.\s]?3\d{2}[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)/g,
    pseudonym: (n) => `+39 300 000 ${String(n).padStart(4, "0")}` },
  // Brazilian phone
  { name: "phone_br", category: "phone", confidence: "medium",
    regex: /(?<!\d)\+55[-.\s]?\d{2}[-.\s]?9?\d{4}[-.\s]?\d{4}(?!\d)/g,
    pseudonym: (n) => `+55 11 90000 ${String(n).padStart(4, "0")}` },
  // Indian phone
  { name: "phone_in", category: "phone", confidence: "medium",
    regex: /(?<!\d)(?:\+91[-.\s]?|0)[6-9]\d{9}(?!\d)/g,
    pseudonym: (n) => `+91 90000 ${String(n).padStart(5, "0")}` },
  // Australian phone
  { name: "phone_au", category: "phone", confidence: "medium",
    regex: /(?<!\d)(?:\+61[-.\s]?|0)4\d{2}[-.\s]?\d{3}[-.\s]?\d{3}(?!\d)/g,
    pseudonym: (n) => `+61 400 000 ${String(n).padStart(3, "0")}` },
  // Japanese phone
  { name: "phone_jp", category: "phone", confidence: "medium",
    regex: /(?<!\d)(?:\+81[-.\s]?|0)[1-9]0[-.\s]?\d{4}[-.\s]?\d{4}(?!\d)/g,
    pseudonym: (n) => `+81 90 0000 ${String(n).padStart(4, "0")}` },

  // French INSEE
  { name: "id_fr_insee", category: "ssn", confidence: "high",
    regex: /\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b/g,
    pseudonym: (n) => `1 00 00 00 000 ${String(n).padStart(3, "0")} 00` },
  // German tax ID (context-aware)
  { name: "id_de_steuerid", category: "ssn", confidence: "high",
    regex: /(?:steuer[-\s]?id(?:entifikationsnummer)?|tin)[-.\s:]*(\d{2}\s?\d{3}\s?\d{3}\s?\d{3})/gi,
    pseudonym: (n) => `00 000 000 ${String(n).padStart(3, "0")}`,
    hasPrefix: true },
  // Indian Aadhaar (context-aware)
  { name: "id_in_aadhaar", category: "ssn", confidence: "high",
    regex: /(?:aadhaar|aadhar|uidai)[-.\s:]*([2-9]\d{3}[-.\s]?\d{4}[-.\s]?\d{4})/gi,
    pseudonym: (n) => `2000 0000 ${String(n).padStart(4, "0")}`,
    hasPrefix: true },
  // Indian PAN
  { name: "id_in_pan", category: "ssn", confidence: "medium",
    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
    pseudonym: () => `AAAAA0000A` },
  // Canadian SIN (context-aware)
  { name: "id_ca_sin", category: "ssn", confidence: "high",
    regex: /(?:sin|social\s+insurance)[-.\s:]*(\d{3}[-.\s]?\d{3}[-.\s]?\d{3})/gi,
    pseudonym: (n) => `000-000-${String(n).padStart(3, "0")}`,
    hasPrefix: true },
  // Australian TFN (context-aware)
  { name: "id_au_tfn", category: "ssn", confidence: "high",
    regex: /(?:tfn|tax\s+file\s+number)[-.\s:]*(\d{3}[-.\s]?\d{3}[-.\s]?\d{2,3})/gi,
    pseudonym: (n) => `000 000 ${String(n).padStart(3, "0")}`,
    hasPrefix: true },

  // UK postcode
  { name: "postcode_uk", category: "identifier", confidence: "low",
    regex: /\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b/gi,
    pseudonym: (n) => `XX${n} 0XX` },
  // German PLZ (context-aware)
  { name: "postcode_de", category: "identifier", confidence: "low",
    regex: /(?:plz|postleitzahl|postal)[-.\s:]*(\d{5})\b/gi,
    pseudonym: (n) => `0000${n}`,
    hasPrefix: true },
  // French postal code (context-aware)
  { name: "postcode_fr", category: "identifier", confidence: "low",
    regex: /(?:code\s+postal|cp)[-.\s:]*(\d{5})\b/gi,
    pseudonym: (n) => `7500${n}`,
    hasPrefix: true },
  // Japanese postal code
  { name: "postcode_jp", category: "identifier", confidence: "low",
    regex: /\u3012\s?(\d{3}-\d{4})/g,
    pseudonym: (n) => `\u3012000-${String(n).padStart(4, "0")}`, hasPrefix: true },
  // Canadian postal code
  { name: "postcode_ca", category: "identifier", confidence: "low",
    regex: /\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b/gi,
    pseudonym: (n) => `X0X 0X${n}` },
  // Indian PIN code (context-aware)
  { name: "postcode_in", category: "identifier", confidence: "low",
    regex: /(?:pin\s*code|pincode|postal)[-.\s:]*(\d{6})\b/gi,
    pseudonym: (n) => `10000${n}`,
    hasPrefix: true },

  // EU date DD/MM/YYYY or DD.MM.YYYY or DD-MM-YYYY
  { name: "date_eu", category: "identifier", confidence: "low",
    regex: /\b(?:0[1-9]|[12]\d|3[01])[/.\-](?:0[1-9]|1[0-2])[/.\-](?:19|20)\d{2}\b/g,
    pseudonym: () => `01/01/2000` },
  // ISO date YYYY-MM-DD or YYYY/MM/DD
  { name: "date_iso", category: "identifier", confidence: "low",
    regex: /\b(?:19|20)\d{2}[/\-](?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])\b/g,
    pseudonym: () => `2000-01-01` },

  // === REAL-LIFE PATTERNS ===

  // UK number plate
  { name: "plate_uk", category: "identifier", confidence: "medium",
    regex: /\b[A-Z]{2}\d{2}\s?[A-Z]{3}\b/g,
    pseudonym: () => `XX00 XXX` },
  // US license plate (context-aware)
  { name: "plate_us", category: "identifier", confidence: "medium",
    regex: /(?:plate|license\s*plate|tag|registration)[-.\s:]*([A-Z0-9]{1,4}[-.\s]?[A-Z0-9]{2,5})/gi,
    pseudonym: (n) => `XXXX-${String(n).padStart(3, "0")}`, hasPrefix: true },
  // EU plate (context-aware)
  { name: "plate_eu", category: "identifier", confidence: "medium",
    regex: /(?:plate|plaque|kennzeichen|targa|matricula|kenteken|immatriculation)[-.\s:]*([A-Z0-9]{1,4}[-.\s]?[A-Z0-9]{1,4}[-.\s]?[A-Z0-9]{1,5})/gi,
    pseudonym: () => `XX-000-XX`, hasPrefix: true },

  // NHS number (context-aware)
  { name: "id_nhs", category: "ssn", confidence: "high",
    regex: /(?:nhs|nhs\s+number|nhs\s+no)[-.\s:]*(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})/gi,
    pseudonym: (n) => `000 000 ${String(n).padStart(4, "0")}`, hasPrefix: true },
  // US Medicare/Medicaid (context-aware)
  { name: "id_us_medicare", category: "ssn", confidence: "high",
    regex: /(?:medicare|medicaid)[-.\s#:]*([A-Z0-9]{4,12})/gi,
    pseudonym: (n) => `0000-000-${String(n).padStart(4, "0")}`, hasPrefix: true },
  // Insurance policy (context-aware)
  { name: "id_insurance_policy", category: "ssn", confidence: "high",
    regex: /(?:policy\s+(?:number|no|#)|insurance\s+id|member\s+id|subscriber\s+id|group\s+(?:number|no|#)|plan\s+id)[-.\s#:]*([A-Z0-9]{4,20})/gi,
    pseudonym: (n) => `POLICY-${String(n).padStart(6, "0")}`, hasPrefix: true },
  // EU/UK VAT registration number (context-aware — a bare "GB123456789" is
  // too ambiguous with other IDs to match without the keyword)
  { name: "id_vat", category: "ssn", confidence: "high",
    regex: /vat[_\s]*(?:reg(?:istration)?[_\s]*)?(?:number|no|id)?[-.\s#:]*([A-Z]{2}\d{8,12}[A-Z]?)/gi,
    pseudonym: (n) => `VAT${String(n).padStart(9, "0")}`, hasPrefix: true },

  // UK driving licence (context-aware)
  { name: "id_uk_driving", category: "ssn", confidence: "high",
    regex: /(?:driving\s+licen[cs]e|driver'?s?\s+licen[cs]e|dvla)[-.\s#:]*([A-Z]{5}\d{6}[A-Z0-9]{5})/gi,
    pseudonym: () => `XXXXX000000XX0XX`, hasPrefix: true },
  // US driver's licence (context-aware)
  { name: "id_us_driving", category: "ssn", confidence: "high",
    regex: /(?:driver'?s?\s+licen[cs]e|dl|dmv)[-.\s#:]*([A-Z]?\d{4,12})/gi,
    pseudonym: (n) => `DL-0000${String(n).padStart(4, "0")}`, hasPrefix: true },

  // UK sort code (context-aware)
  { name: "bank_sort_code", category: "identifier", confidence: "high",
    regex: /(?:sort\s*code)[-.\s#:]*(\d{2}[-.\s]?\d{2}[-.\s]?\d{2})/gi,
    pseudonym: (n) => `00-00-${String(n).padStart(2, "0")}`, hasPrefix: true },
  // US/CA routing number (context-aware)
  { name: "bank_routing", category: "identifier", confidence: "high",
    regex: /(?:routing|routing\s+number|aba|transit)[-.\s#:]*(\d{9})\b/gi,
    pseudonym: (n) => `000000${String(n).padStart(3, "0")}`, hasPrefix: true },
  // Bank account number (context-aware)
  { name: "bank_account", category: "identifier", confidence: "high",
    regex: /(?:account\s*(?:number|no|#)|acct\s*(?:no|#)|bank\s+account|checking|savings|current\s+account)[-.\s#:]*(\d{6,18})/gi,
    pseudonym: (n) => `00000000${String(n).padStart(4, "0")}`, hasPrefix: true },
  // SWIFT/BIC (context-aware)
  { name: "bank_swift", category: "identifier", confidence: "high",
    regex: /(?:swift|bic|swift\s*code|bic\s*code)[-.\s#:]*([A-Z]{6}[A-Z0-9]{2,5})/gi,
    pseudonym: () => `XXXXXX00`, hasPrefix: true },

  // UK UTR (context-aware)
  { name: "id_uk_utr", category: "ssn", confidence: "high",
    regex: /(?:utr|unique\s+taxpayer\s+reference|tax\s+reference)[-.\s#:]*(\d{10})\b/gi,
    pseudonym: (n) => `0000000${String(n).padStart(3, "0")}`, hasPrefix: true },
  // UK NINO
  { name: "id_uk_nino", category: "ssn", confidence: "high",
    regex: /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/g,
    pseudonym: (n) => `XX 00 00 ${String(n).padStart(2, "0")} A` },
  // US EIN (context-aware)
  { name: "id_us_ein", category: "ssn", confidence: "high",
    regex: /(?:ein|employer\s+id|fein|tax\s+id)[-.\s#:]*(\d{2}-\d{7})/gi,
    pseudonym: (n) => `00-000${String(n).padStart(4, "0")}`, hasPrefix: true },
  // US ITIN (context-aware)
  { name: "id_us_itin", category: "ssn", confidence: "high",
    regex: /(?:itin)[-.\s#:]*(9\d{2}-\d{2}-\d{4})/gi,
    pseudonym: (n) => `900-00-${String(n).padStart(4, "0")}`, hasPrefix: true },

  // VIN (context-aware)
  { name: "id_vin", category: "identifier", confidence: "high",
    regex: /(?:vin|vehicle\s+identification)[-.\s#:]*([A-HJ-NPR-Z0-9]{17})/gi,
    pseudonym: (n) => `00000000000000${String(n).padStart(3, "0")}`, hasPrefix: true },
  // Claim/reference/order/booking/tracking number (context-aware)
  { name: "id_claim_ref", category: "identifier", confidence: "medium",
    regex: /(?:claim\s*(?:number|no|#|ref)|reference\s*(?:number|no|#)|case\s*(?:number|no|#)|ticket\s*(?:number|no|#)|invoice\s*(?:number|no|#)|order\s*(?:number|no|#)|booking\s*(?:number|no|#|ref)|confirmation\s*(?:number|no|#)|tracking\s*(?:number|no|#))[-.\s#:]*([A-Z0-9][-A-Z0-9]{3,20})/gi,
    pseudonym: (n) => `REF-${String(n).padStart(6, "0")}`, hasPrefix: true },

  // DOB (context-aware)
  { name: "dob", category: "ssn", confidence: "high",
    regex: /(?:dob|date\s+of\s+birth|birthdate|birth\s+date|born\s+on|born)[-.\s:]*(\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4})/gi,
    pseudonym: () => `01/01/1990`, hasPrefix: true },
  // Age (context-aware)
  { name: "age", category: "ssn", confidence: "medium",
    regex: /(?:age|aged)[-.\s:]*(\d{1,3})\s*(?:years?\s+old|yrs?\s+old|y\.?o\.?|years?|yrs?)?\b/gi,
    pseudonym: () => `[AGE]`, hasPrefix: true },
  // Gender (context-aware)
  { name: "gender", category: "ssn", confidence: "medium",
    regex: /(?:gender|sex)[-.\s:]*(male|female|non-binary|nonbinary|other|m|f)\b/gi,
    pseudonym: () => `[GENDER]`, hasPrefix: true },
  // Nationality (context-aware)
  { name: "nationality", category: "ssn", confidence: "medium",
    regex: /\b(?:nationality|citizenship|ethnicity|race)\b[-.\s:]*([A-Za-z][-A-Za-z\s]{2,25})/gi,
    pseudonym: () => `[NATIONALITY]`, hasPrefix: true },
  // Religion (context-aware)
  { name: "religion", category: "ssn", confidence: "medium",
    regex: /(?:religion|faith|religious\s+affiliation)[-.\s:]*([A-Za-z][-A-Za-z\s]{2,25})/gi,
    pseudonym: () => `[RELIGION]`, hasPrefix: true },

  // Full person names (First Last matched against name dictionaries)
  { name: "person_name", category: "ssn", confidence: "medium",
    regex: /\b([A-Z][a-z]{1,14})\s+([A-Z][a-z']{1,19})\b/g,
    pseudonym: (n) => `[PERSON_${n}]`,
    validator: (fullMatch) => {
      const parts = fullMatch.trim().split(/\s+/);
      if (parts.length < 2) return false;
      const first = parts[0].toLowerCase();
      const last = parts[parts.length - 1].toLowerCase();
      return _NAME_FIRST.has(first) && _NAME_LAST.has(last);
    },
  },
];


// === Language Detection ===

const _CJK = /[\u4e00-\u9fff\u3400-\u4dbf]/;
const _HIRAGANA = /[\u3040-\u309f]/;
const _KATAKANA = /[\u30a0-\u30ff]/;
const _HANGUL = /[\uac00-\ud7af\u1100-\u11ff]/;
const _CYRILLIC = /[\u0400-\u04ff]/;
const _ARABIC = /[\u0600-\u06ff]/;
const _DEVANAGARI = /[\u0900-\u097f]/;

const _LANG_MARKERS = {
  fr: ["le", "la", "les", "un", "une", "des", "du", "de", "est", "sont", "avec", "pour", "dans", "mot_de_passe", "cle_api"],
  es: ["el", "la", "los", "las", "un", "una", "es", "son", "con", "para", "del", "contraseña", "clave", "clave_api"],
  de: ["der", "die", "das", "ein", "eine", "ist", "sind", "mit", "und", "auf", "passwort", "kennwort", "schlüssel"],
  pt: ["o", "os", "um", "uma", "do", "da", "no", "na", "com", "para", "senha", "chave", "chave_api"],
  it: ["il", "lo", "la", "gli", "le", "un", "una", "del", "nel", "con", "chiave", "chiave_api", "segreto"],
  nl: ["de", "het", "een", "van", "in", "op", "met", "voor", "aan", "wachtwoord", "sleutel", "geheim"],
  ru: ["и", "в", "на", "не", "что", "это", "для", "как", "из", "от"],
};

const _I18N_KEYWORDS = {
  fr: ["mot de passe", "mot_de_passe", "mdp", "motdepasse", "clé api", "cle_api", "clé secrète", "cle_secrete", "clé privée", "cle_privee", "jeton", "jeton_api", "jeton_acces", "identifiant", "secret_api", "mot passe admin", "mot_passe_admin", "mot passe root", "mot_passe_root", "mot passe db", "mot_passe_db"],
  es: ["contraseña", "contrasena", "clave", "clave_api", "clave secreta", "clave_secreta", "clave privada", "clave_privada", "clave acceso", "clave_acceso", "secreto", "secreto_api", "token acceso", "token_acceso", "token_api", "contrasena_admin", "contrasena_root", "contrasena_db"],
  de: ["passwort", "kennwort", "kenncode", "geheimnis", "geheim", "schlüssel", "schluessel", "api schlüssel", "api_schlüssel", "api_schluessel", "admin passwort", "admin_passwort", "root_passwort", "db_passwort"],
  pt: ["senha", "senha_api", "senha secreta", "senha_secreta", "chave", "chave_api", "chave secreta", "chave_secreta", "chave privada", "chave_privada", "segredo", "segredo_api", "token acesso", "token_acesso", "senha_admin", "senha_root"],
  it: ["password", "parola chiave", "parola_chiave", "parola d'ordine", "parola_dordine", "chiave", "chiave_api", "chiave segreta", "chiave_segreta", "chiave privata", "chiave_privata", "segreto", "segreto_api", "gettone", "password_admin", "password_db"],
  nl: ["wachtwoord", "toegangscode", "sleutel", "api sleutel", "api_sleutel", "geheime sleutel", "geheime_sleutel", "geheim", "privesleutel", "admin wachtwoord", "admin_wachtwoord", "root_wachtwoord", "db_wachtwoord"],
  ja: ["\u30D1\u30B9\u30EF\u30FC\u30C9", "\u6697\u8A3C\u756A\u53F7", "\u79D8\u5BC6\u9375", "API\u30AD\u30FC", "\u30A2\u30AF\u30BB\u30B9\u30AD\u30FC", "\u30B7\u30FC\u30AF\u30EC\u30C3\u30C8", "\u30C8\u30FC\u30AF\u30F3"],
  zh: ["\u5BC6\u7801", "\u53E3\u4EE4", "\u5BC6\u94A5", "\u79D8\u94A5", "\u8BBF\u95EE\u5BC6\u94A5", "\u79C1\u94A5", "\u516C\u94A5", "\u4EE4\u724C", "\u51ED\u8BC1"],
  ko: ["\uBE44\uBC00\uBC88\uD638", "\uC554\uD638", "\uBE44\uBC00\uD0A4", "\uC811\uADFC\uD0A4", "\uC778\uC99D\uD0A4", "\uD1A0\uD070"],
  ru: ["\u043F\u0430\u0440\u043E\u043B\u044C", "\u0441\u0435\u043A\u0440\u0435\u0442", "\u043A\u043B\u044E\u0447", "\u0441\u0435\u043A\u0440\u0435\u0442\u043D\u044B\u0439 \u043A\u043B\u044E\u0447", "\u0441\u0435\u043A\u0440\u0435\u0442\u043D\u044B\u0439_\u043A\u043B\u044E\u0447", "api \u043A\u043B\u044E\u0447", "api_\u043A\u043B\u044E\u0447", "\u0442\u043E\u043A\u0435\u043D", "\u043F\u0430\u0440\u043E\u043B\u044C \u0430\u0434\u043C\u0438\u043D\u0430", "\u043F\u0430\u0440\u043E\u043B\u044C_\u0430\u0434\u043C\u0438\u043D\u0430"],
  ar: ["\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631", "\u0643\u0644\u0645\u0629\u0627\u0644\u0633\u0631", "\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0648\u0635\u0648\u0644", "\u0645\u0641\u062A\u0627\u062D_\u0627\u0644\u0648\u0635\u0648\u0644", "\u0627\u0644\u0633\u0631", "\u0631\u0645\u0632 \u0627\u0644\u0648\u0635\u0648\u0644", "\u0631\u0645\u0632_\u0627\u0644\u0648\u0635\u0648\u0644", "\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0623\u0628\u0631\u0627\u062C", "\u0627\u0644\u0631\u0645\u0632 \u0627\u0644\u0633\u0631\u064A"],
  hi: ["\u092A\u093E\u0938\u0935\u0930\u094D\u0921", "\u0917\u0941\u092A\u094D\u0924 \u0915\u0941\u0902\u091C\u0940", "\u0917\u0941\u092A\u094D\u0924\u0915\u0941\u0902\u091C\u0940", "\u092A\u094D\u0930\u092E\u093E\u0923\u0940\u0915\u0930\u0923 \u0915\u0941\u0902\u091C\u0940", "\u090F\u092A\u0940\u0906\u0908 \u0915\u0941\u0902\u091C\u0940", "\u091F\u094B\u0915\u0928", "\u092A\u094D\u0930\u093E\u0907\u0935\u0947\u091F \u0915\u0941\u0902\u091C\u0940"],
};

function _detectLanguages(text) {
  const langs = new Set(["en"]);
  if (_CJK.test(text)) langs.add("zh");
  if (_HIRAGANA.test(text) || _KATAKANA.test(text)) langs.add("ja");
  if (_HANGUL.test(text)) langs.add("ko");
  if (_CYRILLIC.test(text)) langs.add("ru");
  if (_ARABIC.test(text)) langs.add("ar");
  if (_DEVANAGARI.test(text)) langs.add("hi");

  const lower = text.toLowerCase();
  const words = new Set(lower.match(/\b[a-zA-Z\u00C0-\u017F_]{2,}\b/g) || []);
  for (const [lang, markers] of Object.entries(_LANG_MARKERS)) {
    let hits = 0;
    for (const m of markers) { if (words.has(m)) hits++; }
    if (hits >= 1) langs.add(lang);
  }
  return langs;
}

function _buildI18nSecretPatterns(langs) {
  const keywords = [];
  for (const lang of langs) {
    if (lang === "en") continue;
    const kw = _I18N_KEYWORDS[lang];
    if (kw) keywords.push(...kw);
  }
  if (keywords.length === 0) return [];
  const escaped = keywords.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
  // Connectors: punctuation (with optional surrounding spaces), Latin-script
  // "to be" verbs (require leading space), CJK particles (no leading space needed)
  const conn = `(?:\\s*[=:]\\s*|\\s+(?:is|est|ist|é|è|es|zijn|является)\\s*|\\s*(?:是|は|が|를|은|는|です|है)\\s*)`;
  return [
    { name: "i18n_secret", category: "secret", confidence: "high",
      regex: new RegExp(`((?:${escaped})${conn}\\s*["'])([^"']{4,})(?=["'])`, "gi"),
      pseudonym: (n) => `REDACTED_SECRET_${n}`, hasPrefix: true },
    { name: "i18n_secret_unquoted", category: "secret", confidence: "high",
      regex: new RegExp(`((?:${escaped})${conn}\\s*)([^\\s"']{4,})`, "gi"),
      pseudonym: (n) => `REDACTED_SECRET_${n}`, hasPrefix: true },
  ];
}


// === Privatiser Engine ===

class Privatiser {
  constructor(config = {}) {
    this.mapping = {};        // original -> pseudonym
    this.reverse = {};        // pseudonym -> original
    this.counters = {};       // category -> next counter
    this.confidenceMap = {};  // pseudonym -> { confidence, patternName }

    // Category filtering
    this.enabledCategories = config.enabledCategories || { ...DEFAULT_ENABLED_CATEGORIES };
    this.allowlist = config.allowlist || [];
    this.customWords = config.customWords || [];
    const cp = config.customPatterns;
    this.customPatterns = Array.isArray(cp) ? cp : [];
    const pp = config.patternPacks;
    this.patternPacks = Array.isArray(pp) ? pp : [];
  }

  _isCategoryEnabled(category) {
    for (const [group, cats] of Object.entries(CATEGORY_GROUPS)) {
      if (cats.includes(category)) {
        return this.enabledCategories[group] !== false;
      }
    }
    return true;
  }

  _isAllowlisted(value) {
    return this.allowlist.some((allowed) => value === allowed);
  }

  _getCounter(category) {
    if (!(category in this.counters)) this.counters[category] = 1;
    return this.counters[category];
  }

  _getOrCreate(value, category, pseudonymFn, confidence, patternName) {
    if (value in this.mapping) return this.mapping[value];
    const n = this._getCounter(category);
    const pseudonym = pseudonymFn(n);
    this.counters[category] = n + 1;
    this.mapping[value] = pseudonym;
    this.reverse[pseudonym] = value;
    if (confidence) this.confidenceMap[pseudonym] = { confidence, patternName: patternName || category };
    return pseudonym;
  }

  _anonymizeArn(original) {
    if (original in this.mapping) return this.mapping[original];
    const parts = original.split(":");
    if (parts.length >= 6) {
      const service = parts[2];
      const region = parts[3];
      const resource = parts.length > 5 ? parts[5] : "resource";
      let resourceType = "";
      if (resource.includes("/")) resourceType = resource.split("/")[0] + "/";
      const n = this._getCounter("arn");
      const pseudonym = `arn:aws:${service}:${region}:${100000000000 + n}:${resourceType}redacted-${n}`;
      this.counters["arn"] = n + 1;
      this.mapping[original] = pseudonym;
      this.reverse[pseudonym] = original;
      this.confidenceMap[pseudonym] = { confidence: "high", patternName: "arn" };
      return pseudonym;
    }
    return original;
  }

  anonymize(content) {
    if (!content) return { result: content, mapping: {}, confidenceMap: {} };

    const placeholders = [];
    let result = content;

    // Custom words pre-pass (highest priority, runs before all patterns)
    if (this.customWords.length > 0) {
      const escaped = this.customWords
        .filter((w) => w && w.trim().length > 0)
        .map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
        .filter(Boolean);
      if (escaped.length > 0) {
        const customRegex = new RegExp(`(${escaped.join("|")})`, "gi");
        result = result.replace(customRegex, (match) => {
          if (match.includes("\x00")) return match;
          const pseudonym = this._getOrCreate(match, "custom", (n) => `CUSTOM_${n}`, "high", "custom_word");
          const idx = placeholders.length;
          placeholders.push(pseudonym);
          return `\x00PRIV_${idx}\x00`;
        });
      }
    }

    // Custom regex patterns (Pro) — run after custom words, before built-in patterns
    for (const cp of this.customPatterns) {
      if (!cp || !cp.regex) continue;
      try {
        const flags = "g" + (cp.caseInsensitive ? "i" : "");
        const re = new RegExp(cp.regex, flags);
        const prefix = (cp.name || "PATTERN").toUpperCase().replace(/[^A-Z0-9]/g, "_");
        result = result.replace(re, (match) => {
          if (match.includes("\x00")) return match;
          if (this._isAllowlisted(match)) return match;
          const pseudonym = this._getOrCreate(match, `cp_${prefix}`, (n) => `${prefix}_${n}`, "high", cp.name);
          const idx = placeholders.length;
          placeholders.push(pseudonym);
          return `\x00PRIV_${idx}\x00`;
        });
      } catch {
        // Invalid regex — skip silently
      }
    }

    // Pack patterns run before built-ins so specific pack patterns take priority
    // over generic built-in patterns (e.g. k8s namespace before generic identifier)
    const packPatterns = this.patternPacks.flat().filter((p) => p && p.regex);
    // Language detection + i18n secret patterns
    const detectedLangs = _detectLanguages(content);
    const i18nSecretPatterns = _buildI18nSecretPatterns(detectedLangs);

    const activePatterns = [
      ...packPatterns,
      ...i18nSecretPatterns,
      ...INTL_PATTERNS.filter((p) => this._isCategoryEnabled(p.category)),
      ...PATTERNS.filter((p) => this._isCategoryEnabled(p.category)),
    ];

    for (const pattern of activePatterns) {
      pattern.regex.lastIndex = 0;

      result = result.replace(pattern.regex, (...args) => {
        const fullMatch = args[0];

        // Skip if already contains a placeholder
        if (fullMatch.includes("\x00")) return fullMatch;

        // Check allowlist
        if (this._isAllowlisted(fullMatch)) return fullMatch;

        // Run validator
        if (pattern.validator && !pattern.validator(fullMatch)) return fullMatch;

        let pseudonym;

        if (pattern.name === "arn") {
          pseudonym = this._anonymizeArn(fullMatch);
        } else if (pattern.hasPrefix) {
          let prefix, value;
          if (typeof args[2] === "number") {
            // Only 1 capture group: args[1] = value, args[2] = offset
            value = args[1];
            prefix = fullMatch.slice(0, fullMatch.indexOf(value));
          } else {
            // 2 capture groups: args[1] = prefix, args[2] = value
            prefix = args[1];
            value = args[2];
          }
          if (value && typeof value === "string" && value.startsWith("REDACTED_")) return fullMatch;
          // For SSH keys, prefix is group1 + " "
          const actualPrefix = pattern.prefixFromGroup1 ? prefix + " " : prefix;
          const p = this._getOrCreate(value, pattern.category, pattern.pseudonym, pattern.confidence, pattern.name);
          pseudonym = actualPrefix + p;
        } else if (pattern.name === "ipv4" && fullMatch.includes("/")) {
          const [ip, cidr] = fullMatch.split("/");
          const p = this._getOrCreate(ip, pattern.category, pattern.pseudonym, pattern.confidence, pattern.name);
          pseudonym = `${p}/${cidr}`;
        } else {
          pseudonym = this._getOrCreate(fullMatch, pattern.category, pattern.pseudonym, pattern.confidence, pattern.name);
        }

        const idx = placeholders.length;
        placeholders.push(pseudonym);
        return `\x00PRIV_${idx}\x00`;
      });
    }

    // Replace placeholders with actual pseudonyms
    for (let i = 0; i < placeholders.length; i++) {
      result = result.split(`\x00PRIV_${i}\x00`).join(placeholders[i]);
    }

    return { result, mapping: { ...this.reverse }, confidenceMap: { ...this.confidenceMap } };
  }

  deanonymize(content, mapping) {
    if (!content || !mapping) return content;
    let result = content;
    const entries = Object.entries(mapping).sort((a, b) => b[0].length - a[0].length);
    for (const [pseudonym, original] of entries) {
      result = result.split(pseudonym).join(original);
    }
    return result;
  }

  reset() {
    this.mapping = {};
    this.reverse = {};
    this.counters = {};
    this.confidenceMap = {};
  }
}
globalThis.Privatiser = Privatiser;
