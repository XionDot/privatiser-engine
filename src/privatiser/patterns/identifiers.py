"""Identifier patterns: UUIDs, keyword-based identifiers, custom regex support."""

import re

from . import PatternHandler, register
from .network import SKIP_DOMAINS


# Shared grammar separator for keyword-based patterns
_GRAMMAR_SEP = r"\s*(?:[=:]|is|are|was|were|will be|would be|should be|shall be|set to|set as|equals)"

# Keywords for different identifier types
_HOST_KEYWORDS = (
    r"hostname|host_name|host|server|server_name|server_address|server_host|"
    r"server_addr|fqdn|domain|domain_name|dns_name|subdomain|"
    r"db_host|database_host|redis_host|mongo_host|mysql_host|postgres_host|"
    r"proxy_host|gateway_host|load_balancer|lb_host|cdn_host|"
    r"origin_host|upstream_host|backend_host|frontend_host|"
    r"mail_server|smtp_host|smtp_server|imap_server|pop_server|"
    r"ntp_server|dns_server|syslog_host|log_host"
)

_USER_KEYWORDS = (
    r"username|user_name|user|login|login_name|login_id|"
    r"admin_user|admin_username|db_user|db_username|database_user|"
    r"mysql_user|postgres_user|mongo_user|redis_user|"
    r"ssh_user|ftp_user|smtp_user|proxy_user|vpn_user|"
    r"service_account|service_user|system_user|"
    r"owner|created_by|modified_by|assigned_to|author"
)

_ACCOUNT_KEYWORDS = (
    r"account|account_name|account_number|account_id|"
    r"customer_id|customer_number|client_number|"
    r"member_id|member_number|subscriber_id|"
    r"employee_id|employee_number|staff_id|"
    r"patient_id|student_id|tenant_id|tenant_name|"
    r"org_id|org_name|organization|organisation|organization_id|organisation_id|"
    r"workspace_id|workspace_name|workspace|"
    r"team_id|team_name|group_id|group_name|"
    r"project_name|project_id|project|"
    r"company|company_name|company_id|"
    r"department|department_id|department_name|"
    r"division|division_id|cost_center|cost_centre"
)

_INFRA_KEYWORDS = (
    r"cluster|cluster_name|cluster_id|"
    r"instance|instance_id|instance_name|"
    r"container|container_id|container_name|"
    r"pod|pod_name|pod_id|"
    r"node|node_name|node_id|"
    r"namespace|namespace_name|"
    r"deployment|deployment_name|deployment_id|"
    r"service_name|service_id|"
    r"stack|stack_name|stack_id|"
    r"resource|resource_id|resource_name|resource_group|"
    r"vpc|vpc_id|vpc_name|"
    r"subnet|subnet_id|subnet_name|"
    r"security_group|sg_id|"
    r"region|zone|availability_zone|az|"
    r"environment|env|env_name|stage|"
    r"replica|replica_set|shard|"
    r"volume|volume_id|volume_name|"
    r"snapshot|snapshot_id|"
    r"image|image_id|image_name|ami|ami_id|"
    r"registry|registry_url|repository|repo|repo_name|repo_url"
)

_ENDPOINT_KEYWORDS = (
    r"endpoint|url|uri|base_url|api_url|api_endpoint|"
    r"callback_url|redirect_url|redirect_uri|webhook_url|"
    r"health_check_url|healthcheck_url|status_url|"
    r"proxy_url|proxy_address|"
    r"connection_string|connection_url|connect_url|"
    r"broker_url|broker_address|"
    r"queue_url|topic_arn|"
    r"frontend_url|backend_url|site_url|website_url|"
    r"download_url|upload_url|"
    r"grafana_url|kibana_url|prometheus_url|"
    r"jenkins_url|ci_url|cd_url"
)

_DB_KEYWORDS = (
    r"database|database_name|db_name|db|"
    r"schema|schema_name|"
    r"table|table_name|"
    r"collection|collection_name|"
    r"keyspace|keyspace_name|"
    r"index|index_name|"
    r"catalog|catalog_name"
)

_PATH_KEYWORDS = (
    r"path|file_path|filepath|file|filename|file_name|"
    r"directory|dir|dir_path|folder|"
    r"log_file|log_path|config_file|config_path|"
    r"cert_file|cert_path|key_file|key_path|"
    r"data_dir|data_path|backup_path|backup_dir|"
    r"mount_path|mount_point|"
    r"home_dir|home_directory|working_dir|work_dir"
)

_NAME_KEYWORDS = (
    r"name|full_name|first_name|last_name|surname|"
    r"display_name|real_name|legal_name|"
    r"contact|contact_name|contact_person|"
    r"recipient|sender|"
    r"beneficiary|payee|payer"
)

_ADDRESS_KEYWORDS = (
    r"address|street|street_address|"
    r"city|town|state|province|"
    r"zip|zip_code|zipcode|postal_code|postcode|"
    r"country|location|geo|latitude|longitude|"
    r"coordinates|lat|lng|lon"
)

_ALL_IDENTIFIER_KEYWORDS = (
    f"{_HOST_KEYWORDS}|{_USER_KEYWORDS}|{_ACCOUNT_KEYWORDS}|"
    f"{_INFRA_KEYWORDS}|{_ENDPOINT_KEYWORDS}|{_DB_KEYWORDS}|"
    f"{_PATH_KEYWORDS}|{_NAME_KEYWORDS}|{_ADDRESS_KEYWORDS}"
)


def _identifier_transform(match: re.Match) -> tuple[str, str]:
    """For 'keyword = value' patterns, anonymize only the value."""
    prefix = match.group(1)
    value = match.group(2)
    return value, prefix


def _identifier_validator(match: re.Match) -> bool:
    """Skip already-redacted values, well-known domains, and common words."""
    value = match.group(2)
    if value.startswith("REDACTED_"):
        return False
    # Skip well-known domains
    for skip_domain in SKIP_DOMAINS:
        if value.endswith(skip_domain) or value == skip_domain:
            return False
    # Skip common non-sensitive values
    skip = {"true", "false", "null", "none", "nil", "undefined", "default", "auto", "yes", "no"}
    return value.lower() not in skip


register(
    # UUIDs
    PatternHandler(
        name="uuid",
        category="uuid",
        regex=re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        pseudonym_fn=lambda n: f"00000000-0000-4000-a000-{n:012d}",
        priority=52,
    ),
    # Keyword-based identifiers: hostname/user/account/etc = "value" (quoted)
    PatternHandler(
        name="generic_identifier",
        category="identifier",
        regex=re.compile(
            rf"((?:{_ALL_IDENTIFIER_KEYWORDS})"
            rf"{_GRAMMAR_SEP}\s*[\"'])"
            r"([^\"']{2,})"
            r"(?=[\"'])",
            re.IGNORECASE,
        ),
        pseudonym_fn=lambda n: f"REDACTED_IDENTIFIER_{n}",
        priority=85,
        match_transform=_identifier_transform,
        validator=_identifier_validator,
    ),
    # Keyword-based identifiers: hostname/user/account/etc = value (unquoted)
    PatternHandler(
        name="generic_identifier_unquoted",
        category="identifier",
        regex=re.compile(
            rf"((?:{_ALL_IDENTIFIER_KEYWORDS})"
            rf"{_GRAMMAR_SEP}\s*)"
            r"([^\s\"']{2,})",
            re.IGNORECASE,
        ),
        pseudonym_fn=lambda n: f"REDACTED_IDENTIFIER_{n}",
        priority=85,
        match_transform=_identifier_transform,
        validator=_identifier_validator,
    ),
)


def register_custom(
    name: str,
    regex_str: str,
    pseudonym_template: str = "REDACTED_{name}_{n}",
    priority: int = 80,
) -> PatternHandler:
    """Register a user-defined pattern.

    Args:
        name: Unique name for the pattern.
        regex_str: Regular expression string to match.
        pseudonym_template: Template with {name} and {n} placeholders.
        priority: Lower = matched first.

    Returns:
        The registered PatternHandler.
    """
    handler = PatternHandler(
        name=name,
        category=name,
        regex=re.compile(regex_str),
        pseudonym_fn=lambda n, _name=name, _tmpl=pseudonym_template: _tmpl.format(
            name=_name, n=n
        ),
        priority=priority,
    )
    register(handler)
    return handler
