"""Tests for identifier patterns: UUID, custom patterns."""

from privatiser import Privatiser, register_custom


class TestUUID:
    def test_basic_uuid(self, p):
        text = "id: 550e8400-e29b-41d4-a716-446655440000"
        result, mapping = p.anonymize(text)
        assert "550e8400" not in result
        assert "00000000-0000-4000-a000-" in result

    def test_uppercase_uuid(self, p):
        text = "id: 550E8400-E29B-41D4-A716-446655440000"
        result, mapping = p.anonymize(text)
        assert "550E8400" not in result

    def test_consistency(self, p):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        text = f"a = {uuid}\nb = {uuid}"
        result, mapping = p.anonymize(text)
        lines = result.strip().split("\n")
        assert lines[0].split("= ")[1] == lines[1].split("= ")[1]


class TestGenericIdentifierHosts:
    """Test hostname/server/domain keyword-based detection."""

    def test_hostname_quoted(self, p):
        text = 'hostname = "prod-db-01.internal.corp"'
        result, _ = p.anonymize(text)
        assert "prod-db-01.internal.corp" not in result

    def test_hostname_unquoted(self, p):
        text = "hostname = prod-db-01"
        result, _ = p.anonymize(text)
        assert "prod-db-01" not in result

    def test_server_is(self, p):
        text = 'server is "web-frontend-03"'
        result, _ = p.anonymize(text)
        assert "web-frontend-03" not in result

    def test_server_name_colon(self, p):
        text = 'server_name: "app.mycompany.internal"'
        result, _ = p.anonymize(text)
        assert "app.mycompany.internal" not in result

    def test_db_host(self, p):
        text = 'db_host = "rds-prod-master.us-east-1"'
        result, _ = p.anonymize(text)
        assert "rds-prod-master" not in result

    def test_smtp_server(self, p):
        text = 'smtp_server = "mail.company.com"'
        result, _ = p.anonymize(text)
        assert "mail.company.com" not in result

    def test_redis_host(self, p):
        text = 'redis_host = "cache-prod-01.internal"'
        result, _ = p.anonymize(text)
        assert "cache-prod-01" not in result

    def test_load_balancer(self, p):
        text = 'load_balancer = "lb-prod-us-west.internal"'
        result, _ = p.anonymize(text)
        assert "lb-prod-us-west" not in result

    def test_dns_server(self, p):
        text = "dns_server set to ns1.company.internal"
        result, _ = p.anonymize(text)
        assert "ns1.company.internal" not in result

    def test_skip_well_known_domains(self, p):
        text = 'endpoint = "s3.amazonaws.com"'
        result, _ = p.anonymize(text)
        assert "amazonaws.com" in result


class TestGenericIdentifierUsers:
    """Test username/login/account keyword-based detection."""

    def test_username_quoted(self, p):
        text = 'username = "john.doe"'
        result, _ = p.anonymize(text)
        assert "john.doe" not in result
        assert "REDACTED_IDENTIFIER_" in result

    def test_username_unquoted(self, p):
        text = "username = admin_user"
        result, _ = p.anonymize(text)
        assert "admin_user" not in result

    def test_user_is(self, p):
        text = 'user is "jsmith"'
        result, _ = p.anonymize(text)
        assert "jsmith" not in result

    def test_login_name(self, p):
        text = 'login_name = "root"'
        result, _ = p.anonymize(text)
        assert "root" not in result

    def test_db_user(self, p):
        text = 'db_user = "postgres_admin"'
        result, _ = p.anonymize(text)
        assert "postgres_admin" not in result

    def test_ssh_user(self, p):
        text = 'ssh_user = "deploy"'
        result, _ = p.anonymize(text)
        assert "deploy" not in result

    def test_service_account(self, p):
        text = 'service_account = "svc-monitoring@project.iam"'
        result, _ = p.anonymize(text)
        assert "svc-monitoring" not in result

    def test_owner(self, p):
        text = 'owner = "jane.smith"'
        result, _ = p.anonymize(text)
        assert "jane.smith" not in result

    def test_created_by(self, p):
        text = 'created_by = "admin"'
        result, _ = p.anonymize(text)
        assert "admin" not in result


class TestGenericIdentifierAccounts:
    """Test account/org/tenant/project keyword-based detection."""

    def test_account_id(self, p):
        text = 'account_id = "acct-12345-prod"'
        result, _ = p.anonymize(text)
        assert "acct-12345-prod" not in result

    def test_customer_id(self, p):
        text = 'customer_id = "CUST-98765"'
        result, _ = p.anonymize(text)
        assert "CUST-98765" not in result

    def test_tenant_id(self, p):
        text = 'tenant_id = "t-abc123"'
        result, _ = p.anonymize(text)
        assert "t-abc123" not in result

    def test_org_name(self, p):
        text = 'org_name = "AcmeCorp"'
        result, _ = p.anonymize(text)
        assert "AcmeCorp" not in result

    def test_organization_is(self, p):
        text = 'organization is "Global Logistics Inc"'
        result, _ = p.anonymize(text)
        assert "Global Logistics Inc" not in result

    def test_project_id(self, p):
        text = 'project_id = "my-gcp-project-123"'
        result, _ = p.anonymize(text)
        assert "my-gcp-project-123" not in result

    def test_workspace_name(self, p):
        text = 'workspace_name = "production-analytics"'
        result, _ = p.anonymize(text)
        assert "production-analytics" not in result

    def test_company_name(self, p):
        text = 'company = "Acme Corporation"'
        result, _ = p.anonymize(text)
        assert "Acme Corporation" not in result

    def test_department(self, p):
        text = 'department = "Engineering"'
        result, _ = p.anonymize(text)
        assert "Engineering" not in result

    def test_employee_id(self, p):
        text = 'employee_id = "EMP-54321"'
        result, _ = p.anonymize(text)
        assert "EMP-54321" not in result


class TestGenericIdentifierInfra:
    """Test infrastructure keyword-based detection."""

    def test_cluster_name(self, p):
        text = 'cluster_name = "prod-k8s-us-east-1"'
        result, _ = p.anonymize(text)
        assert "prod-k8s-us-east-1" not in result

    def test_instance_id(self, p):
        text = 'instance_id = "i-0abc123def456"'
        result, _ = p.anonymize(text)
        assert "i-0abc123def456" not in result

    def test_container_name(self, p):
        text = 'container_name = "web-api-prod"'
        result, _ = p.anonymize(text)
        assert "web-api-prod" not in result

    def test_pod_name(self, p):
        text = 'pod_name = "api-deployment-7b9c5d-xk2lm"'
        result, _ = p.anonymize(text)
        assert "api-deployment-7b9c5d-xk2lm" not in result

    def test_namespace(self, p):
        text = 'namespace = "production"'
        result, _ = p.anonymize(text)
        assert "production" not in result

    def test_deployment_name(self, p):
        text = 'deployment_name = "api-v2-canary"'
        result, _ = p.anonymize(text)
        assert "api-v2-canary" not in result

    def test_vpc_id(self, p):
        text = 'vpc_id = "vpc-0abc123"'
        result, _ = p.anonymize(text)
        assert "vpc-0abc123" not in result

    def test_subnet_id(self, p):
        text = 'subnet_id = "subnet-0def456"'
        result, _ = p.anonymize(text)
        assert "subnet-0def456" not in result

    def test_security_group(self, p):
        text = 'security_group = "sg-prod-web"'
        result, _ = p.anonymize(text)
        assert "sg-prod-web" not in result

    def test_ami_id(self, p):
        text = 'ami_id = "ami-0abc123456789"'
        result, _ = p.anonymize(text)
        assert "ami-0abc123456789" not in result

    def test_volume_id(self, p):
        text = 'volume_id = "vol-0abcdef"'
        result, _ = p.anonymize(text)
        assert "vol-0abcdef" not in result

    def test_snapshot_id(self, p):
        text = 'snapshot_id = "snap-0abc123"'
        result, _ = p.anonymize(text)
        assert "snap-0abc123" not in result

    def test_repo_name(self, p):
        text = 'repo_name = "my-private-repo"'
        result, _ = p.anonymize(text)
        assert "my-private-repo" not in result

    def test_environment(self, p):
        text = 'environment = "staging"'
        result, _ = p.anonymize(text)
        assert "staging" not in result


class TestGenericIdentifierEndpoints:
    """Test endpoint/URL keyword-based detection."""

    def test_endpoint(self, p):
        text = 'endpoint = "https://api.internal.company.com/v2"'
        result, _ = p.anonymize(text)
        assert "internal.company.com" not in result

    def test_base_url(self, p):
        text = 'base_url = "https://dashboard.myapp.io"'
        result, _ = p.anonymize(text)
        assert "dashboard.myapp.io" not in result

    def test_webhook_url(self, p):
        text = 'webhook_url = "https://hooks.slack.com/services/T01/B02/abc123"'
        result, _ = p.anonymize(text)
        assert "hooks.slack.com" not in result

    def test_callback_url(self, p):
        text = 'callback_url = "https://myapp.com/oauth/callback"'
        result, _ = p.anonymize(text)
        assert "myapp.com" not in result

    def test_api_endpoint(self, p):
        text = 'api_endpoint = "https://api.stripe.com/v1/charges"'
        result, _ = p.anonymize(text)
        assert "api.stripe.com" not in result

    def test_grafana_url(self, p):
        text = 'grafana_url = "https://grafana.internal.corp:3000"'
        result, _ = p.anonymize(text)
        assert "grafana.internal.corp" not in result


class TestGenericIdentifierDatabase:
    """Test database keyword-based detection."""

    def test_database_name(self, p):
        text = 'database_name = "prod_customers"'
        result, _ = p.anonymize(text)
        assert "prod_customers" not in result

    def test_schema_name(self, p):
        text = 'schema_name = "billing"'
        result, _ = p.anonymize(text)
        assert "billing" not in result

    def test_table_name(self, p):
        text = 'table_name = "user_credentials"'
        result, _ = p.anonymize(text)
        assert "user_credentials" not in result

    def test_collection(self, p):
        text = 'collection = "audit_logs"'
        result, _ = p.anonymize(text)
        assert "audit_logs" not in result


class TestGenericIdentifierPaths:
    """Test file/path keyword-based detection."""

    def test_file_path(self, p):
        text = 'file_path = "/etc/myapp/secrets.yml"'
        result, _ = p.anonymize(text)
        assert "/etc/myapp/secrets.yml" not in result

    def test_config_file(self, p):
        text = 'config_file = "/opt/app/config/production.json"'
        result, _ = p.anonymize(text)
        assert "/opt/app/config/production.json" not in result

    def test_log_path(self, p):
        text = 'log_path = "/var/log/myapp/error.log"'
        result, _ = p.anonymize(text)
        assert "/var/log/myapp/error.log" not in result

    def test_backup_path(self, p):
        text = 'backup_path = "/mnt/backups/db-2024-01"'
        result, _ = p.anonymize(text)
        assert "/mnt/backups/db-2024-01" not in result


class TestGenericIdentifierNames:
    """Test name/person keyword-based detection."""

    def test_full_name(self, p):
        text = 'full_name = "John Doe"'
        result, _ = p.anonymize(text)
        assert "John Doe" not in result

    def test_first_name(self, p):
        text = 'first_name = "Alice"'
        result, _ = p.anonymize(text)
        assert "Alice" not in result

    def test_last_name(self, p):
        text = 'last_name = "Johnson"'
        result, _ = p.anonymize(text)
        assert "Johnson" not in result

    def test_contact_name(self, p):
        text = 'contact_name = "Bob Smith"'
        result, _ = p.anonymize(text)
        assert "Bob Smith" not in result

    def test_display_name(self, p):
        text = 'display_name = "admin_jane"'
        result, _ = p.anonymize(text)
        assert "admin_jane" not in result


class TestGenericIdentifierAddress:
    """Test address/location keyword-based detection."""

    def test_street_address(self, p):
        text = 'street_address = "123 Main Street"'
        result, _ = p.anonymize(text)
        assert "123 Main Street" not in result

    def test_city(self, p):
        text = 'city = "San Francisco"'
        result, _ = p.anonymize(text)
        assert "San Francisco" not in result

    def test_zip_code(self, p):
        text = 'zip_code = "94105"'
        result, _ = p.anonymize(text)
        assert "94105" not in result

    def test_postal_code(self, p):
        text = 'postal_code = "SW1A 1AA"'
        result, _ = p.anonymize(text)
        assert "SW1A 1AA" not in result


class TestGenericIdentifierGrammar:
    """Test grammar forms for identifier patterns."""

    def test_hostname_was(self, p):
        text = 'hostname was "old-server.corp"'
        result, _ = p.anonymize(text)
        assert "old-server.corp" not in result

    def test_server_will_be(self, p):
        text = 'server will be "new-server-prod"'
        result, _ = p.anonymize(text)
        assert "new-server-prod" not in result

    def test_username_set_to(self, p):
        text = 'username set to "new_admin"'
        result, _ = p.anonymize(text)
        assert "new_admin" not in result

    def test_database_should_be(self, p):
        text = 'database should be "analytics_v2"'
        result, _ = p.anonymize(text)
        assert "analytics_v2" not in result

    def test_cluster_equals(self, p):
        text = 'cluster equals "staging-us-west"'
        result, _ = p.anonymize(text)
        assert "staging-us-west" not in result

    def test_project_are(self, p):
        text = "project set as prod-backend"
        result, _ = p.anonymize(text)
        assert "prod-backend" not in result


class TestGenericIdentifierSkips:
    """Test that common non-sensitive values are skipped."""

    def test_skip_true(self, p):
        text = 'enabled = "true"'
        result, _ = p.anonymize(text)
        assert "true" in result

    def test_skip_false(self, p):
        text = 'active = "false"'
        result, _ = p.anonymize(text)
        assert "false" in result

    def test_skip_null(self, p):
        text = 'value = "null"'
        result, _ = p.anonymize(text)
        assert "null" in result

    def test_skip_none(self, p):
        text = 'setting = "none"'
        result, _ = p.anonymize(text)
        assert "none" in result

    def test_skip_default(self, p):
        text = 'env = "default"'
        result, _ = p.anonymize(text)
        assert "default" in result

    def test_skip_redacted(self, p):
        text = 'hostname = "REDACTED_IDENTIFIER_1"'
        result, _ = p.anonymize(text)
        assert result == text


class TestGenericIdentifierRoundTrip:
    """Test that identifier patterns are fully reversible."""

    def test_round_trip_hostname(self, p):
        text = 'hostname = "prod-db.internal"'
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_round_trip_username(self, p):
        text = 'username = "admin_user"'
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_round_trip_full_name(self, p):
        text = 'full_name = "Jane Doe"'
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_round_trip_unquoted(self, p):
        text = "cluster_name = prod-k8s-cluster"
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_round_trip_grammar(self, p):
        text = 'server will be "new-prod-01"'
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_multiple_identifiers(self, p):
        text = 'hostname = "web-01"\nusername = "deploy"\ndatabase = "prod_db"'
        result, mapping = p.anonymize(text)
        assert "web-01" not in result
        assert "deploy" not in result
        assert "prod_db" not in result
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_consistency(self, p):
        text = 'server = "prod-01"\nhost = "prod-01"'
        result, mapping = p.anonymize(text)
        # Same value should get same pseudonym
        lines = result.split("\n")
        pseudo1 = lines[0].split('"')[1]
        pseudo2 = lines[1].split('"')[1]
        assert pseudo1 == pseudo2


class TestCustomPattern:
    def test_register_custom(self):
        register_custom("ticket", r"TICKET-\d{4,6}", "REDACTED_TICKET_{n}")
        p = Privatiser()
        result, mapping = p.anonymize("fix TICKET-12345 and TICKET-67890")
        assert "TICKET-12345" not in result
        assert "TICKET-67890" not in result
        assert "REDACTED_TICKET_" in result
        assert len(mapping) == 2
