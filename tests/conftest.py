"""Shared test fixtures."""

import pytest

from privatiser import Privatiser


@pytest.fixture
def p():
    """Fresh Privatiser instance."""
    return Privatiser()


@pytest.fixture
def sample_config():
    """Realistic config text with multiple sensitive data types."""
    return """\
# Database config
db_host = "prod-db.mycompany.com"
db_port = 5432
password = "SuperSecret123!"
connection = "postgresql://admin:s3cret@prod-db.mycompany.com:5432/appdb"

# AWS
account_id = "123456789012"
role_arn = arn:aws:iam::123456789012:role/deploy-prod
s3_logs = s3://my-prod-logs-bucket/2024/

# Network
server_ip = "192.168.1.100"
cidr = "10.0.0.0/16"
contact = "admin@mycompany.com"

# API keys
OPENAI_KEY = "sk-proj-FAKEabcdefghijklmnopqrstuvwxyzTESTVALUE"
"""
