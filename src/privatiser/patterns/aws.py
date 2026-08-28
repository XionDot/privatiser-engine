"""AWS-specific patterns: Account IDs, ARNs, S3 buckets."""

import re

from . import PatternHandler, register


def _arn_transform(match: re.Match) -> tuple[str, str]:
    """Extract ARN components for structured pseudonymization."""
    return match.group(0), ""


def _arn_pseudonym_factory():
    """ARN pseudonyms need to preserve service/region structure."""
    # This is handled specially in core.py via match_transform
    # The pseudonym_fn here is a fallback
    return lambda n: f"arn:aws:service:us-east-1:{100000000000 + n}:resource/redacted-{n}"


register(
    # ARNs (must come before account ID to avoid partial matching)
    PatternHandler(
        name="arn",
        category="arn",
        regex=re.compile(
            r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"'`\]}>),$]+"
        ),
        pseudonym_fn=_arn_pseudonym_factory(),
        priority=20,
    ),

    # AWS Account IDs (12 digits in context)
    PatternHandler(
        name="aws_account_id",
        category="account",
        regex=re.compile(r'(?<=[:"/])\d{12}(?=[:/"\s])'),
        pseudonym_fn=lambda n: f"{100000000000 + n}",
        priority=30,
    ),

    # S3 bucket names (in s3:// or s3::: URIs)
    PatternHandler(
        name="s3_bucket",
        category="bucket",
        regex=re.compile(
            r"(?<=(?:s3://|s3:::))[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]"
        ),
        pseudonym_fn=lambda n: f"redacted-bucket-{n}",
        priority=25,
    ),
)
