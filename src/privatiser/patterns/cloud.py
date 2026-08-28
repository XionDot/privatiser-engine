"""Cloud provider patterns: Azure, GCP identifiers."""

import re

from . import PatternHandler, register


def _azure_sub_transform(match: re.Match) -> tuple[str, str]:
    """Preserve '/subscriptions/' prefix, anonymize the GUID."""
    return match.group(1), "/subscriptions/"


def _gcp_project_transform(match: re.Match) -> tuple[str, str]:
    """Preserve 'projects/' or 'project_id=' prefix, anonymize the project ID."""
    prefix = match.group(1)
    project_id = match.group(2)
    return project_id, prefix


register(
    # Azure subscription IDs (GUIDs in /subscriptions/ context)
    PatternHandler(
        name="azure_subscription",
        category="cloud",
        regex=re.compile(
            r"/subscriptions/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
        ),
        pseudonym_fn=lambda n: f"00000000-0000-4000-a000-{n:012d}",
        priority=18,
        match_transform=_azure_sub_transform,
    ),

    # GCP project IDs (projects/my-project-id or project_id = "my-project-id")
    PatternHandler(
        name="gcp_project",
        category="cloud",
        regex=re.compile(
            r"(projects/)([a-z][a-z0-9\-]{4,28}[a-z0-9])"
        ),
        pseudonym_fn=lambda n: f"redacted-project-{n}",
        priority=22,
        match_transform=_gcp_project_transform,
    ),
)
