"""Command-line interface for Privatiser."""

from __future__ import annotations

import json
import re
import sys

import click

from privatiser import Privatiser
from privatiser.core import CATEGORY_GROUPS

CATEGORY_NAMES = list(CATEGORY_GROUPS.keys())


@click.group()
@click.version_option(package_name="privatiser")
def main():
    """Privatiser — Anonymize sensitive content before sharing with AI."""

# Key name patterns that indicate the value is a secret
_SECRET_KEY_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|key|credential|auth|private)"
    r"|(?:.*_(?:password|passwd|pwd|secret|token|key|credential|auth))",
    re.IGNORECASE,
)


def _anonymize_env(p: Privatiser, text: str) -> tuple[str, dict]:
    """Anonymize a .env file, preserving keys and comments.

    - Pattern-detected values (IPs, API keys, etc.) are always anonymized.
    - Values whose KEY name suggests a secret are also anonymized, even
      if no pattern matches them.
    """
    lines = text.splitlines(keepends=True)
    result_lines = []
    all_mapping: dict[str, str] = {}
    env_secret_counter = 1

    for line in lines:
        stripped = line.strip()
        # Preserve comments and blank lines
        if not stripped or stripped.startswith("#"):
            result_lines.append(line)
            continue
        # Parse KEY=VALUE
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            # Strip optional quotes from value
            raw_value = value.strip()
            quote = ""
            if len(raw_value) >= 2 and raw_value[0] in ('"', "'") and raw_value[-1] == raw_value[0]:
                quote = raw_value[0]
                raw_value = raw_value[1:-1]

            # First pass: try pattern-based anonymization
            prev_count = len(all_mapping)
            anon_value, mapping = p.anonymize(raw_value)
            all_mapping.update(mapping)
            matched_something = len(all_mapping) > prev_count

            # Second pass: if the key looks secret but nothing was matched,
            # redact the entire value
            if not matched_something and raw_value and _SECRET_KEY_RE.search(key):
                pseudonym = f"REDACTED_ENV_{env_secret_counter}"
                env_secret_counter += 1
                all_mapping[pseudonym] = raw_value
                anon_value = pseudonym

            result_lines.append(f"{key}={quote}{anon_value}{quote}\n")
        else:
            result_lines.append(line)
    return "".join(result_lines), all_mapping


@main.command()
@click.argument("input", default="-", type=click.File("r"))
@click.option("-o", "--output", type=click.File("w"), default="-", help="Output file (default: stdout)")
@click.option("-m", "--mapping-file", type=click.Path(), help="Save pseudonym mapping to JSON file")
@click.option("-c", "--clipboard", is_flag=True, help="Read input from clipboard")
@click.option("-d", "--disable", multiple=True, type=click.Choice(CATEGORY_NAMES, case_sensitive=False),
              help="Disable a pattern category (can be repeated)")
@click.option("--allowlist", "allowlist_file", type=click.Path(exists=True),
              help="File with values to skip (one per line)")
@click.option("--env", "env_mode", is_flag=True,
              help="Treat input as .env file: only anonymize values, keep keys and comments")
def anonymize(input, output, mapping_file, clipboard, disable, allowlist_file, env_mode):
    """Anonymize sensitive content.

    Reads from FILE (or stdin if omitted). Use -c to read from clipboard.

    Examples:

        cat config.tf | privatiser anonymize -m mapping.json

        privatiser anonymize config.tf -o clean.tf -m mapping.json

        privatiser anonymize -c -m mapping.json

        privatiser anonymize .env --env

        privatiser anonymize config.tf -d pii -d aws
    """
    if clipboard:
        import pyperclip
        text = pyperclip.paste()
        if not text:
            click.echo("Clipboard is empty.", err=True)
            sys.exit(1)
    else:
        text = input.read()

    enabled_categories = {cat: (cat not in disable) for cat in CATEGORY_NAMES} if disable else None
    allowlist = None
    if allowlist_file:
        with open(allowlist_file) as f:
            allowlist = [line.strip() for line in f if line.strip()]

    p = Privatiser(enabled_categories=enabled_categories, allowlist=allowlist)

    if env_mode:
        result, mapping = _anonymize_env(p, text)
    else:
        result, mapping = p.anonymize(text)
    output.write(result)

    if mapping_file:
        with open(mapping_file, "w") as f:
            json.dump(mapping, f, indent=2)
        click.echo(f"Mapping saved to {mapping_file}", err=True)

    if not output.isatty() or output.name != "<stdout>":
        # If writing to a file or pipe, also show summary on stderr
        count = len(mapping)
        if count:
            click.echo(f"Anonymized {count} item(s).", err=True)


@main.command()
@click.argument("input", default="-", type=click.File("r"))
@click.option("-m", "--mapping-file", type=click.Path(exists=True), required=True,
              help="JSON mapping file from a previous anonymize run")
@click.option("-o", "--output", type=click.File("w"), default="-", help="Output file (default: stdout)")
def deanonymize(input, output, mapping_file):
    """Restore original content using a saved mapping.

    Examples:

        privatiser deanonymize clean.tf -m mapping.json

        cat clean.tf | privatiser deanonymize -m mapping.json -o restored.tf
    """
    text = input.read()
    with open(mapping_file) as f:
        mapping = json.load(f)

    p = Privatiser()
    result = p.deanonymize(text, mapping)
    output.write(result)


@main.command()
@click.option("--port", default=7860, type=int, help="Port to run the web UI on")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--debug", is_flag=True, help="Run in debug mode")
def ui(port, host, debug):
    """Launch the Privatiser web UI."""
    try:
        from privatiser.web.app import create_app
    except ImportError:
        click.echo("Flask is required for the web UI. Install it with:", err=True)
        click.echo("  pip install privatiser[web]", err=True)
        sys.exit(1)

    app = create_app()
    click.echo(f"Starting Privatiser UI at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
