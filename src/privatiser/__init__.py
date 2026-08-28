"""Privatiser — Content anonymizer/pseudonymizer."""

# Import pattern modules to trigger registration
import privatiser.patterns.network
import privatiser.patterns.aws
import privatiser.patterns.secrets
import privatiser.patterns.pii
import privatiser.patterns.identifiers
import privatiser.patterns.cloud
import privatiser.patterns.international
import privatiser.patterns.reallife
import privatiser.patterns.names

from privatiser.core import Privatiser
from privatiser.patterns import PatternHandler
from privatiser.patterns.identifiers import register_custom

__version__ = "0.1.0"
__all__ = ["Privatiser", "PatternHandler", "register_custom"]
