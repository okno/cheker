"""Explicit bootstrap for future extractors shipped in the trusted application wheel.

The default registry is deliberately empty. No XLSX/PPTX/EML/MSG/RTF/ODT support
is enabled by this module. To add a reviewed extractor, package its module, add
a literal import here and register its handler/version/dependencies below.
Never derive imports from input filenames, document contents, environment
variables, installed entry points or user-controlled paths.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .extractor_registry import ExtractorRegistry


def register_all(registry: ExtractorRegistry) -> None:
    """Register explicitly packaged handlers before the caller freezes the registry.

    Empty by design: supported built-in extraction continues through extraction.py.
    Each fresh worker calls the same bootstrap; parent-only registrations do not
    propagate to a new process and are not a production installation mechanism.
    """
    return None
