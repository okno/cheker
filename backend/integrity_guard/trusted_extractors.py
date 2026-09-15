"""Explicit bootstrap for extractors shipped in the trusted application wheel.

Only the limited static XLSX profile is registered. PPTX/EML/MSG/RTF/ODT support
is not enabled by this module. To add a reviewed extractor, package its module, add
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

    Built-in extraction continues through extraction.py.
    Each fresh worker calls the same bootstrap; parent-only registrations do not
    propagate to a new process and are not a production installation mechanism.
    """
    from .xlsx_extractor import extract_xlsx

    registry.register_extractor("xlsx", (".xlsx",), "1.0.0", extract_xlsx, ("defusedxml",))
