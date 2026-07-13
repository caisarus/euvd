# SPDX-License-Identifier: EUPL-1.2
"""Typed errors for SBOM parsing and format detection."""

from __future__ import annotations


class SbomParseError(Exception):
    """Raised when an SBOM document cannot be parsed. Carries file/position context."""


class UnsupportedFormatError(Exception):
    """Raised when a document is valid JSON but neither CycloneDX nor SPDX."""
