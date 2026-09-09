"""
api_parser.py
=============

Main entry point for APIForge AI's FastAPI source parser.

    from api_parser import parse_fastapi_code

    result = parse_fastapi_code(source_code_or_path)
    # result is always a dict, either matching the ParseResult schema
    # ({"endpoints": [...]}) or the ParseError schema ({"error": ...}).

This module performs no network calls and never calls an LLM. It is 100%
deterministic: the same source will always produce the same output.
"""

from __future__ import annotations

import ast
import os
from dataclasses import asdict
from typing import Any, Dict, Union

from pydantic import ValidationError

from extractor import extract_endpoints
from models import Endpoint, ParseError, ParseResult

__all__ = ["parse_fastapi_code", "parse_fastapi_file"]


def _looks_like_a_path(source: str) -> bool:
    """
    Heuristic: treat the input as a file path only if it has no newlines
    and actually exists on disk. This avoids accidentally trying to
    `os.path.exists()` on multi-kilobyte source strings, and avoids
    misclassifying a one-line source snippet as a path.
    """
    if "\n" in source:
        return False
    if len(source) > 4096:
        return False
    return os.path.isfile(source)


def _read_source(source: str) -> str:
    if _looks_like_a_path(source):
        with open(source, "r", encoding="utf-8") as f:
            return f.read()
    return source


def _error_dict(
    message: str, error_type: str, line: int = None, column: int = None, detail: str = None
) -> Dict[str, Any]:
    err = ParseError(
        error=message,
        error_type=error_type,
        line=line,
        column=column,
        detail=detail,
    )
    return err.model_dump()


def parse_fastapi_code(source: str) -> Dict[str, Any]:
    """
    Parse FastAPI source code and return structured endpoint metadata.

    Parameters
    ----------
    source : str
        Either raw Python source code, or a path to a `.py` file on disk.
        Path-vs-raw-code detection is automatic (see `_looks_like_a_path`).

    Returns
    -------
    dict
        On success: {"endpoints": [...]} matching the `ParseResult` schema.
        On failure: {"error": ..., "error_type": ..., "line": ..., ...}
        matching the `ParseError` schema. This function never raises for
        malformed input -- it always returns a JSON-serializable dict.
    """
    if not isinstance(source, str):
        return _error_dict(
            message=f"Expected a string (source code or file path), got {type(source).__name__}.",
            error_type="TypeError",
        )

    try:
        code = _read_source(source)
    except OSError as exc:
        return _error_dict(
            message=f"Could not read source file: {exc}",
            error_type=type(exc).__name__,
        )

    if code.strip() == "":
        return ParseResult(endpoints=[]).model_dump()

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return _error_dict(
            message=f"Invalid Python syntax: {exc.msg}",
            error_type="SyntaxError",
            line=exc.lineno,
            column=exc.offset,
            detail=exc.text.strip() if exc.text else None,
        )
    except ValueError as exc:
        # e.g. source contains null bytes.
        return _error_dict(
            message=f"Could not parse source: {exc}",
            error_type=type(exc).__name__,
        )

    try:
        raw_endpoints = extract_endpoints(tree)
    except Exception as exc:  # pragma: no cover - defensive catch-all
        # The extractor is designed to never raise, but if some pathological
        # input finds a gap in that guarantee, fail soft rather than crash
        # the caller.
        return _error_dict(
            message=f"Internal error while extracting endpoints: {exc}",
            error_type=type(exc).__name__,
        )

    try:
        endpoints = [Endpoint(**asdict(ep)) for ep in raw_endpoints]
        result = ParseResult(endpoints=endpoints)
    except ValidationError as exc:
        return _error_dict(
            message="Extracted data failed schema validation.",
            error_type="ValidationError",
            detail=str(exc),
        )

    return result.model_dump()


def parse_fastapi_file(path: str) -> Dict[str, Any]:
    """Convenience alias that is explicit about expecting a file path."""
    return parse_fastapi_code(path)


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python api_parser.py <path_to_fastapi_file.py>", file=sys.stderr)
        sys.exit(1)

    output = parse_fastapi_code(sys.argv[1])
    print(json.dumps(output, indent=2))
