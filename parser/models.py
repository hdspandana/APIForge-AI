"""
models.py
=========

Pydantic schema definitions used to validate and serialize the output of the
APIForge AI FastAPI parser.

These models are intentionally strict (`extra="forbid"`) so that any drift
between the extractor logic and the documented output contract is caught
immediately via a `pydantic.ValidationError` rather than silently shipping
malformed JSON to downstream consumers (e.g. an LLM prompt builder, a UI,
or another service).
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

# Where a parameter's value is expected to come from on an incoming HTTP
# request. This intentionally covers more than just "path" / "query" so the
# parser degrades gracefully for header/cookie/dependency-injected params
# instead of misclassifying them.
ParameterLocation = Literal["path", "query", "body", "header", "cookie"]

HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


class Parameter(BaseModel):
    """A single function parameter belonging to an endpoint handler."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Parameter name as it appears in the function signature.")
    type: str = Field(
        default="Any",
        description="Best-effort string representation of the type annotation. "
        "'Any' when no annotation is present in the source.",
    )
    location: ParameterLocation = Field(
        ..., description="Where this parameter is sourced from on the HTTP request."
    )
    required: bool = Field(
        default=True,
        description="False if the parameter has a default value / is Optional.",
    )
    default: Optional[str] = Field(
        default=None,
        description="Source-level repr of the default value, if any (e.g. '10', \"'active'\").",
    )


class Endpoint(BaseModel):
    """A single detected FastAPI route handler."""

    model_config = ConfigDict(extra="forbid")

    method: HttpMethod
    path: str = Field(..., description="Route path, e.g. '/users/{id}'.")
    function: str = Field(..., description="Name of the Python function handling this route.")
    parameters: List[Parameter] = Field(default_factory=list)
    docstring: Optional[str] = Field(
        default=None, description="Function docstring, if present, else None."
    )
    is_async: bool = Field(default=False, description="Whether the handler is 'async def'.")
    tags: List[str] = Field(
        default_factory=list, description="Tags passed to the route decorator, if any."
    )


class ParseResult(BaseModel):
    """Top-level successful parse output. Matches the required output contract."""

    model_config = ConfigDict(extra="forbid")

    endpoints: List[Endpoint] = Field(default_factory=list)


class ParseError(BaseModel):
    """
    Returned instead of ParseResult when the input cannot be parsed at all
    (e.g. a SyntaxError). Kept separate from ParseResult so callers can
    reliably distinguish "zero endpoints found" from "parsing failed".
    """

    model_config = ConfigDict(extra="forbid")

    error: str = Field(..., description="Human-readable error message.")
    error_type: str = Field(..., description="Exception class name, e.g. 'SyntaxError'.")
    line: Optional[int] = Field(default=None, description="1-based line number, if available.")
    column: Optional[int] = Field(default=None, description="0-based column offset, if available.")
    detail: Optional[str] = Field(default=None, description="Additional context, if any.")
