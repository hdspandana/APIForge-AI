"""
extractor.py
============

Deterministic AST-based extraction logic. No LLM calls, no network access,
no `exec`/`eval` of user code -- this module only ever walks the syntax
tree produced by `ast.parse`.

Design notes
------------
* We detect route decorators of the shape `@<something>.<http_verb>(...)`
  (e.g. `@app.get(...)`, `@router.post(...)`, `@api.v1.put(...)`). We do not
  require the object to literally be named `app`, since real projects use
  `router`, `api_router`, nested routers, etc.
* Path parameters are discovered two ways and reconciled:
    1. By scanning the route path string for `{name}` / `{name:int}` style
       placeholders (Starlette path-converter syntax).
    2. By matching function parameter names against that set.
  A parameter is classified as `path` if its name appears in the route
  string, regardless of what FastAPI marker (if any) is used.
* Explicit FastAPI parameter markers used as a default value --
  `Query(...)`, `Path(...)`, `Body(...)`, `Header(...)`, `Cookie(...)` --
  are honored first, since they are an explicit, unambiguous signal from
  the author of the code.
* `Depends(...)` parameters are dependency injection, not request input,
  so they are intentionally excluded from the `parameters` list.
* `Request`/`Response`/`BackgroundTasks`-typed parameters are framework
  plumbing, not client-supplied input, and are excluded as well.
* Absent an explicit marker, primitive types (`str`, `int`, `float`,
  `bool`, `UUID`, `datetime`, `date`, `Decimal`, plus `Optional[...]` /
  `X | None` wrappers of those) are treated as `query` parameters.
  Everything else (Pydantic models, `dict`, `list`, user-defined classes,
  unannotated parameters) is treated as `body` for methods that
  conventionally carry a request body (POST/PUT/PATCH), and as `query`
  otherwise.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

# Types considered "primitive" for the purposes of query-vs-body inference.
PRIMITIVE_TYPES = {
    "str",
    "int",
    "float",
    "bool",
    "bytes",
    "UUID",
    "uuid.UUID",
    "datetime",
    "date",
    "time",
    "Decimal",
    "decimal.Decimal",
}

# Parameters typed as these (or defaulted via these) are framework plumbing,
# not client-supplied data, so we never surface them as endpoint parameters.
FRAMEWORK_TYPES = {"Request", "Response", "BackgroundTasks", "WebSocket"}

# FastAPI parameter marker functions and the location they explicitly imply.
EXPLICIT_MARKERS = {
    "Path": "path",
    "Query": "query",
    "Body": "body",
    "Header": "header",
    "Cookie": "cookie",
}

BODY_DEFAULT_METHODS = {"post", "put", "patch"}

_PATH_PARAM_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)(?::[^}]+)?\}")


@dataclass
class ExtractedParameter:
    name: str
    type: str = "Any"
    location: str = "query"
    required: bool = True
    default: Optional[str] = None


@dataclass
class ExtractedEndpoint:
    method: str
    path: str
    function: str
    parameters: List[ExtractedParameter] = field(default_factory=list)
    docstring: Optional[str] = None
    is_async: bool = False
    tags: List[str] = field(default_factory=list)


def _unparse(node: Optional[ast.AST]) -> Optional[str]:
    """Best-effort source reconstruction that never raises."""
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return None


def _base_type_name(annotation_str: Optional[str]) -> str:
    """
    Strip `Optional[...]`, `Union[..., None]`, and `X | None` wrappers down
    to the inner type name so it can be checked against PRIMITIVE_TYPES.
    Falls back to the original string when no such wrapper is present.
    """
    if not annotation_str:
        return "Any"

    s = annotation_str.strip()

    optional_match = re.fullmatch(r"Optional\[(.+)\]", s)
    if optional_match:
        return _base_type_name(optional_match.group(1))

    union_match = re.fullmatch(r"Union\[(.+)\]", s)
    if union_match:
        parts = [p.strip() for p in union_match.group(1).split(",")]
        non_none = [p for p in parts if p != "None"]
        if len(non_none) == 1:
            return _base_type_name(non_none[0])
        return s

    if "|" in s:
        parts = [p.strip() for p in s.split("|")]
        non_none = [p for p in parts if p != "None"]
        if len(non_none) == 1:
            return _base_type_name(non_none[0])

    # Strip a leading module path, e.g. "uuid.UUID" -> keep as-is (it's in
    # PRIMITIVE_TYPES already), but "models.User" -> "models.User" (unknown,
    # so it will correctly fall through to "not primitive").
    return s


def _is_optional(annotation_str: Optional[str], has_default: bool) -> bool:
    if has_default:
        return True
    if not annotation_str:
        return False
    s = annotation_str.strip()
    if s.startswith("Optional["):
        return True
    if re.search(r"\bNone\b", s) and ("|" in s or s.startswith("Union[")):
        return True
    return False


def _explicit_marker_from_default(default_node: Optional[ast.AST]):
    """
    If `default_node` is a call to one of FastAPI's parameter markers
    (Query(...), Path(...), Body(...), Header(...), Cookie(...), Depends(...)),
    return (marker_name, call_node). Otherwise return (None, None).
    """
    if default_node is None or not isinstance(default_node, ast.Call):
        return None, None

    func = default_node.func
    if isinstance(func, ast.Name):
        name = func.id
    elif isinstance(func, ast.Attribute):
        name = func.attr
    else:
        return None, None

    if name in EXPLICIT_MARKERS or name == "Depends":
        return name, default_node
    return None, None


def _default_repr_from_marker_call(call_node: ast.Call) -> Optional[str]:
    """
    For `Query(10)` or `Query(default=10)`, return the source text of the
    default value carried inside the marker call, if any explicit default
    (other than `...`) was supplied.
    """
    if call_node.args:
        first = call_node.args[0]
        if isinstance(first, ast.Constant) and first.value is Ellipsis:
            return None
        return _unparse(first)
    for kw in call_node.keywords:
        if kw.arg == "default":
            if isinstance(kw.value, ast.Constant) and kw.value.value is Ellipsis:
                return None
            return _unparse(kw.value)
    return None


def _is_marker_required(call_node: ast.Call) -> bool:
    """A marker call is 'required' when its default is literally `...`."""
    if call_node.args:
        first = call_node.args[0]
        return isinstance(first, ast.Constant) and first.value is Ellipsis
    for kw in call_node.keywords:
        if kw.arg == "default":
            return isinstance(kw.value, ast.Constant) and kw.value.value is Ellipsis
    # No default/args supplied at all, e.g. bare `Query()` -> required.
    return True


def _decorator_route_info(decorator: ast.AST):
    """
    If `decorator` is a call like `<obj>.<method>("/path", ...)`, return
    (http_method_upper, path_string, tags_list). Otherwise return None.
    """
    if not isinstance(decorator, ast.Call):
        return None
    if not isinstance(decorator.func, ast.Attribute):
        return None

    method_name = decorator.func.attr.lower()
    if method_name not in HTTP_METHODS:
        return None

    path_value = None
    if decorator.args:
        first_arg = decorator.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            path_value = first_arg.value
    if path_value is None:
        for kw in decorator.keywords:
            if kw.arg == "path" and isinstance(kw.value, ast.Constant):
                path_value = kw.value.value

    if path_value is None:
        # A route decorator with no discoverable literal path is still a
        # route; surface it with an empty path rather than dropping it.
        path_value = ""

    tags: List[str] = []
    for kw in decorator.keywords:
        if kw.arg == "tags" and isinstance(kw.value, (ast.List, ast.Tuple)):
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    tags.append(elt.value)

    return method_name.upper(), path_value, tags


def _path_param_names(path: str) -> set:
    return set(_PATH_PARAM_RE.findall(path))


def _classify_parameter(
    *,
    name: str,
    annotation_str: Optional[str],
    default_node: Optional[ast.AST],
    http_method: str,
    path_param_names: set,
) -> Optional[ExtractedParameter]:
    """
    Returns an ExtractedParameter, or None if this parameter should be
    excluded entirely (e.g. Depends(), Request-typed, self/cls).
    """
    if name in ("self", "cls"):
        return None

    base_type = _base_type_name(annotation_str)

    # Framework-injected objects (Request, Response, BackgroundTasks, ...)
    # are not client-supplied parameters.
    if base_type in FRAMEWORK_TYPES or base_type.split(".")[-1] in FRAMEWORK_TYPES:
        return None

    marker_name, marker_call = _explicit_marker_from_default(default_node)
    if marker_name == "Depends":
        return None

    has_default = default_node is not None
    is_required = not _is_optional(annotation_str, has_default)
    default_repr = _unparse(default_node) if has_default else None

    if marker_name in EXPLICIT_MARKERS:
        location = EXPLICIT_MARKERS[marker_name]
        is_required = _is_marker_required(marker_call)
        default_repr = _default_repr_from_marker_call(marker_call)
        return ExtractedParameter(
            name=name,
            type=annotation_str or "Any",
            location=location,
            required=is_required,
            default=default_repr,
        )

    # No explicit marker: infer from path membership, then primitiveness.
    if name in path_param_names:
        return ExtractedParameter(
            name=name,
            type=annotation_str or "Any",
            location="path",
            required=True,  # FastAPI path params are always required.
            default=None,
        )

    if base_type in PRIMITIVE_TYPES or base_type == "Any":
        # Unannotated, non-path-matching, non-body-method params default to
        # query -- this mirrors FastAPI's own inference rules for GET/DELETE
        # and for primitives on any method.
        return ExtractedParameter(
            name=name,
            type=annotation_str or "Any",
            location="query",
            required=is_required,
            default=default_repr,
        )

    # Complex / model / list / dict type with no explicit marker.
    if http_method in BODY_DEFAULT_METHODS:
        location = "body"
    else:
        location = "query"

    return ExtractedParameter(
        name=name,
        type=annotation_str or "Any",
        location=location,
        required=is_required,
        default=default_repr,
    )


def _extract_parameters(func_node, http_method: str, path: str) -> List[ExtractedParameter]:
    args_obj = func_node.args
    path_param_names = _path_param_names(path)

    positional = list(args_obj.posonlyargs) + list(args_obj.args)
    defaults = list(args_obj.defaults)
    # Right-align defaults with positional args (defaults apply to the
    # trailing N positional args).
    pad = len(positional) - len(defaults)
    default_nodes = [None] * pad + defaults

    kwonly = list(args_obj.kwonlyargs)
    kwonly_defaults = list(args_obj.kw_defaults)

    results: List[ExtractedParameter] = []

    for arg_node, default_node in zip(positional, default_nodes):
        annotation_str = _unparse(arg_node.annotation)
        param = _classify_parameter(
            name=arg_node.arg,
            annotation_str=annotation_str,
            default_node=default_node,
            http_method=http_method,
            path_param_names=path_param_names,
        )
        if param is not None:
            results.append(param)

    for arg_node, default_node in zip(kwonly, kwonly_defaults):
        annotation_str = _unparse(arg_node.annotation)
        param = _classify_parameter(
            name=arg_node.arg,
            annotation_str=annotation_str,
            default_node=default_node,
            http_method=http_method,
            path_param_names=path_param_names,
        )
        if param is not None:
            results.append(param)

    return results


class FastAPIRouteVisitor(ast.NodeVisitor):
    """
    Walks a module's top-level and class-level function definitions,
    collecting every one decorated with an HTTP-verb route decorator.
    """

    def __init__(self) -> None:
        self.endpoints: List[ExtractedEndpoint] = []

    def _handle_function(self, node) -> None:
        is_async = isinstance(node, ast.AsyncFunctionDef)

        for decorator in node.decorator_list:
            route_info = _decorator_route_info(decorator)
            if route_info is None:
                continue

            http_method, path, tags = route_info
            parameters = _extract_parameters(node, http_method.lower(), path)
            docstring = ast.get_docstring(node)

            self.endpoints.append(
                ExtractedEndpoint(
                    method=http_method,
                    path=path,
                    function=node.name,
                    parameters=parameters,
                    docstring=docstring,
                    is_async=is_async,
                    tags=tags,
                )
            )
            # A function could theoretically carry more than one route
            # decorator (e.g. GET and HEAD on the same handler); keep
            # scanning the rest of the decorator list instead of breaking.

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._handle_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._handle_function(node)


def extract_endpoints(tree: ast.AST) -> List[ExtractedEndpoint]:
    """Public entry point used by api_parser.py."""
    visitor = FastAPIRouteVisitor()
    visitor.visit(tree)
    return visitor.endpoints
