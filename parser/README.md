# APIForge AI — FastAPI Source Parser

A deterministic, dependency-light Python module that parses FastAPI source
code and extracts structured API metadata as JSON — **no LLM calls, no
network access, no code execution**. It works entirely off Python's built-in
`ast` module, so it's safe to run on arbitrary/untrusted source and always
produces a well-defined result, even for invalid Python.

## Why AST and not regex / LLM?

- **Deterministic**: same input always produces the same output. No prompt
  drift, no hallucinated field names, no API latency or cost.
- **Accurate**: `ast` understands real Python scoping, decorators, and type
  annotations — it doesn't get confused by strings that look like decorators
  in comments/docstrings, multi-line signatures, etc.
- **Safe**: source is parsed, never executed (no `eval`/`exec`/`importlib`).

## Project layout

```
parser/
├── api_parser.py    # Main entry point: parse_fastapi_code()
├── extractor.py      # AST NodeVisitor + classification logic
├── models.py          # Pydantic schema (Endpoint, Parameter, ParseResult, ParseError)
├── test_parser.py    # Pytest suite
└── README.md
```

## Requirements

- Python 3.9+ (uses `ast.unparse`, available since 3.9)
- `pydantic>=2.0`
- `pytest` (dev/test only)

```bash
pip install "pydantic>=2.0" pytest
```

## Usage

### As a library

```python
from api_parser import parse_fastapi_code

source = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/users/{id}")
def get_user(id: int, verbose: bool = False):
    """Fetch a single user."""
    return {"id": id}
'''

result = parse_fastapi_code(source)
print(result)
```

```json
{
  "endpoints": [
    {
      "method": "GET",
      "path": "/users/{id}",
      "function": "get_user",
      "parameters": [
        {"name": "id", "type": "int", "location": "path", "required": true, "default": null},
        {"name": "verbose", "type": "bool", "location": "query", "required": false, "default": "False"}
      ],
      "docstring": "Fetch a single user.",
      "is_async": false,
      "tags": []
    }
  ]
}
```

You can also pass a **file path** instead of raw source — the function
auto-detects which one it received:

```python
result = parse_fastapi_code("my_service/routes/users.py")
```

### From the command line

```bash
python api_parser.py path/to/fastapi_app.py
```

Pretty-prints the resulting JSON to stdout.

### Error handling

Invalid Python never raises — it returns a `ParseError`-shaped dict instead:

```python
>>> parse_fastapi_code("def broken(:\n    pass")
{
  "error": "Invalid Python syntax: invalid syntax",
  "error_type": "SyntaxError",
  "line": 1,
  "column": 12,
  "detail": "def broken(:"
}
```

Callers can distinguish "parsed successfully, zero routes found"
(`{"endpoints": []}`) from "failed to parse" (`{"error": ..., ...}`) by
checking which key is present.

## Parameter classification rules

For each handler parameter, in priority order:

1. **Explicit FastAPI markers win.** A default value of `Path(...)`,
   `Query(...)`, `Body(...)`, `Header(...)`, or `Cookie(...)` sets the
   location directly, and `required` is derived from whether the marker's
   default is the `...` (Ellipsis) sentinel.
2. **`Depends(...)` parameters are excluded** from the output entirely —
   they're dependency injection, not client-supplied request data.
3. **Framework objects are excluded** — parameters typed `Request`,
   `Response`, `BackgroundTasks`, or `WebSocket` aren't request input.
4. **Name matches a `{placeholder}` in the route path → `path`.** Path
   parameters are always `required: true`, matching FastAPI's own behavior.
5. **Primitive type (or no annotation) → `query`.** Recognized primitives:
   `str`, `int`, `float`, `bool`, `bytes`, `UUID`, `datetime`, `date`,
   `time`, `Decimal` — including when wrapped in `Optional[...]` or
   `X | None`.
6. **Everything else (Pydantic models, `dict`, `list`, custom classes)
   → `body`** on `POST` / `PUT` / `PATCH`, or **`query`** on methods that
   conventionally have no body (`GET`, `DELETE`, etc.).

`required` is `False` whenever the parameter has any default value, or its
annotation is `Optional[...]` / `... | None`.

## Route detection

Any decorator of the shape `<object>.<verb>("/path", ...)` is treated as a
route, where `<verb>` is one of `get`, `post`, `put`, `delete`, `patch`,
`options`, `head` — regardless of whether `<object>` is named `app`,
`router`, `api_router`, etc. This matches how real FastAPI projects
structure routers across multiple files.

`tags=[...]` on the decorator and the function's docstring/`async` status
are captured as extra metadata beyond the minimum required schema.

## Running tests

```bash
pytest test_parser.py -v
```

The suite covers: path params, query params (including `Optional` and
unannotated), body inference for Pydantic models, explicit
`Query`/`Path`/`Body` markers, `Depends`/`Request` exclusion, async
handlers, docstrings, tags, multiple endpoints, routers other than `app`,
and error handling for invalid syntax / non-string input / empty source /
missing files.

## Known limitations

- Only decorator calls with a **literal string** path (e.g. `@app.get("/x")`)
  are matched; a path built from a variable (`@app.get(SOME_PATH_CONST)`)
  will be recorded with an empty `path` string, since AST alone can't
  resolve arbitrary runtime values.
- Type annotations are captured as their **source text** (via
  `ast.unparse`), not resolved to actual Python types — this is sufficient
  for classification and downstream display, but doesn't validate that the
  imported type actually exists.
- Dependency-injected sub-parameters (i.e. parameters *inside* a function
  passed to `Depends(...)`) are not recursively expanded; only the
  top-level handler's own parameters are extracted.
