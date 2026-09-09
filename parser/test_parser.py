"""
test_parser.py
===============

Pytest suite for APIForge AI's deterministic FastAPI parser.

Run with:
    pytest test_parser.py -v
"""

import textwrap

import pytest

from api_parser import parse_fastapi_code


def _endpoint_by_function(result: dict, function_name: str) -> dict:
    matches = [e for e in result["endpoints"] if e["function"] == function_name]
    assert matches, f"No endpoint found for function '{function_name}'"
    return matches[0]


def _param_by_name(endpoint: dict, name: str) -> dict:
    matches = [p for p in endpoint["parameters"] if p["name"] == name]
    assert matches, f"No parameter '{name}' found on endpoint '{endpoint['function']}'"
    return matches[0]


class TestBasicPathParameters:
    def test_simple_path_param(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/users/{id}")
            def get_user(id: int):
                return {"id": id}
            """
        )
        result = parse_fastapi_code(source)
        assert "endpoints" in result
        assert len(result["endpoints"]) == 1

        ep = result["endpoints"][0]
        assert ep["method"] == "GET"
        assert ep["path"] == "/users/{id}"
        assert ep["function"] == "get_user"
        assert ep["is_async"] is False

        param = _param_by_name(ep, "id")
        assert param["type"] == "int"
        assert param["location"] == "path"
        assert param["required"] is True

    def test_multiple_path_params(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/orgs/{org_id}/users/{user_id}")
            def get_org_user(org_id: str, user_id: str):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "get_org_user")
        names_and_locations = {p["name"]: p["location"] for p in ep["parameters"]}
        assert names_and_locations == {"org_id": "path", "user_id": "path"}


class TestQueryParameters:
    def test_primitive_defaults_to_query(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/items")
            def list_items(limit: int = 10, offset: int = 0):
                return []
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "list_items")

        limit = _param_by_name(ep, "limit")
        assert limit["location"] == "query"
        assert limit["required"] is False
        assert limit["default"] == "10"

        offset = _param_by_name(ep, "offset")
        assert offset["location"] == "query"
        assert offset["default"] == "0"

    def test_optional_query_param(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            from typing import Optional
            app = FastAPI()

            @app.get("/search")
            def search(q: Optional[str] = None):
                return []
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "search")
        q = _param_by_name(ep, "q")
        assert q["location"] == "query"
        assert q["required"] is False
        assert q["type"] == "Optional[str]"

    def test_unannotated_param_treated_as_query_on_get(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/legacy")
            def legacy_endpoint(mode):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "legacy_endpoint")
        mode = _param_by_name(ep, "mode")
        assert mode["type"] == "Any"
        assert mode["location"] == "query"


class TestBodyParameters:
    def test_pydantic_model_on_post_is_body(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            from pydantic import BaseModel
            app = FastAPI()

            class UserCreate(BaseModel):
                name: str
                email: str

            @app.post("/users")
            def create_user(payload: UserCreate):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "create_user")
        assert ep["method"] == "POST"

        payload = _param_by_name(ep, "payload")
        assert payload["type"] == "UserCreate"
        assert payload["location"] == "body"
        assert payload["required"] is True

    def test_complex_type_on_get_is_not_body(self):
        # GET requests conventionally have no body, so a complex/unannotated
        # type on a GET should fall back to query rather than body.
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/weird")
            def weird_get(filters):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "weird_get")
        filters = _param_by_name(ep, "filters")
        assert filters["location"] == "query"

    def test_path_and_body_combined(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            from pydantic import BaseModel
            app = FastAPI()

            class UserUpdate(BaseModel):
                name: str

            @app.put("/users/{user_id}")
            def update_user(user_id: int, payload: UserUpdate):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "update_user")
        assert ep["method"] == "PUT"
        assert _param_by_name(ep, "user_id")["location"] == "path"
        assert _param_by_name(ep, "payload")["location"] == "body"


class TestExplicitFastAPIMarkers:
    def test_explicit_query_path_body_markers(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI, Query, Path, Body
            app = FastAPI()

            @app.put("/users/{user_id}/profile")
            def update_profile(
                user_id: str = Path(...),
                bio: str = Body(...),
                tag: str = Query(default="x"),
            ):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "update_profile")

        user_id = _param_by_name(ep, "user_id")
        assert user_id["location"] == "path"
        assert user_id["required"] is True

        bio = _param_by_name(ep, "bio")
        assert bio["location"] == "body"
        assert bio["required"] is True

        tag = _param_by_name(ep, "tag")
        assert tag["location"] == "query"
        assert tag["required"] is False
        assert tag["default"] == "'x'"

    def test_depends_is_excluded(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI, Depends
            app = FastAPI()

            def get_db():
                return None

            @app.get("/things")
            def list_things(db=Depends(get_db)):
                return []
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "list_things")
        assert ep["parameters"] == []

    def test_request_object_is_excluded(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI, Request
            app = FastAPI()

            @app.get("/raw")
            def raw_handler(request: Request):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "raw_handler")
        assert ep["parameters"] == []


class TestAsyncAndMetadata:
    def test_async_handler_detected(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/ping")
            async def ping():
                return "pong"
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "ping")
        assert ep["is_async"] is True
        assert ep["parameters"] == []

    def test_docstring_captured(self):
        source = textwrap.dedent(
            '''
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/health")
            def health_check():
                """Simple health check endpoint."""
                return {"status": "ok"}
            '''
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "health_check")
        assert ep["docstring"] == "Simple health check endpoint."

    def test_missing_docstring_is_none(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/no-doc")
            def no_doc():
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "no_doc")
        assert ep["docstring"] is None

    def test_tags_captured(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/users", tags=["users", "public"])
            def list_users():
                return []
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "list_users")
        assert ep["tags"] == ["users", "public"]

    def test_router_object_other_than_app(self):
        source = textwrap.dedent(
            """
            from fastapi import APIRouter
            router = APIRouter()

            @router.delete("/items/{item_id}")
            def delete_item(item_id: int):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        ep = _endpoint_by_function(result, "delete_item")
        assert ep["method"] == "DELETE"


class TestMultipleEndpoints:
    def test_multiple_endpoints_all_captured(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/a")
            def a():
                return {}

            @app.post("/b")
            def b():
                return {}

            @app.delete("/c/{id}")
            def c(id: int):
                return {}
            """
        )
        result = parse_fastapi_code(source)
        methods = sorted(e["method"] for e in result["endpoints"])
        assert methods == ["DELETE", "GET", "POST"]

    def test_non_route_functions_ignored(self):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            def helper():
                return 42

            @app.get("/only-this-one")
            def only_this_one():
                return {}
            """
        )
        result = parse_fastapi_code(source)
        functions = [e["function"] for e in result["endpoints"]]
        assert functions == ["only_this_one"]


class TestErrorHandling:
    def test_invalid_syntax_returns_error_dict(self):
        source = "def broken(:\n    pass"
        result = parse_fastapi_code(source)
        assert "error" in result
        assert result["error_type"] == "SyntaxError"
        assert isinstance(result["line"], int)
        assert "endpoints" not in result

    def test_empty_source_returns_empty_endpoints(self):
        result = parse_fastapi_code("")
        assert result == {"endpoints": []}

    def test_valid_python_with_no_routes(self):
        source = "x = 1\ny = 2\n"
        result = parse_fastapi_code(source)
        assert result == {"endpoints": []}

    def test_non_string_input_returns_error(self):
        result = parse_fastapi_code(12345)  # type: ignore[arg-type]
        assert "error" in result
        assert result["error_type"] == "TypeError"

    def test_error_result_never_raises_for_garbage_input(self):
        garbage_inputs = [
            "@@@ not python at all @@@",
            "class Foo(:\n    pass",
            "\t\tmismatched indentation\n  here",
        ]
        for g in garbage_inputs:
            result = parse_fastapi_code(g)
            assert "error" in result


class TestFileInput:
    def test_parses_from_file_path(self, tmp_path):
        source = textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/from-file/{x}")
            def from_file(x: int):
                return {}
            """
        )
        file_path = tmp_path / "sample_api.py"
        file_path.write_text(source)

        result = parse_fastapi_code(str(file_path))
        ep = _endpoint_by_function(result, "from_file")
        assert ep["path"] == "/from-file/{x}"
        assert _param_by_name(ep, "x")["location"] == "path"

    def test_missing_file_returns_error(self, tmp_path):
        missing = tmp_path / "does_not_exist.py"
        result = parse_fastapi_code(str(missing))
        # Not a valid path per our heuristic check (os.path.isfile is False),
        # so it is treated as raw source and fails to parse as Python.
        assert "error" in result


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
