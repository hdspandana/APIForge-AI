import ast
import re


def get_type(annotation):
    if isinstance(annotation, ast.Name):
        types = {
            "int": "integer",
            "str": "string",
            "float": "number",
            "bool": "boolean"
        }
        return types.get(annotation.id, annotation.id)

    return "unknown"


def get_flask_path_params(path):
    """
    Extract Flask parameters such as:
    /users/<int:id>
    /posts/<id>
    """
    path_params = {}

    if not isinstance(path, str):
        return path_params

    matches = re.findall(r"<(?:(\w+):)?(\w+)>", path)

    for param_type, param_name in matches:
        type_map = {
            "int": "integer",
            "float": "number",
            "string": "string",
            "str": "string",
            "bool": "boolean"
        }

        path_params[param_name] = type_map.get(
            param_type,
            "string"
        )

    return path_params


def get_fastapi_path_params(path):
    """
    Extract FastAPI parameters such as:
    /users/{id}
    """
    path_params = set()

    if isinstance(path, str):
        for part in path.split("/"):
            if part.startswith("{") and part.endswith("}"):
                path_params.add(part[1:-1])

    return path_params


def parse_api_code(code):
    tree = ast.parse(code)
    endpoints = []

    for node in ast.walk(tree):

        if not isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue

        for decorator in node.decorator_list:

            if not isinstance(decorator, ast.Call):
                continue

            if not isinstance(decorator.func, ast.Attribute):
                continue

            decorator_name = decorator.func.attr.lower()

            # -----------------------------
            # FastAPI
            # @app.get("/users")
            # -----------------------------
            if decorator_name in [
                "get",
                "post",
                "put",
                "delete",
                "patch"
            ]:

                method = decorator_name.upper()
                path = "Unknown"

                if (
                    decorator.args
                    and isinstance(
                        decorator.args[0],
                        ast.Constant
                    )
                ):
                    path = decorator.args[0].value

                fastapi_path_params = get_fastapi_path_params(path)
                flask_path_params = {}

            # -----------------------------
            # Flask
            # @app.route("/users/<int:id>")
            # -----------------------------
            elif decorator_name == "route":

                path = "Unknown"

                if (
                    decorator.args
                    and isinstance(
                        decorator.args[0],
                        ast.Constant
                    )
                ):
                    path = decorator.args[0].value

                method = "GET"

                for keyword in decorator.keywords:

                    if (
                        keyword.arg == "methods"
                        and isinstance(keyword.value, ast.List)
                    ):

                        if keyword.value.elts:

                            first_method = keyword.value.elts[0]

                            if isinstance(
                                first_method,
                                ast.Constant
                            ):
                                method = str(
                                    first_method.value
                                ).upper()

                fastapi_path_params = set()
                flask_path_params = get_flask_path_params(path)

            else:
                continue

            parameters = []

            # Function arguments
            for arg in node.args.args:

                param_type = get_type(arg.annotation)

                # Flask path parameter
                if arg.arg in flask_path_params:

                    param_type = flask_path_params[arg.arg]
                    location = "path"

                # FastAPI path parameter
                elif arg.arg in fastapi_path_params:

                    location = "path"

                # Otherwise query parameter
                else:

                    location = "query"

                parameters.append({
                    "name": arg.arg,
                    "type": param_type,
                    "location": location
                })

            # Detect Flask query parameters
            # request.args.get("page")
            # request.args.get("limit")
            # request.args.get("role")
            source = ast.unparse(node)

            query_params = re.findall(
                r"request\.args\.get\(\s*[\"'](\w+)[\"']",
                source
            )

            existing_names = {
                param["name"]
                for param in parameters
            }

            for param_name in query_params:

                if param_name not in existing_names:

                    parameters.append({
                        "name": param_name,
                        "type": "unknown",
                        "location": "query"
                    })

            # Detect JSON body fields
            # data["name"]
            # data["email"]
            # data.get("role")
            body_fields = re.findall(
    r'data(?:\.get\(\s*["\'](\w+)["\']\s*(?:,\s*[^)]*)?\)|\[\s*["\'](\w+)["\']\s*\])',
    source
)

            for field_match in body_fields:

                field_name = field_match[0] or field_match[1]

                if field_name not in existing_names:

                    parameters.append({
                        "name": field_name,
                        "type": "unknown",
                        "location": "body"
                   })

            endpoints.append({
                "method": method,
                "path": path,
                "function": node.name,
                "parameters": parameters
            })

    return {
        "endpoints": endpoints
    }