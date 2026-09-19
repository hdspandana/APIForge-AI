import ast


def extract_example_response(source_code, function_name):
    try:
        tree = ast.parse(source_code)

        for node in tree.body:
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and node.name == function_name:

                for statement in ast.walk(node):
                    if isinstance(statement, ast.Return):
                        if not statement.value:
                            continue

                        value = statement.value

                        def ast_to_example(node):
                            if isinstance(node, ast.Constant):
                                return node.value

                            if isinstance(node, ast.List):
                                return [
                                    ast_to_example(item)
                                    for item in node.elts
                                ]

                            if isinstance(node, ast.Dict):
                                result = {}

                                for key, val in zip(
                                    node.keys,
                                    node.values
                                ):
                                    if isinstance(key, ast.Constant):
                                        result[str(key.value)] = (
                                            ast_to_example(val)
                                        )

                                return result

                            if isinstance(node, ast.Name):
                                return f"<{node.id}>"

                            return "<dynamic>"

                        return ast_to_example(value)

    except SyntaxError:
        pass

    return {}
    
    

def generate_documentation(endpoint, context, source_code=""):
    """
    Generate context-aware API documentation
    from endpoint, API context, and source code.
    """

    function_name = endpoint["function"].replace("_", " ")
    method = endpoint["method"]
    path = endpoint["path"]

    framework = context.get("framework", "Unknown")
    data_source = context.get("data_source", "Unknown")
    authentication = context.get(
        "authentication",
        "Not detected"
    )

    path_lower = path.lower()
    function_lower = endpoint["function"].lower()

    if method == "GET":
        if "<" in path or "{" in path:
            purpose = (
                f"Retrieves details for a specific "
                f"{function_lower.replace('get_', '').replace('_', ' ')}."
            )
        else:
            purpose = (
                f"Retrieves "
                f"{function_lower.replace('get_', '').replace('_', ' ')}."
            )

    elif method == "POST":
        if "login" in path_lower or "auth" in path_lower:
            purpose = (
                "Authenticates a user and creates "
                "an authentication session."
            )
        elif "create" in function_lower:
            resource = (
                function_lower
                .replace("create_", "")
                .replace("_", " ")
            )
            purpose = f"Creates a new {resource}."
        else:
            purpose = "Creates or submits data to the API."

    elif method == "PUT":
        purpose = "Updates an existing resource."

    elif method == "PATCH":
        purpose = "Partially updates an existing resource."

    elif method == "DELETE":
        purpose = "Deletes an existing resource."

    else:
        purpose = "Handles an API operation."

    parameters = [
        {
            "name": param["name"],
            "type": param["type"],
            "location": param["location"]
        }
        for param in endpoint["parameters"]
    ]

    resource = (
        endpoint["function"]
        .replace("get_", "")
        .replace("create_", "")
        .replace("update_", "")
        .replace("delete_", "")
        .replace("list_", "")
        .replace("_", " ")
    )

    if not resource:
        resource = "resource"

    if method == "GET":
        use_cases = [
            f"View {resource}",
            f"Display {resource} information",
            f"Fetch {resource} details"
        ]

    elif method == "POST":
        use_cases = [
            f"Create {resource}",
            f"Submit new {resource} data",
            f"Add {resource}"
        ]

    elif method == "PUT":
        use_cases = [
            f"Update {resource}",
            f"Modify {resource} information",
            f"Replace {resource} data"
        ]

    elif method == "PATCH":
        use_cases = [
            f"Partially update {resource}",
            f"Modify selected {resource} fields",
            f"Apply changes to {resource}"
        ]

    elif method == "DELETE":
        use_cases = [
            f"Delete {resource}",
            f"Remove {resource}",
            f"Clean up {resource}"
        ]

    else:
        use_cases = [
            f"Perform operations on {resource}"
        ]

    

    example_response = extract_example_response(
    source_code,
    endpoint["function"]
)

    return {
        "summary": f"{method} {path} — {function_name}",
        "purpose": purpose,
        "parameters": parameters,
        "framework": framework,
        "data_source": data_source,
        "authentication": authentication,
        "use_cases": use_cases,
        "example_response": example_response,
        "context": (
            f"This endpoint is part of the API. "
            f"It uses {framework} with {data_source}. "
            f"Authentication: {authentication}."
        )
    }