import re


def analyze_context(code, endpoints):
    context = {
        "module": "Unknown",
        "framework": "Unknown",
        "data_source": "Unknown",
        "authentication": "Unknown",
        "purpose": "API endpoint operations",
        "related_endpoints": []
    }

            # Module / API domains
    detected_modules = []

    for endpoint in endpoints:
        path = endpoint["path"]

        if not isinstance(path, str):
            continue

        parts = [
            part
            for part in path.split("/")
            if part and not part.startswith("<")
            and not part.startswith("{")
        ]

        if parts:
            resource = parts[0].replace("-", " ").replace("_", " ")
            resource = resource.strip()

            if resource:
                module_name = resource.title()

                if module_name not in detected_modules:
                    detected_modules.append(module_name)

    if detected_modules:
        context["module"] = ", ".join(detected_modules)
    # Framework
    code_lower = code.lower()

    if "from flask import" in code_lower or "import flask" in code_lower:
        context["framework"] = "Flask"
    elif "from fastapi import" in code_lower or "import fastapi" in code_lower:
        context["framework"] = "FastAPI"

            # Database / ORM
    has_sqlalchemy = "sqlalchemy" in code_lower

    if "postgresql" in code_lower or "psycopg" in code_lower:
        database = "PostgreSQL"
    elif "mysql" in code_lower or "pymysql" in code_lower:
        database = "MySQL"
    elif "mongodb" in code_lower or "pymongo" in code_lower:
        database = "MongoDB"
    elif "sqlite" in code_lower:
        database = "SQLite"
    elif "redis" in code_lower:
        database = "Redis"
    else:
        database = None

    if has_sqlalchemy and database:
        context["data_source"] = f"{database} via SQLAlchemy"
    elif has_sqlalchemy:
        context["data_source"] = "Database via SQLAlchemy"
    elif database:
        context["data_source"] = database
    else:
        context["data_source"] = "Not detected"
        # Authentication
    if (
        "jwt" in code_lower
        or "jwt_required" in code_lower
        or "flask_jwt" in code_lower
    ):
        context["authentication"] = "JWT"

    elif (
        "bearer" in code_lower
        or "authorization" in code_lower
    ):
        context["authentication"] = "Bearer token"

    elif (
        "api_key" in code_lower
        or "apikey" in code_lower
        or "x-api-key" in code_lower
    ):
        context["authentication"] = "API key"

    elif (
        "oauth" in code_lower
        or "oauth2" in code_lower
    ):
        context["authentication"] = "OAuth 2.0"

    elif (
        "basic_auth" in code_lower
        or "basicauth" in code_lower
    ):
        context["authentication"] = "Basic authentication"

    else:
        context["authentication"] = "Not detected"
        # Purpose
    if endpoints:
        methods = {
            endpoint["method"]
            for endpoint in endpoints
        }

        if context["module"] != "Unknown":
            module = context["module"]

            if methods == {"GET"}:
                context["purpose"] = f"Retrieve {module.lower()} information"
            elif methods == {"POST"}:
                context["purpose"] = f"Create {module.lower()} information"
            elif methods == {"DELETE"}:
                context["purpose"] = f"Delete {module.lower()} information"
            elif methods.issubset({"PUT", "PATCH"}):
                context["purpose"] = f"Update {module.lower()} information"
            else:
                context["purpose"] = f"Manage {module.lower()} information"

        else:
            if methods == {"GET"}:
                context["purpose"] = "Retrieve data"
            elif methods == {"POST"}:
                context["purpose"] = "Create or submit data"
            elif methods == {"DELETE"}:
                context["purpose"] = "Delete data"
            elif methods.issubset({"PUT", "PATCH"}):
                context["purpose"] = "Update data"
            else:
                context["purpose"] = "Provide API operations"

    # Related endpoints
    context["related_endpoints"] = [
        endpoint["path"]
        for endpoint in endpoints
    ]

    return context