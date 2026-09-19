def calculate_quality(endpoints, security, context):
    score = 0
    total = 5

    # 1. Endpoints detected
    if endpoints:
        score += 1

    # 2. Parameters parsed
    if any(endpoint["parameters"] for endpoint in endpoints):
        score += 1

    # 3. Framework detected
    if context.get("framework") != "Unknown":
        score += 1

    # 4. Data source detected
    if context.get("data_source") != "Unknown":
        score += 1

    # 5. Security check
    if not security:
        score += 1

    return {
        "score": score * 20,
        "max_score": 100
    }