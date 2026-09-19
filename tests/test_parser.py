from backend.api_parser import parse_api_code

code = '''
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def get_users():
    return {"users": []}

@app.get("/users/{id}")
def get_user(id: int):
    return {"id": id}

@app.post("/users")
def create_user(name: str, age: int):
    return {"name": name, "age": age}

@app.delete("/users/{id}")
def delete_user(id: int):
    return {"deleted": id}
'''

result = parse_api_code(code)

for endpoint in result["endpoints"]:
    print(endpoint)