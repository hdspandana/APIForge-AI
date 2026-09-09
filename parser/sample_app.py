from fastapi import FastAPI, Query, Path, Body, Depends, Request
from typing import Optional
from pydantic import BaseModel

app = FastAPI()

class UserCreate(BaseModel):
    username: str
    email: str

@app.get("/users/{user_id}", tags=["users"])
async def get_user(
    user_id: int = Path(..., description="Target User ID"),
    include_details: bool = Query(False, description="Include detailed info")
):
    """Retrieve user profile by ID."""
    return {"user_id": user_id, "include_details": include_details}

@app.post("/users", tags=["users"])
def create_user(
    user: UserCreate,
    req: Request,
    auth: dict = Depends(lambda: {})
):
    """Create a new user."""
    return {"status": "created"}
