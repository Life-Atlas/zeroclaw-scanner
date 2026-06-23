"""Dummy vulnerable FastAPI app for injection testing."""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/search")
def search(q: str = ""):
    # Vulnerable: reflects input directly into SQL-like query
    query = f"SELECT * FROM users WHERE name = '{q}'"
    return {"query": query, "results": []}


@app.get("/profile/{user_id}")
def profile(user_id: str):
    # Vulnerable: reflects input in response
    query = f"SELECT * FROM profiles WHERE id = '{user_id}'"
    return {"query": query}


@app.post("/login")
async def login(data: dict):
    # Vulnerable: reflects input directly
    username = data.get("username", "")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return {"query": query}


@app.get("/greet")
def greet(name: str = ""):
    # Vulnerable: reflects input in HTML response
    html = f"<h1>Hello {name}</h1>"
    return HTMLResponse(content=html)


@app.get("/comment")
def comment(text: str = ""):
    # Vulnerable: stores and reflects input
    return {"comment": text, "html": f"<div>{text}</div>"}