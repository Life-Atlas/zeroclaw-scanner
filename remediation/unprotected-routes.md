# Finding: Unprotected FastAPI Routes

## Why it's dangerous
Endpoints that fetch, create, or modify user-owned data are vulnerable if they are exposed without authorization constraints. Unauthenticated clients can query these endpoints directly, leading to data extraction, manipulation, or escalation of privileges.

## How to fix it
Protect all sensitive endpoint routes by assigning authentication dependency validation functions (`Depends(get_current_user)`) directly in the route handler arguments list.

## Before (vulnerable)
```python
# Anyone can access and query all users from this route
@app.get("/users")
def get_users():
    return db.get_all_users()
```

## After (fixed)
```python
# Route execution blocks unless a valid user token is checked
from fastapi import Depends
from auth import get_current_user

@app.get("/users")
def get_users(user=Depends(get_current_user)):
    return db.get_all_users()
```
