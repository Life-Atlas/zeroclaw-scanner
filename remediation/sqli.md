# Finding: SQL Injection (SQLi)

## Why it's dangerous
SQL Injection occurs when user-supplied input is directly concatenated into database queries. Attackers can exploit this to alter query logic, bypassing authentication, reading sensitive database contents (like user hashes or credit card details), deleting tables, or executing administrative commands.

## How to fix it
Always utilize **parameterized queries** (also known as prepared statements). Parameterization treats user inputs strictly as literals/values rather than executable query tokens, preventing manipulation.

## Before (vulnerable)
```python
# The input is directly formatting the query string
cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
```

## After (fixed)
```python
# The query structure is pre-defined; inputs are passed separately as a tuple
cursor.execute("SELECT * FROM users WHERE name = %s", (user_input,))
```
