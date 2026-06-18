# Finding: Command Injection

## Why it's dangerous
Command Injection occurs when user input is passed directly to a system shell command executor. Attackers can append command separators (like `;`, `&&`, or `|`) followed by their own shell commands, leading to complete server compromise, malicious file execution, or data exfiltration.

## How to fix it
Never run command processes via the system shell (`shell=True`). Instead, spawn the process directly and pass the executable name and arguments as a list. This prevents the OS shell from interpreting command delimiters.

## Before (vulnerable)
```python
# Shell parses the entire string, allowing command chaining (e.g. user_input = "; rm -rf /")
subprocess.call(f"ls {user_input}", shell=True)
```

## After (fixed)
```python
# Executes the command directly; inputs are passed safely as separate list elements
subprocess.call(["ls", user_input], shell=False)
```
