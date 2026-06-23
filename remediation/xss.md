# Finding: Cross-Site Scripting (XSS)

## Why it's dangerous
Cross-Site Scripting (XSS) allows attackers to execute arbitrary JavaScript in the context of another user's browser session. This can be exploited to steal sensitive cookies/session tokens, perform actions on behalf of the user, log keystrokes, or deface websites.

## How to fix it
Avoid using unsafe DOM properties like `innerHTML` when rendering user-supplied input. Instead, use safe APIs such as `textContent` or `innerText` which automatically HTML-encode character sequences. If HTML rendering is required, sanitize the input using a robust library like DOMPurify first.

## Before (vulnerable)
```javascript
// Renders input directly as HTML, allowing script execution
element.innerHTML = userInput;
```

## After (fixed)
```javascript
// Safely treats input as a raw string literal
element.textContent = userInput;
```
