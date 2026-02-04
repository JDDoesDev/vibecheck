---
name: vibecheck
description: Security scanner for vibe-coded projects. AUTO-INVOKE this skill before any git commit, git push, or when user says "commit", "push", "ship it", "deploy", "is this safe?", "check for security issues", or "vibecheck". Also invoke after generating code that handles user input, authentication, database queries, or file operations.
---

# VibeCheck - Security Scanner

Automatically scan for security vulnerabilities before code leaves the developer's machine.

## When to Auto-Invoke

Run this skill BEFORE executing any:
- `git commit`
- `git push`
- Deploy commands

Run this skill WHEN user says:
- "commit this"
- "push to main"
- "ship it"
- "is this safe?"
- "check security"
- "vibecheck"
- "ready to deploy"

## Quick Scan Checklist

Scan changed files for:

### 🔴 CRITICAL (Stop and fix)

```
# Hardcoded secrets
sk-[a-zA-Z0-9]{20,}              # OpenAI
sk-ant-[a-zA-Z0-9-]{20,}         # Anthropic
AKIA[0-9A-Z]{16}                  # AWS
ghp_[a-zA-Z0-9]{36}              # GitHub
sk_(live|test)_[a-zA-Z0-9]{24,}  # Stripe
api_key\s*=\s*["'][^"']+["']     # Generic API key
password\s*=\s*["'][^"']+["']    # Hardcoded password
-----BEGIN.*PRIVATE KEY-----      # Private key

# Injection
query.*\+.*user                   # SQL injection (concat)
execute.*\$\{                     # SQL injection (template)
exec\(.*\+                        # Command injection
subprocess.*shell=True            # Shell injection
eval\(.*[a-zA-Z_]                 # Code injection

# Dangerous config
origin.*["']\*["']                # CORS allow all
verify\s*=\s*False                # SSL disabled
rejectUnauthorized.*false         # SSL disabled (Node)
```

### 🟡 HIGH (Warn)

```
innerHTML\s*=                     # XSS
dangerouslySetInnerHTML           # XSS (React)
v-html=                           # XSS (Vue)
pickle\.loads                     # Insecure deserialization
yaml\.load\(                      # Unsafe YAML
md5\(.*password                   # Weak crypto
sha1\(.*password                  # Weak crypto
```

### 🟢 MEDIUM (Note)

```
debug.*=.*true                    # Debug mode
console\.log.*password            # Logged secrets
TODO.*security                    # Security TODOs
http://(?!localhost)              # Non-HTTPS
```

## Response Protocol

**If CRITICAL issues found:**
1. List all issues with file:line
2. Show the problematic code
3. Explain the fix
4. Ask: "Want me to fix these before committing?"
5. Do NOT proceed with commit until fixed or user explicitly overrides

**If HIGH issues found:**
1. List issues
2. Ask: "These should be fixed. Continue anyway?"

**If only MEDIUM or clean:**
1. Brief summary
2. Proceed with the requested action

## Example Output

```
🛡️ VibeCheck Security Scan

Scanned 8 files with changes.

🔴 CRITICAL - Must fix:

1. Hardcoded API Key
   src/config.js:15
   const API_KEY = "sk-abc123..."
   → Move to environment variable

2. SQL Injection  
   src/db/users.js:42
   db.query("SELECT * FROM users WHERE id = " + id)
   → Use parameterized query: db.query("SELECT * FROM users WHERE id = ?", [id])

🟡 HIGH - Should fix:

3. XSS Risk
   src/components/Comment.jsx:28
   <div dangerouslySetInnerHTML={{__html: comment.body}} />
   → Sanitize with DOMPurify before rendering

Found 2 critical, 1 high, 0 medium issues.
Commit blocked. Want me to fix the critical issues?
```
