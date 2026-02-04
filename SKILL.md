---
name: vibecheck
description: Security scanner for vibe-coded projects. Use this skill before committing code, after generating new files, or when the user asks to check for security issues. Scans for hardcoded secrets, SQL injection, XSS, command injection, insecure patterns, and common vulnerabilities introduced during rapid AI-assisted development. Triggers on phrases like "commit", "push", "check security", "scan for issues", "vibecheck", "is this safe", or "review before shipping".
---

# VibeCheck - Security Scanner for Vibe Coding

Scan generated code for security issues before they hit production.

## When to Run

- Before ANY commit or push
- After generating new files with user input handling
- After creating API endpoints, database queries, or auth logic
- When user asks "is this safe?" or "check for issues"
- Proactively after large code generation sessions

## Quick Start

Run the scanner on staged changes:
```bash
python3 /path/to/vibecheck/scripts/scan.py --staged
```

Run on specific files:
```bash
python3 /path/to/vibecheck/scripts/scan.py src/api/auth.js src/db/queries.py
```

Run on entire project:
```bash
python3 /path/to/vibecheck/scripts/scan.py --all
```

## What It Catches

### Critical (Block Commit)
- Hardcoded API keys, passwords, tokens, secrets
- SQL injection (string concatenation in queries)
- Command injection (unsanitized shell exec)
- Path traversal (user input in file paths)
- Disabled security features (CORS *, SSL verify=False)

### High (Warn)
- XSS vulnerabilities (unescaped user output)
- Insecure deserialization (pickle, eval, yaml.load)
- Weak cryptography (MD5, SHA1 for passwords, ECB mode)
- Hardcoded credentials in config files
- Debug mode enabled in production configs

### Medium (Note)
- Missing input validation
- Overly permissive file permissions
- Console.log with sensitive data
- TODO/FIXME security comments
- Outdated dependency patterns

## Integration Workflow

When user wants to commit:

1. Run `vibecheck --staged`
2. If CRITICAL issues found:
   - List all issues with file:line references
   - Offer to fix each one
   - Re-scan after fixes
   - Only proceed with commit when clean
3. If HIGH issues found:
   - List issues and explain risks
   - Ask user if they want to fix or proceed
4. If only MEDIUM issues:
   - Mention them briefly
   - Proceed with commit

## Responding to Results

When reporting issues, be specific and actionable:

```
VibeCheck found 2 critical issues:

1. CRITICAL: Hardcoded API key
   src/config.js:15
   `const API_KEY = "sk-ant-abc123..."`
   Fix: Move to environment variable

2. CRITICAL: SQL injection  
   src/db/users.js:42
   `db.query("SELECT * FROM users WHERE id = " + userId)`
   Fix: Use parameterized query

Want me to fix these before committing?
```

## Manual Patterns Reference

If the script is unavailable, check for these patterns manually:

### Secrets (regex patterns)
```
sk-[a-zA-Z0-9]{20,}           # OpenAI
sk-ant-[a-zA-Z0-9-]{20,}      # Anthropic  
AKIA[0-9A-Z]{16}              # AWS
ghp_[a-zA-Z0-9]{36}           # GitHub
password\s*=\s*["'][^"']+     # Hardcoded passwords
```

### SQL Injection
```
query.*\+.*user               # String concat with user input
execute.*\$\{                 # Template literal in query
f"SELECT.*{                   # Python f-string in SQL
```

### Command Injection
```
exec\(.*\+                    # exec with concatenation
system\(.*\$                  # system() with variables
child_process.*\+             # Node child_process with concat
subprocess.*shell=True        # Python shell=True
```

### XSS
```
innerHTML\s*=                 # Direct innerHTML assignment
dangerouslySetInnerHTML       # React unsafe HTML
\|\s*safe                     # Django/Jinja safe filter
v-html=                       # Vue unsafe HTML
```
