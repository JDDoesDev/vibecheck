---
description: Scan code for security vulnerabilities before committing. Catches hardcoded secrets, SQL injection, XSS, and other issues common in vibe-coded projects.
---

# Security Scan

Run a security scan on the current changes before committing.

## Instructions

1. First, check what files have changed:
   - Run `git diff --name-only --cached` for staged files
   - If nothing staged, run `git diff --name-only` for unstaged changes
   - If no changes, scan files mentioned by the user or recently modified files

2. For each changed file with a scannable extension (.js, .ts, .py, .rb, .php, .go, .java, etc.), scan for these patterns:

### CRITICAL - Block commit until fixed:

**Hardcoded Secrets:**
- OpenAI keys: `sk-[a-zA-Z0-9]{20,}`
- Anthropic keys: `sk-ant-[a-zA-Z0-9-]{20,}`
- AWS keys: `AKIA[0-9A-Z]{16}`
- GitHub tokens: `ghp_[a-zA-Z0-9]{36}`
- Stripe keys: `sk_(live|test)_[a-zA-Z0-9]{24,}`
- Generic: `api_key = "..."`, `password = "..."`
- Private keys: `-----BEGIN PRIVATE KEY-----`

**Injection Vulnerabilities:**
- SQL injection: `query("SELECT * FROM users WHERE id = " + userId)`
- Command injection: `exec("rm " + userInput)`, `shell=True`
- Code injection: `eval(userInput)`

**Dangerous Config:**
- CORS wildcard: `Access-Control-Allow-Origin: *`
- SSL disabled: `verify=False`, `rejectUnauthorized: false`

### HIGH - Warn before commit:

**XSS:**
- `innerHTML = userContent`
- `dangerouslySetInnerHTML`
- `v-html=`

**Insecure Deserialization:**
- `pickle.loads()`
- `yaml.load()` without SafeLoader

**Weak Crypto:**
- MD5/SHA1 for passwords

### MEDIUM - Note but allow commit:

- `DEBUG = true` in config
- `console.log` with passwords/tokens
- Security-related TODOs
- HTTP URLs (should be HTTPS)

## Response Format

If issues found:
```
GoodVibesOnly found [N] issues:

🔴 CRITICAL (must fix):
1. [Type]: [file]:[line]
   `[code snippet]`
   Fix: [how to fix]

🟡 HIGH (should fix):
...

🟢 MEDIUM (note):
...

Want me to fix the critical issues before you commit?
```

If clean:
```
✓ GoodVibesOnly passed - no security issues found in [N] files
```

## Allowlist: `.goodvibesonly.json`

Users can suppress specific findings by adding entries to `.goodvibesonly.json` in the project root:

```json
{
  "allow": [
    { "pattern": "XSS via dangerouslySetInnerHTML", "reason": "Sanitized with DOMPurify" },
    { "path": "test/**", "reason": "Test files contain intentional patterns" },
    { "pattern": "SQL Injection", "path": "src/db/raw.js", "reason": "Parameterized at call site" }
  ]
}
```

- `pattern` only: suppress that pattern in all files
- `path` only: suppress all patterns in matching files (supports `*` and `**` globs)
- `pattern` + `path`: suppress specific pattern in specific files
- Every entry should have a `reason`
- Pattern names must match exactly — run `node bin/scan.js --list-patterns` to see all names

### Allowing Findings in Conversation

When a user wants to allow a finding:

1. Ask: **one-time** (this commit only) or **permanent**?
2. Ask for a reason

**One-time**: Write entry to `.goodvibesonly.json` (don't stage it), re-run commit, then remove the entry afterward.

**Permanent**: Write entry to `.goodvibesonly.json`, re-run commit, leave the file for user to commit later.

Always show the user exactly what was added to the config.

## After Scanning

- If CRITICAL issues: Offer to fix them automatically
- If HIGH issues: Ask if user wants to fix or proceed
- If only MEDIUM: Mention them briefly, proceed with commit
