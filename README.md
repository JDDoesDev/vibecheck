# VibeCheck

**Security scanner for vibe-coded projects.** Catch hardcoded secrets, SQL injection, XSS, and other vulnerabilities before they ship.

Built for the AI-assisted development era where code gets written fast and security reviews don't always keep up.

## Why VibeCheck?

When you're vibe coding with Claude Code, Cursor, or other AI tools, code gets generated quickly. That's great for productivity, but easy to miss:

- API keys that got hardcoded during prototyping
- SQL queries built with string concatenation
- Debug flags left enabled
- Eval statements with user input

VibeCheck catches these before you commit.

## Installation

### As a Claude Code Skill

Copy the `vibecheck` folder to your Claude Code skills directory:

```bash
cp -r vibecheck /path/to/your/skills/
```

Then Claude Code will automatically use it when you say things like:
- "check this for security issues"
- "vibecheck before I commit"
- "is this safe to ship?"

### Standalone CLI

```bash
# Clone the repo
git clone https://github.com/jddoesdev/vibecheck.git

# Run directly
python vibecheck/scripts/scan.py --help

# Or add to PATH
chmod +x vibecheck/scripts/scan.py
ln -s $(pwd)/vibecheck/scripts/scan.py /usr/local/bin/vibecheck
```

## Usage

```bash
# Scan staged files (default)
python scan.py --staged

# Scan specific files
python scan.py src/auth.js src/db.py

# Scan entire project
python scan.py --all

# Scan changes since last commit
python scan.py --diff HEAD~1

# Output as JSON (for CI/tooling)
python scan.py --staged --json
```

## What It Catches

### Critical (Exit Code 2)
| Issue | Example |
|-------|---------|
| Hardcoded API keys | `sk-ant-abc123...`, `AKIA...` |
| SQL injection | `query("SELECT * FROM users WHERE id = " + userId)` |
| Command injection | `exec("rm " + userInput)` |
| Disabled SSL verification | `verify=False` |
| CORS allow all | `Access-Control-Allow-Origin: *` |

### High (Exit Code 1)
| Issue | Example |
|-------|---------|
| XSS vulnerabilities | `innerHTML = userInput` |
| Insecure deserialization | `pickle.loads(data)` |
| Weak crypto | `md5(password)` |
| Path traversal | `readFile(userPath)` |

### Medium (Exit Code 1)
| Issue | Example |
|-------|---------|
| Debug mode enabled | `DEBUG=true` |
| Sensitive data in logs | `console.log(password)` |
| Security TODOs | `// TODO: add auth` |

## CI Integration

### GitHub Actions

```yaml
- name: Security Check
  run: |
    python vibecheck/scripts/scan.py --staged
    if [ $? -eq 2 ]; then
      echo "Critical security issues found!"
      exit 1
    fi
```

### Pre-commit Hook

```bash
#!/bin/sh
python /path/to/vibecheck/scripts/scan.py --staged
if [ $? -eq 2 ]; then
    echo "Commit blocked: Critical security issues found"
    exit 1
fi
```

## Supported Languages

- JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`)
- Python (`.py`)
- Ruby (`.rb`)
- PHP (`.php`)
- Java (`.java`)
- Go (`.go`)
- Rust (`.rs`)
- C/C++ (`.c`, `.cpp`, `.h`)
- Shell (`.sh`, `.bash`)
- HTML/Vue/Svelte (`.html`, `.vue`, `.svelte`)
- Config files (`.json`, `.yaml`, `.yml`, `.env`, `.toml`)

## Adding Custom Patterns

Edit `scripts/scan.py` and add to the `PATTERNS` list:

```python
Pattern(
    name="My Custom Check",
    severity="HIGH",
    regex=r'my-dangerous-pattern',
    description="Why this is dangerous",
    fix="How to fix it",
    languages=['js', 'py'],  # or ['all']
),
```

## False Positives

VibeCheck errs on the side of caution. If you get a false positive:

1. **Check if it's actually safe** - Sometimes what looks like a false positive is a real issue
2. **Add an inline ignore** - `# vibecheck-ignore` (coming soon)
3. **Open an issue** - Help improve the patterns

## License

MIT

## Contributing

PRs welcome! Especially for:
- New vulnerability patterns
- Language-specific improvements
- Reduced false positives
- CI/CD integrations
