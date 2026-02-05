```
╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║            ░██████╗░██╗░░░██╗░█████╗░                           ║
║            ██╔════╝░██║░░░██║██╔══██╗                           ║
║            ██║░░██╗░╚██╗░██╔╝██║░░██║                           ║
║            ██║░░╚██╗░╚████╔╝░██║░░██║                           ║
║            ╚██████╔╝░░╚██╔╝░░╚█████╔╝                           ║
║            ░╚═════╝░░░░╚═╝░░░░╚════╝░                           ║
║                                                                 ║
║           🛡️  security scanner for vibe coders  🛡️                ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝
```

# GoodVibesOnly

**Security scanner for vibe-coded projects.** A Claude Code extension that automatically scans for vulnerabilities before you commit.

## How It Works

GoodVibesOnly uses Claude Code's hooks system to intercept git commands:

1. **Hooks into git commit/push** - Automatically runs before any `git commit` or `git push`
2. **Scans changed files** - Checks for hardcoded secrets, injection vulnerabilities, XSS, and more
3. **Blocks on critical issues** - Prevents commits with critical vulnerabilities (exit code 2)
4. **Allows warnings through** - High/medium issues are reported but don't block

```
You: git commit -m "add user api"

🛡️  GoodVibesOnly Security Scan

🔴 CRITICAL - Must fix before commit:

  1. Hardcoded API Key
     src/config.js:15
     const API_KEY = "sk-abc123..."

  2. SQL Injection
     src/db/users.js:42
     db.query("SELECT * FROM users WHERE id = " + id)

Found 2 critical, 0 high, 0 medium issues.
Commit blocked. Fix critical issues or use --no-verify to bypass.
```

## Installation

### Option 1: npx (recommended)

```bash
npx goodvibesonly-cc
```

### Option 2: npm global install

```bash
npm install -g goodvibesonly-cc
```

### Option 3: Manual

```bash
git clone https://github.com/YOURNAME/goodvibesonly.git
cd goodvibesonly
node bin/install.js --global
```

### Options

```bash
node bin/install.js --global      # Install to ~/.claude/ (all projects)
node bin/install.js --local       # Install to ./.claude/ (this project)
node bin/install.js --no-hooks    # Skip hook installation (command/skill only)
node bin/install.js --uninstall   # Remove GoodVibesOnly
```

## Usage

### Automatic (via hooks)

Just use git normally. GoodVibesOnly runs automatically:

```bash
git commit -m "message"    # Scans before commit
git push                   # Scans before push
```

### Manual Scan

```
/goodvibesonly
```

Or ask Claude:
```
is this code safe?
goodvibesonly this
check for security issues
```

## What It Catches

### CRITICAL (Blocks Commit)

| Category | Examples |
|----------|----------|
| **API Keys** | OpenAI (`sk-...`), Anthropic (`sk-ant-...`), AWS (`AKIA...`), GitHub (`ghp_...`), Stripe (`sk_live_...`) |
| **Secrets** | Hardcoded passwords, API keys, private keys |
| **Injection** | SQL injection, command injection, code injection (eval) |
| **Config** | CORS wildcard (`origin: "*"`), disabled SSL verification |

### HIGH (Warns)

| Category | Examples |
|----------|----------|
| **XSS** | `innerHTML`, `dangerouslySetInnerHTML`, `v-html` |
| **Deserialization** | `pickle.loads()`, `yaml.load()` without SafeLoader |
| **Weak Crypto** | MD5/SHA1 for passwords |

### MEDIUM (Notes)

| Category | Examples |
|----------|----------|
| **Debug** | `DEBUG = true` |
| **Logging** | `console.log(password)` |
| **TODOs** | Security-related TODOs |
| **HTTP** | Non-HTTPS URLs |

## Project Structure

```
goodvibesonly/
├── bin/
│   ├── install.js       # Installer (copies files + sets up hooks)
│   └── scan.js          # Scanner script (runs via hooks)
├── commands/
│   └── goodvibesonly.md # /goodvibesonly slash command
├── skills/
│   └── goodvibesonly/
│       └── SKILL.md     # Skill for Claude assistance
├── hooks/
│   └── hooks.json       # Hook configuration template
├── package.json
└── README.md
```

## How It's Different

- **Actually enforces** - Uses Claude Code hooks to block commits, not just advisory
- **Real scanning** - Node.js script with regex patterns, not just instructions for Claude
- **Zero config** - Installs hooks automatically
- **Uninstall support** - Clean removal with `--uninstall`

## Technical Details

GoodVibesOnly installs a `PreToolUse` hook that intercepts Bash commands. When it detects `git commit` or `git push`:

1. Reads staged files via `git diff --cached --name-only`
2. Scans each file against vulnerability patterns
3. Outputs findings to stderr
4. Exits with code 2 to block (critical issues) or 0 to allow

The hook is configured in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "node \"~/.claude/goodvibesonly/scan.js\""
      }]
    }]
  }
}
```

## Uninstall

```bash
node bin/install.js --uninstall --global
# or
node bin/install.js --uninstall --local
```

Or manually:

```bash
rm -rf ~/.claude/commands/goodvibesonly.md
rm -rf ~/.claude/skills/goodvibesonly/
rm -rf ~/.claude/goodvibesonly/
# Then remove the hook from ~/.claude/settings.json
```

## License

MIT
