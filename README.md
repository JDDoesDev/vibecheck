```
╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║                  ░██████╗░██╗░░░██╗░█████╗░                     ║
║                  ██╔════╝░██║░░░██║██╔══██╗                     ║
║                  ██║░░██╗░╚██╗░██╔╝██║░░██║                     ║
║                  ██║░░╚██╗░╚████╔╝░██║░░██║                     ║
║                  ╚██████╔╝░░╚██╔╝░░╚█████╔╝                     ║
║                  ░╚═════╝░░░░╚═╝░░░░╚════╝░                     ║
║                                                                 ║
║           🛡️  security scanner for vibe coders  🛡️             ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝
```

# GoodVibesOnly

**Security scanner for vibe-coded projects.** A Claude Code extension that automatically scans for vulnerabilities when Claude Code commits on your behalf.

## How It Works

GoodVibesOnly uses Claude Code's [hooks system](https://docs.anthropic.com/en/docs/claude-code/hooks) to intercept git commands **within Claude Code sessions**. It does not hook into git directly — it only triggers when Claude Code itself runs a Bash command.

1. **Intercepts Claude Code's Bash calls** - A `PreToolUse` hook runs the scanner whenever Claude Code is about to execute a Bash command
2. **Checks for git commit/push** - If the command is a `git commit` or `git push`, it scans staged files for hardcoded secrets, injection vulnerabilities, XSS, and more
3. **Blocks on critical issues** - Prevents Claude Code from executing the commit by exiting with code 2
4. **Allows warnings through** - High/medium issues are reported but don't block

> **Note:** This only works when committing through Claude Code. Running `git commit` directly in your terminal will not trigger the scan. For terminal-level git hooks, consider a traditional pre-commit hook tool.

```
You (in Claude Code): commit my changes

🛡️  GoodVibesOnly Security Scan

🔴 CRITICAL - Must fix before commit:

  1. Hardcoded API Key
     src/config.js:15
     const API_KEY = "sk-abc123..."

  2. SQL Injection
     src/db/users.js:42
     db.query("SELECT * FROM users WHERE id = " + id)

Found 2 critical, 0 high, 0 medium issues.
Commit blocked — fix critical issues before committing.
```

## Installation

### Option 1: skills.sh (recommended)

```bash
npx skills add jddoesdev/goodvibesonly
```

Or install globally:

```bash
npx skills add jddoesdev/goodvibesonly --global
```

### Option 2: npx

```bash
npx goodvibesonly-cc
```

### Option 3: npm global install

```bash
npm install -g goodvibesonly-cc
```

### Option 4: Manual

```bash
git clone https://github.com/jddoesdev/goodvibesonly.git
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

When working inside Claude Code, GoodVibesOnly runs automatically whenever Claude executes a git commit or push:

```
You: commit my changes        # Scans before Claude runs git commit
You: push to origin            # Scans before Claude runs git push
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

## Allowlist

Suppress specific findings by adding a `.goodvibesonly.json` file to your project root:

```json
{
  "allow": [
    { "pattern": "XSS via dangerouslySetInnerHTML", "reason": "Sanitized with DOMPurify" },
    { "path": "test/**", "reason": "Test files contain intentional patterns" },
    { "pattern": "SQL Injection", "path": "src/db/raw.js", "reason": "Parameterized at call site" }
  ]
}
```

Each entry in the `allow` array supports:

| Fields | Effect |
|--------|--------|
| `pattern` only | Suppress that pattern in all files |
| `path` only | Suppress all patterns in matching files |
| `pattern` + `path` | Suppress specific pattern in specific files |

- `reason` is expected on every entry (warns if missing)
- Pattern names must match exactly — run `node bin/scan.js --list-patterns` to see all names
- `path` supports glob patterns (`*` for single directory, `**` for recursive)

### Conversational Flow

When GoodVibesOnly flags a finding in Claude Code, you can tell Claude to allow it:

```
You: allow the dangerouslySetInnerHTML one
Claude: One-time (this commit only) or permanent?
You: permanent
Claude: What's the reason?
You: sanitized with DOMPurify
```

- **One-time**: temporarily adds the entry, commits, then removes it
- **Permanent**: adds the entry to `.goodvibesonly.json` for you to commit later

### List All Patterns

```bash
node bin/scan.js --list-patterns
```

## How It's Different

- **Actually enforces** - Uses Claude Code's PreToolUse hooks to block commits, not just advisory
- **Real scanning** - Node.js script with regex patterns, not just instructions for Claude
- **Zero config** - Installs hooks automatically into Claude Code's settings
- **Uninstall support** - Clean removal with `--uninstall`

## Technical Details

GoodVibesOnly installs a `PreToolUse` hook in Claude Code's settings. This hook runs before every Bash tool call that Claude Code makes. When the scanner detects the command is a `git commit` or `git push`:

1. Reads staged files via `git diff --cached --name-only`
2. Scans each file against vulnerability patterns
3. Outputs findings to stderr
4. Exits with code 2 to block Claude Code from running the command (critical issues) or 0 to allow it

For non-git commands, the scanner exits immediately with code 0 (allow).

The hook is configured in Claude Code's `settings.json`:

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
