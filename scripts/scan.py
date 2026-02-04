#!/usr/bin/env python3
"""
VibeCheck - Security scanner for vibe-coded projects

Usage:
    python scan.py [files...]           # Scan specific files
    python scan.py --staged             # Scan git staged files
    python scan.py --all                # Scan all tracked files
    python scan.py --diff HEAD~1        # Scan files changed since commit
"""

import re
import sys
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# =============================================================================
# CONFIGURATION
# =============================================================================

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.py', '.pyw',
    '.rb',
    '.php',
    '.java',
    '.go',
    '.rs',
    '.c', '.cpp', '.h', '.hpp',
    '.cs',
    '.swift',
    '.kt', '.kts',
    '.scala',
    '.sh', '.bash', '.zsh',
    '.sql',
    '.html', '.htm', '.vue', '.svelte',
    '.json', '.yaml', '.yml', '.toml', '.ini', '.env',
    '.xml', '.config',
}

# Max file size to scan (skip large files)
MAX_FILE_SIZE = 1_000_000  # 1MB

# =============================================================================
# PATTERNS
# =============================================================================

@dataclass
class Pattern:
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    regex: str
    description: str
    fix: str
    languages: list = field(default_factory=lambda: ['all'])

PATTERNS = [
    # -------------------------------------------------------------------------
    # CRITICAL: Hardcoded Secrets
    # -------------------------------------------------------------------------
    Pattern(
        name="OpenAI API Key",
        severity="CRITICAL",
        regex=r'sk-[a-zA-Z0-9]{20,}',
        description="Hardcoded OpenAI API key",
        fix="Move to environment variable: process.env.OPENAI_API_KEY",
    ),
    Pattern(
        name="Anthropic API Key",
        severity="CRITICAL",
        regex=r'sk-ant-[a-zA-Z0-9\-]{20,}',
        description="Hardcoded Anthropic API key",
        fix="Move to environment variable: process.env.ANTHROPIC_API_KEY",
    ),
    Pattern(
        name="AWS Access Key",
        severity="CRITICAL",
        regex=r'AKIA[0-9A-Z]{16}',
        description="Hardcoded AWS access key",
        fix="Use AWS credentials file or environment variables",
    ),
    Pattern(
        name="GitHub Token",
        severity="CRITICAL",
        regex=r'ghp_[a-zA-Z0-9]{36}',
        description="Hardcoded GitHub personal access token",
        fix="Move to environment variable or use GitHub CLI auth",
    ),
    Pattern(
        name="Stripe Key",
        severity="CRITICAL",
        regex=r'sk_(live|test)_[a-zA-Z0-9]{24,}',
        description="Hardcoded Stripe secret key",
        fix="Move to environment variable: process.env.STRIPE_SECRET_KEY",
    ),
    Pattern(
        name="Generic API Key Assignment",
        severity="CRITICAL",
        regex=r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
        description="Hardcoded API key or secret",
        fix="Move to environment variable",
    ),
    Pattern(
        name="Password Assignment",
        severity="CRITICAL",
        regex=r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
        description="Hardcoded password",
        fix="Move to environment variable or secrets manager",
    ),
    Pattern(
        name="Private Key",
        severity="CRITICAL",
        regex=r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        description="Private key embedded in code",
        fix="Move to separate key file excluded from git",
    ),
    Pattern(
        name="JWT Secret Hardcoded",
        severity="CRITICAL",
        regex=r'(?i)(jwt[_-]?secret|token[_-]?secret)\s*[=:]\s*["\'][^"\']{8,}["\']',
        description="Hardcoded JWT secret",
        fix="Move to environment variable",
    ),

    # -------------------------------------------------------------------------
    # CRITICAL: Injection Vulnerabilities
    # -------------------------------------------------------------------------
    Pattern(
        name="SQL Injection (String Concat)",
        severity="CRITICAL",
        regex=r'(?i)(query|execute|raw)\s*\([^)]*\+\s*[a-zA-Z_]',
        description="SQL query built with string concatenation",
        fix="Use parameterized queries: query('SELECT * FROM users WHERE id = ?', [userId])",
        languages=['js', 'ts', 'py', 'rb', 'php', 'java'],
    ),
    Pattern(
        name="SQL Injection (f-string)",
        severity="CRITICAL",
        regex=r'(?i)(execute|cursor\.|query)\s*\(\s*f["\'].*\{',
        description="SQL query using Python f-string interpolation",
        fix="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        languages=['py'],
    ),
    Pattern(
        name="SQL Injection (Template Literal)",
        severity="CRITICAL",
        regex=r'(?i)(query|execute)\s*\(\s*`[^`]*\$\{',
        description="SQL query using template literal interpolation",
        fix="Use parameterized queries",
        languages=['js', 'ts'],
    ),
    Pattern(
        name="Command Injection (exec)",
        severity="CRITICAL",
        regex=r'(?i)\b(exec|system|popen|spawn)\s*\([^)]*\+',
        description="Shell command with string concatenation",
        fix="Use parameterized commands or avoid shell execution",
    ),
    Pattern(
        name="Command Injection (shell=True)",
        severity="CRITICAL",
        regex=r'subprocess\.[a-z]+\([^)]*shell\s*=\s*True',
        description="Subprocess with shell=True is vulnerable to injection",
        fix="Use shell=False and pass args as list: subprocess.run(['cmd', arg])",
        languages=['py'],
    ),
    Pattern(
        name="Eval with Variable",
        severity="CRITICAL",
        regex=r'\beval\s*\([^)"\']*[a-zA-Z_][a-zA-Z0-9_]*',
        description="eval() with variable input enables code injection",
        fix="Avoid eval(). Use JSON.parse() for data, or a safe parser",
    ),

    # -------------------------------------------------------------------------
    # CRITICAL: Dangerous Configurations
    # -------------------------------------------------------------------------
    Pattern(
        name="CORS Allow All",
        severity="CRITICAL",
        regex=r'(?i)(access-control-allow-origin|cors).*[\'"]\*[\'"]',
        description="CORS configured to allow all origins",
        fix="Restrict to specific trusted origins",
    ),
    Pattern(
        name="SSL Verification Disabled",
        severity="CRITICAL",
        regex=r'(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)',
        description="SSL/TLS certificate verification disabled",
        fix="Enable certificate verification in production",
    ),

    # -------------------------------------------------------------------------
    # HIGH: XSS Vulnerabilities
    # -------------------------------------------------------------------------
    Pattern(
        name="innerHTML Assignment",
        severity="HIGH",
        regex=r'\.innerHTML\s*=\s*[^"\'`]',
        description="Direct innerHTML assignment may enable XSS",
        fix="Use textContent for text, or sanitize HTML with DOMPurify",
        languages=['js', 'ts'],
    ),
    Pattern(
        name="React dangerouslySetInnerHTML",
        severity="HIGH",
        regex=r'dangerouslySetInnerHTML',
        description="dangerouslySetInnerHTML may enable XSS",
        fix="Sanitize HTML with DOMPurify before using",
        languages=['js', 'ts', 'jsx', 'tsx'],
    ),
    Pattern(
        name="Vue v-html",
        severity="HIGH",
        regex=r'v-html\s*=',
        description="v-html renders raw HTML and may enable XSS",
        fix="Sanitize input or use v-text for plain text",
        languages=['vue', 'js'],
    ),
    Pattern(
        name="Django/Jinja safe Filter",
        severity="HIGH",
        regex=r'\|\s*safe\b',
        description="Marking content as safe bypasses escaping",
        fix="Only use |safe with content you control, never user input",
        languages=['html', 'py'],
    ),

    # -------------------------------------------------------------------------
    # HIGH: Insecure Deserialization
    # -------------------------------------------------------------------------
    Pattern(
        name="Pickle Load",
        severity="HIGH",
        regex=r'pickle\.loads?\s*\(',
        description="Pickle deserialization can execute arbitrary code",
        fix="Use JSON or other safe serialization formats",
        languages=['py'],
    ),
    Pattern(
        name="YAML Unsafe Load",
        severity="HIGH",
        regex=r'yaml\.load\s*\([^)]*\)',
        description="yaml.load without safe_load may be unsafe",
        fix="Use yaml.safe_load() or specify Loader=yaml.SafeLoader",
        languages=['py'],
    ),
    Pattern(
        name="Unserialize (PHP)",
        severity="HIGH",
        regex=r'\bunserialize\s*\(',
        description="unserialize() can lead to object injection",
        fix="Use JSON decode or validate input strictly",
        languages=['php'],
    ),

    # -------------------------------------------------------------------------
    # HIGH: Weak Cryptography
    # -------------------------------------------------------------------------
    Pattern(
        name="MD5 for Password",
        severity="HIGH",
        regex=r'(?i)(md5|MD5)\s*\([^)]*password',
        description="MD5 is cryptographically broken for passwords",
        fix="Use bcrypt, scrypt, or Argon2 for password hashing",
    ),
    Pattern(
        name="SHA1 for Security",
        severity="HIGH",
        regex=r'(?i)(sha1|SHA1)\s*\([^)]*(?:password|secret|token)',
        description="SHA1 is deprecated for security purposes",
        fix="Use SHA-256 or stronger, or bcrypt for passwords",
    ),
    Pattern(
        name="ECB Mode",
        severity="HIGH",
        regex=r'(?i)\.ECB|MODE_ECB|ecb[\'"]',
        description="ECB mode doesn't provide semantic security",
        fix="Use GCM or CBC mode with proper IV",
    ),

    # -------------------------------------------------------------------------
    # HIGH: Path Traversal
    # -------------------------------------------------------------------------
    Pattern(
        name="Path Traversal Risk",
        severity="HIGH",
        regex=r'(?i)(readFile|writeFile|open|fopen)\s*\([^)]*\+\s*[a-zA-Z_]',
        description="File path built with user input may allow traversal",
        fix="Validate input and use path.resolve() with base directory check",
    ),

    # -------------------------------------------------------------------------
    # MEDIUM: Debug/Development Code
    # -------------------------------------------------------------------------
    Pattern(
        name="Debug Mode Enabled",
        severity="MEDIUM",
        regex=r'(?i)(debug|DEBUG)\s*[=:]\s*(true|True|1|[\'"]true[\'"])',
        description="Debug mode may be enabled",
        fix="Ensure debug is disabled in production",
    ),
    Pattern(
        name="Console Log Sensitive",
        severity="MEDIUM",
        regex=r'(?i)console\.log\s*\([^)]*(password|secret|token|key|credential)',
        description="Logging potentially sensitive data",
        fix="Remove sensitive data from logs",
    ),
    Pattern(
        name="TODO Security",
        severity="MEDIUM",
        regex=r'(?i)(TODO|FIXME|HACK|XXX).*(?:security|auth|password|encrypt|sanitiz)',
        description="Security-related TODO comment",
        fix="Address the security concern before shipping",
    ),
    Pattern(
        name="Commented Credentials",
        severity="MEDIUM",
        regex=r'(?i)(#|//|/\*).*(?:password|secret|api.?key)\s*[=:]\s*\S+',
        description="Credentials in comments may leak",
        fix="Remove credentials from comments entirely",
    ),

    # -------------------------------------------------------------------------
    # MEDIUM: Missing Security Controls
    # -------------------------------------------------------------------------
    Pattern(
        name="No HTTPS Redirect",
        severity="MEDIUM",
        regex=r'http://(?!localhost|127\.0\.0\.1)',
        description="HTTP URL found (not HTTPS)",
        fix="Use HTTPS for all external URLs",
    ),
    Pattern(
        name="Hardcoded Localhost",
        severity="MEDIUM",
        regex=r'(?i)(host|url|endpoint)\s*[=:]\s*[\'"]https?://(localhost|127\.0\.0\.1)',
        description="Hardcoded localhost URL",
        fix="Use environment variable for configurable URLs",
    ),
]

# =============================================================================
# SCANNER
# =============================================================================

@dataclass
class Finding:
    file: str
    line: int
    column: int
    severity: str
    name: str
    description: str
    fix: str
    match: str

def get_file_extension(path: Path) -> str:
    return path.suffix.lower()

def should_scan_file(path: Path) -> bool:
    """Check if file should be scanned."""
    if not path.is_file():
        return False
    if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
        return False
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return False
    except OSError:
        return False
    return True

def get_language_from_ext(ext: str) -> str:
    """Map extension to language identifier."""
    mapping = {
        '.js': 'js', '.jsx': 'jsx', '.ts': 'ts', '.tsx': 'tsx',
        '.mjs': 'js', '.cjs': 'js',
        '.py': 'py', '.pyw': 'py',
        '.rb': 'rb',
        '.php': 'php',
        '.java': 'java',
        '.go': 'go',
        '.rs': 'rs',
        '.vue': 'vue',
        '.svelte': 'svelte',
        '.html': 'html', '.htm': 'html',
    }
    return mapping.get(ext, 'all')

def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for security issues."""
    findings = []
    
    try:
        content = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return findings
    
    lines = content.splitlines()
    ext = get_file_extension(path)
    lang = get_language_from_ext(ext)
    
    for pattern in PATTERNS:
        # Check if pattern applies to this language
        if 'all' not in pattern.languages and lang not in pattern.languages:
            continue
        
        regex = re.compile(pattern.regex)
        
        for line_num, line in enumerate(lines, 1):
            for match in regex.finditer(line):
                # Skip if in a comment (basic heuristic)
                stripped = line.lstrip()
                if pattern.name not in ["Commented Credentials", "TODO Security"]:
                    if stripped.startswith(('#', '//', '/*', '*', '"""', "'''")):
                        # Allow comment patterns to still match
                        if 'comment' not in pattern.name.lower():
                            continue
                
                findings.append(Finding(
                    file=str(path),
                    line=line_num,
                    column=match.start() + 1,
                    severity=pattern.severity,
                    name=pattern.name,
                    description=pattern.description,
                    fix=pattern.fix,
                    match=match.group()[:50] + ('...' if len(match.group()) > 50 else ''),
                ))
    
    return findings

def get_staged_files() -> list[Path]:
    """Get list of staged files from git."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
            capture_output=True, text=True, check=True
        )
        return [Path(f) for f in result.stdout.strip().split('\n') if f]
    except subprocess.CalledProcessError:
        return []

def get_all_tracked_files() -> list[Path]:
    """Get all tracked files from git."""
    try:
        result = subprocess.run(
            ['git', 'ls-files'],
            capture_output=True, text=True, check=True
        )
        return [Path(f) for f in result.stdout.strip().split('\n') if f]
    except subprocess.CalledProcessError:
        return []

def get_diff_files(ref: str) -> list[Path]:
    """Get files changed since a ref."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--name-only', ref],
            capture_output=True, text=True, check=True
        )
        return [Path(f) for f in result.stdout.strip().split('\n') if f]
    except subprocess.CalledProcessError:
        return []

# =============================================================================
# OUTPUT
# =============================================================================

def format_findings(findings: list[Finding], output_format: str = 'text') -> str:
    """Format findings for output."""
    if output_format == 'json':
        return json.dumps([{
            'file': f.file,
            'line': f.line,
            'column': f.column,
            'severity': f.severity,
            'name': f.name,
            'description': f.description,
            'fix': f.fix,
            'match': f.match,
        } for f in findings], indent=2)
    
    if not findings:
        return "✓ No security issues found"
    
    # Group by severity
    critical = [f for f in findings if f.severity == 'CRITICAL']
    high = [f for f in findings if f.severity == 'HIGH']
    medium = [f for f in findings if f.severity == 'MEDIUM']
    
    lines = []
    lines.append(f"Found {len(findings)} issue(s):\n")
    
    def format_finding(f: Finding, idx: int):
        lines.append(f"{idx}. [{f.severity}] {f.name}")
        lines.append(f"   {f.file}:{f.line}:{f.column}")
        lines.append(f"   Match: {f.match}")
        lines.append(f"   Fix: {f.fix}")
        lines.append("")
    
    idx = 1
    if critical:
        lines.append("=" * 60)
        lines.append("CRITICAL - Must fix before commit")
        lines.append("=" * 60)
        for f in critical:
            format_finding(f, idx)
            idx += 1
    
    if high:
        lines.append("-" * 60)
        lines.append("HIGH - Should fix")
        lines.append("-" * 60)
        for f in high:
            format_finding(f, idx)
            idx += 1
    
    if medium:
        lines.append("-" * 60)
        lines.append("MEDIUM - Consider fixing")
        lines.append("-" * 60)
        for f in medium:
            format_finding(f, idx)
            idx += 1
    
    return '\n'.join(lines)

# =============================================================================
# MAIN
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='VibeCheck - Security scanner for vibe coding')
    parser.add_argument('files', nargs='*', help='Files to scan')
    parser.add_argument('--staged', action='store_true', help='Scan git staged files')
    parser.add_argument('--all', action='store_true', help='Scan all git tracked files')
    parser.add_argument('--diff', metavar='REF', help='Scan files changed since REF')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    # Determine files to scan
    files = []
    if args.staged:
        files = get_staged_files()
    elif args.all:
        files = get_all_tracked_files()
    elif args.diff:
        files = get_diff_files(args.diff)
    elif args.files:
        files = [Path(f) for f in args.files]
    else:
        # Default: scan staged
        files = get_staged_files()
        if not files:
            print("No staged files. Use --all to scan entire project.")
            sys.exit(0)
    
    # Filter to scannable files
    files = [f for f in files if should_scan_file(f)]
    
    if not files:
        print("No scannable files found.")
        sys.exit(0)
    
    # Scan all files
    all_findings = []
    for file_path in files:
        findings = scan_file(file_path)
        all_findings.extend(findings)
    
    # Output
    output_format = 'json' if args.json else 'text'
    print(format_findings(all_findings, output_format))
    
    # Exit code based on severity
    critical_count = sum(1 for f in all_findings if f.severity == 'CRITICAL')
    if critical_count > 0:
        sys.exit(2)  # Critical issues
    elif all_findings:
        sys.exit(1)  # Non-critical issues
    else:
        sys.exit(0)  # Clean

if __name__ == '__main__':
    main()
