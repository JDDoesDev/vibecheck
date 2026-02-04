#!/usr/bin/env node

/**
 * VibeCheck Scanner
 *
 * Scans files for security vulnerabilities.
 * Used by Claude Code hooks to block commits with critical issues.
 *
 * Usage:
 *   Standalone: node scan.js [--staged|--all] [file1 file2 ...]
 *   As hook: Receives JSON on stdin from Claude Code PreToolUse hook
 *
 * Exit codes:
 *   0 - No critical issues (may have warnings)
 *   1 - Error running scan
 *   2 - Critical issues found (blocks hook)
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

// Vulnerability patterns organized by severity
const PATTERNS = {
  critical: [
    // API Keys and Secrets
    { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{20,}/g },
    { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g },
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
    { name: 'AWS Secret Key', pattern: /(?<![a-zA-Z0-9\/+])[a-zA-Z0-9\/+]{40}(?![a-zA-Z0-9\/+])/, test: (line) => /aws|secret|key/i.test(line) },
    { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/g },
    { name: 'GitHub OAuth', pattern: /gho_[a-zA-Z0-9]{36}/g },
    { name: 'GitHub App Token', pattern: /ghu_[a-zA-Z0-9]{36}/g },
    { name: 'GitHub Refresh Token', pattern: /ghr_[a-zA-Z0-9]{36}/g },
    { name: 'Stripe Secret Key', pattern: /sk_(live|test)_[a-zA-Z0-9]{24,}/g },
    { name: 'Stripe Restricted Key', pattern: /rk_(live|test)_[a-zA-Z0-9]{24,}/g },
    { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/g },
    { name: 'Hardcoded Password', pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/gi },
    { name: 'Hardcoded API Key', pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["'][^"']{8,}["']/gi },
    { name: 'Hardcoded Secret', pattern: /(?:secret|token)\s*[:=]\s*["'][^"']{8,}["']/gi },

    // Injection Vulnerabilities
    { name: 'SQL Injection', pattern: /(?:query|execute|exec)\s*\(\s*["'`].*\$\{|(?:query|execute|exec)\s*\(\s*["'`].*\+\s*\w/gi },
    { name: 'Command Injection', pattern: /(?:exec|spawn|execSync|spawnSync)\s*\([^)]*\+|(?:exec|spawn|execSync|spawnSync)\s*\([^)]*\$\{/gi },
    { name: 'Shell Injection (Python)', pattern: /subprocess\..*shell\s*=\s*True/gi },
    { name: 'Code Injection', pattern: /eval\s*\(\s*(?!["'`])[^)]+\)/g },

    // Dangerous Configuration
    { name: 'CORS Allow All', pattern: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*["']\*["']/gi },
    { name: 'SSL Verification Disabled', pattern: /verify\s*[:=]\s*False|rejectUnauthorized\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/gi },
  ],

  high: [
    // XSS
    { name: 'XSS via innerHTML', pattern: /\.innerHTML\s*=/g },
    { name: 'XSS via dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML/g },
    { name: 'XSS via v-html', pattern: /v-html\s*=/g },
    { name: 'XSS via document.write', pattern: /document\.write\s*\(/g },

    // Insecure Deserialization
    { name: 'Insecure Pickle', pattern: /pickle\.loads?\s*\(/g },
    { name: 'Insecure YAML', pattern: /yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)/g },
    { name: 'Insecure Marshal', pattern: /Marshal\.load/g },

    // Weak Crypto
    { name: 'Weak Hash (MD5)', pattern: /(?:md5|MD5)\s*\([^)]*(?:password|passwd|pwd|secret)/gi },
    { name: 'Weak Hash (SHA1)', pattern: /(?:sha1|SHA1)\s*\([^)]*(?:password|passwd|pwd|secret)/gi },
    { name: 'Weak Random', pattern: /Math\.random\s*\(\s*\).*(?:token|secret|password|key|salt)/gi },
  ],

  medium: [
    { name: 'Debug Mode Enabled', pattern: /(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|["']true["'])/g },
    { name: 'Console Log Sensitive', pattern: /console\.log\s*\([^)]*(?:password|secret|token|key|credential)/gi },
    { name: 'Security TODO', pattern: /(?:TODO|FIXME|XXX|HACK).*(?:security|auth|encrypt|password|vulnerable)/gi },
    { name: 'HTTP URL', pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1)[^"']+["']/g },
  ]
};

// File extensions to scan
const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.pyw',
  '.rb', '.erb',
  '.php',
  '.go',
  '.java', '.kt', '.scala',
  '.cs',
  '.rs',
  '.swift',
  '.c', '.cpp', '.h', '.hpp',
  '.sh', '.bash', '.zsh',
  '.yaml', '.yml',
  '.json',
  '.env', '.env.local', '.env.development', '.env.production',
  '.config', '.conf', '.cfg', '.ini'
]);

function shouldScanFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath).toLowerCase();

  // Always scan .env files
  if (basename.startsWith('.env')) return true;

  // Skip common non-code files
  if (basename === 'package-lock.json' || basename === 'yarn.lock' || basename === 'pnpm-lock.yaml') return false;

  return SCANNABLE_EXTENSIONS.has(ext);
}

function scanFile(filePath) {
  const findings = [];

  if (!fs.existsSync(filePath)) return findings;
  if (!shouldScanFile(filePath)) return findings;

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    return findings;
  }

  const lines = content.split('\n');

  for (const [severity, patterns] of Object.entries(PATTERNS)) {
    for (const { name, pattern, test } of patterns) {
      lines.forEach((line, index) => {
        // Skip comments (basic heuristic)
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;

        // If there's a test function, apply it
        if (test && !test(line)) return;

        const regex = new RegExp(pattern.source, pattern.flags);
        const matches = line.match(regex);

        if (matches) {
          findings.push({
            severity,
            type: name,
            file: filePath,
            line: index + 1,
            code: line.trim().substring(0, 100) + (line.trim().length > 100 ? '...' : ''),
            match: matches[0].substring(0, 50) + (matches[0].length > 50 ? '...' : '')
          });
        }
      });
    }
  }

  return findings;
}

function getChangedFiles(staged = true) {
  try {
    const cmd = staged
      ? 'git diff --cached --name-only --diff-filter=ACMR'
      : 'git diff --name-only --diff-filter=ACMR';
    const output = execSync(cmd, { encoding: 'utf8' });
    return output.trim().split('\n').filter(f => f.length > 0);
  } catch (err) {
    return [];
  }
}

function formatFindings(findings) {
  const bySeverity = { critical: [], high: [], medium: [] };

  for (const f of findings) {
    bySeverity[f.severity].push(f);
  }

  let output = '\n🛡️  VibeCheck Security Scan\n\n';

  const total = findings.length;
  if (total === 0) {
    output += '✓ No security issues found\n';
    return output;
  }

  if (bySeverity.critical.length > 0) {
    output += '🔴 CRITICAL - Must fix before commit:\n\n';
    bySeverity.critical.forEach((f, i) => {
      output += `  ${i + 1}. ${f.type}\n`;
      output += `     ${f.file}:${f.line}\n`;
      output += `     ${f.code}\n\n`;
    });
  }

  if (bySeverity.high.length > 0) {
    output += '🟡 HIGH - Should fix:\n\n';
    bySeverity.high.forEach((f, i) => {
      output += `  ${i + 1}. ${f.type}\n`;
      output += `     ${f.file}:${f.line}\n`;
      output += `     ${f.code}\n\n`;
    });
  }

  if (bySeverity.medium.length > 0) {
    output += '🟢 MEDIUM - Consider fixing:\n\n';
    bySeverity.medium.forEach((f, i) => {
      output += `  ${i + 1}. ${f.type}\n`;
      output += `     ${f.file}:${f.line}\n\n`;
    });
  }

  output += `Found ${bySeverity.critical.length} critical, ${bySeverity.high.length} high, ${bySeverity.medium.length} medium issues.\n`;

  return output;
}

async function main() {
  const args = process.argv.slice(2);
  let files = [];
  let isHook = false;

  // Check if running as a hook (stdin will have JSON)
  if (!process.stdin.isTTY) {
    try {
      const chunks = [];
      for await (const chunk of process.stdin) {
        chunks.push(chunk);
      }
      const input = Buffer.concat(chunks).toString('utf8').trim();

      if (input.startsWith('{')) {
        const hookData = JSON.parse(input);
        isHook = true;

        // Check if this is a git commit/push command
        const command = hookData.tool_input?.command || '';
        if (!/git\s+(commit|push)/i.test(command)) {
          // Not a git commit/push, let it through
          process.exit(0);
        }

        // Get staged files for commit
        files = getChangedFiles(true);

        // If no staged files, check unstaged
        if (files.length === 0) {
          files = getChangedFiles(false);
        }
      }
    } catch (err) {
      // Not JSON input, continue with args
    }
  }

  // Parse command line args if not running as hook
  if (files.length === 0 && !isHook) {
    if (args.includes('--staged')) {
      files = getChangedFiles(true);
    } else if (args.includes('--all')) {
      files = getChangedFiles(false);
    } else {
      // Use remaining args as file paths
      files = args.filter(a => !a.startsWith('--'));
    }

    // Default to staged files
    if (files.length === 0) {
      files = getChangedFiles(true);
      if (files.length === 0) {
        files = getChangedFiles(false);
      }
    }
  }

  if (files.length === 0) {
    if (isHook) {
      // No files to scan, allow the command
      process.exit(0);
    }
    console.log('No files to scan');
    process.exit(0);
  }

  // Scan all files
  const allFindings = [];
  for (const file of files) {
    const findings = scanFile(file);
    allFindings.push(...findings);
  }

  // Output results
  const output = formatFindings(allFindings);

  const criticalCount = allFindings.filter(f => f.severity === 'critical').length;

  if (isHook) {
    if (criticalCount > 0) {
      // Block the command
      console.error(output);
      console.error('Commit blocked. Fix critical issues or use --no-verify to bypass.\n');
      process.exit(2);
    } else {
      // Allow with warnings
      if (allFindings.length > 0) {
        console.error(output);
      }
      process.exit(0);
    }
  } else {
    // Standalone mode
    console.log(output);
    console.log(`Scanned ${files.length} files.\n`);
    process.exit(criticalCount > 0 ? 2 : 0);
  }
}

main().catch(err => {
  console.error('Scan error:', err.message);
  process.exit(1);
});
