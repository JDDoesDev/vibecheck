#!/usr/bin/env node

/**
 * VibeCheck Installer
 *
 * Installs VibeCheck as a Claude Code extension with:
 * - Slash command: /vibecheck
 * - Auto-invoke skill for commit/push detection
 * - PreToolUse hook for automatic scanning before git commit/push
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const GLOBAL_CLAUDE_DIR = path.join(process.env.HOME || process.env.USERPROFILE, '.claude');
const LOCAL_CLAUDE_DIR = '.claude';

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

function copyFile(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}

function loadJson(filePath) {
  if (fs.existsSync(filePath)) {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (err) {
      return {};
    }
  }
  return {};
}

function saveJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

function installHooks(targetDir, scanScriptPath) {
  const settingsPath = path.join(targetDir, 'settings.json');
  const settings = loadJson(settingsPath);

  // Initialize hooks structure if needed
  if (!settings.hooks) {
    settings.hooks = {};
  }
  if (!settings.hooks.PreToolUse) {
    settings.hooks.PreToolUse = [];
  }

  // Check if vibecheck hook already exists
  const existingHookIndex = settings.hooks.PreToolUse.findIndex(h =>
    h.hooks?.some(inner => inner.command?.includes('vibecheck') || inner.command?.includes('scan.js'))
  );

  const vibecheckHook = {
    matcher: 'Bash',
    hooks: [
      {
        type: 'command',
        command: `node "${scanScriptPath}"`,
        timeout: 30
      }
    ]
  };

  if (existingHookIndex >= 0) {
    // Update existing hook
    settings.hooks.PreToolUse[existingHookIndex] = vibecheckHook;
    console.log('Updated existing VibeCheck hook');
  } else {
    // Add new hook
    settings.hooks.PreToolUse.push(vibecheckHook);
    console.log('Installed VibeCheck hook');
  }

  saveJson(settingsPath, settings);
}

function install(targetDir, skipHooks = false) {
  const projectRoot = path.join(__dirname, '..');
  const commandsSrc = path.join(projectRoot, 'commands');
  const skillsSrc = path.join(projectRoot, 'skills');
  const scanScriptSrc = path.join(projectRoot, 'bin', 'scan.js');

  const commandsDest = path.join(targetDir, 'commands');
  const skillsDest = path.join(targetDir, 'skills');
  const vibecheckDir = path.join(targetDir, 'vibecheck');
  const scanScriptDest = path.join(vibecheckDir, 'scan.js');

  // Copy commands
  if (fs.existsSync(commandsSrc)) {
    console.log(`Installing commands to ${commandsDest}`);
    copyDir(commandsSrc, commandsDest);
  }

  // Copy skills
  if (fs.existsSync(skillsSrc)) {
    console.log(`Installing skills to ${skillsDest}`);
    copyDir(skillsSrc, skillsDest);
  }

  // Copy scan script
  if (fs.existsSync(scanScriptSrc)) {
    console.log(`Installing scanner to ${vibecheckDir}`);
    copyFile(scanScriptSrc, scanScriptDest);
  }

  // Install hooks (unless skipped)
  if (!skipHooks) {
    installHooks(targetDir, scanScriptDest);
  }

  console.log('\n✓ VibeCheck installed successfully!\n');
  console.log('Features:');
  console.log('  • /vibecheck command for manual scans');
  console.log('  • Auto-scan before git commit/push (via hooks)');
  console.log('  • Blocks commits with critical vulnerabilities');
  console.log('');
  console.log('Usage:');
  console.log('  /vibecheck              Manual security scan');
  console.log('  git commit -m "msg"     Auto-scans before commit');
  console.log('  git push                Auto-scans before push');
  console.log('');
}

function uninstall(targetDir) {
  const commandPath = path.join(targetDir, 'commands', 'vibecheck.md');
  const skillPath = path.join(targetDir, 'skills', 'vibecheck');
  const vibecheckDir = path.join(targetDir, 'vibecheck');
  const settingsPath = path.join(targetDir, 'settings.json');

  let removed = false;

  // Remove command
  if (fs.existsSync(commandPath)) {
    fs.unlinkSync(commandPath);
    console.log('Removed /vibecheck command');
    removed = true;
  }

  // Remove skill
  if (fs.existsSync(skillPath)) {
    fs.rmSync(skillPath, { recursive: true });
    console.log('Removed vibecheck skill');
    removed = true;
  }

  // Remove scanner
  if (fs.existsSync(vibecheckDir)) {
    fs.rmSync(vibecheckDir, { recursive: true });
    console.log('Removed scanner');
    removed = true;
  }

  // Remove hook from settings
  if (fs.existsSync(settingsPath)) {
    const settings = loadJson(settingsPath);
    if (settings.hooks?.PreToolUse) {
      const originalLength = settings.hooks.PreToolUse.length;
      settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(h =>
        !h.hooks?.some(inner => inner.command?.includes('vibecheck') || inner.command?.includes('scan.js'))
      );
      if (settings.hooks.PreToolUse.length < originalLength) {
        saveJson(settingsPath, settings);
        console.log('Removed hook from settings');
        removed = true;
      }
    }
  }

  if (removed) {
    console.log('\n✓ VibeCheck uninstalled successfully!\n');
  } else {
    console.log('VibeCheck was not installed in this location.\n');
  }
}

async function prompt(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

async function main() {
  const args = process.argv.slice(2);

  console.log('');
  console.log('🛡️  VibeCheck Installer');
  console.log('   Security scanner for vibe-coded projects');
  console.log('');

  // Handle uninstall
  if (args.includes('--uninstall') || args.includes('-u')) {
    const targetDir = args.includes('--local') || args.includes('-l')
      ? LOCAL_CLAUDE_DIR
      : GLOBAL_CLAUDE_DIR;
    uninstall(targetDir);
    return;
  }

  // Handle skip-hooks flag
  const skipHooks = args.includes('--no-hooks');

  let targetDir;

  if (args.includes('--global') || args.includes('-g')) {
    targetDir = GLOBAL_CLAUDE_DIR;
  } else if (args.includes('--local') || args.includes('-l')) {
    targetDir = LOCAL_CLAUDE_DIR;
  } else {
    // Interactive mode
    console.log('Where would you like to install VibeCheck?');
    console.log('');
    console.log('  [g] Global (~/.claude/) - Available in all projects');
    console.log('  [l] Local (./.claude/)  - This project only');
    console.log('');

    const answer = await prompt('Choice (g/l): ');

    if (answer === 'g' || answer === 'global') {
      targetDir = GLOBAL_CLAUDE_DIR;
    } else if (answer === 'l' || answer === 'local') {
      targetDir = LOCAL_CLAUDE_DIR;
    } else {
      console.log('Invalid choice. Use --global or --local flag.');
      process.exit(1);
    }
  }

  install(targetDir, skipHooks);
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
