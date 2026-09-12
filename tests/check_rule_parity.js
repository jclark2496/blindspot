#!/usr/bin/env node
// Rule parity check — runs the JS scanner (extension/rules.js) against every
// corpus fixture and compares the rule ID sets against the Python scanner's
// output. Fails (non-zero exit) if they differ on any fixture.
//
// The Python side is invoked once via `python3 -m scanner.cli --json` and
// its output is treated as ground truth for this comparison; this script
// only proves the JS engine agrees with it, rule ID for rule ID.

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

function loadJsScanner() {
  const src = fs.readFileSync(path.join(ROOT, 'extension', 'rules.js'), 'utf8');
  const sandbox = {
    atob: (b64) => Buffer.from(b64, 'base64').toString('binary'),
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox, { filename: 'extension/rules.js' });
  return sandbox.scanContent;
}

function collectCorpusFiles() {
  const corpusDir = path.join(ROOT, 'corpus');
  const exts = new Set(['.md', '.json', '.yaml', '.yml', '.txt']);
  const out = [];
  for (const sub of ['malicious', 'mcp', 'benign', 'edge_cases']) {
    const dir = path.join(corpusDir, sub);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      if (exts.has(path.extname(f))) out.push(path.join(dir, f));
    }
  }
  return out.sort();
}

function pythonRuleIds(filePath) {
  const raw = execFileSync('python3', ['-m', 'scanner.cli', filePath, '--json'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  const parsed = JSON.parse(raw);
  const result = parsed[0];
  return new Set(result.findings.map((f) => f.rule_id));
}

function jsRuleIds(scanContent, filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const result = scanContent(content, path.basename(filePath));
  return new Set(result.findings.map((f) => f.id));
}

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

function main() {
  const scanContent = loadJsScanner();
  const files = collectCorpusFiles();
  let failures = 0;

  console.log(`Checking rule parity across ${files.length} corpus fixtures…\n`);

  for (const file of files) {
    const rel = path.relative(ROOT, file);
    const py = pythonRuleIds(file);
    const js = jsRuleIds(scanContent, file);

    if (setsEqual(py, js)) {
      console.log(`  ✓ ${rel}`);
    } else {
      failures++;
      console.log(`  ✗ ${rel}`);
      const pyOnly = [...py].filter((x) => !js.has(x));
      const jsOnly = [...js].filter((x) => !py.has(x));
      if (pyOnly.length) console.log(`      python only: ${pyOnly.join(', ')}`);
      if (jsOnly.length) console.log(`      js only:     ${jsOnly.join(', ')}`);
    }
  }

  console.log();
  if (failures) {
    console.log(`FAILED: ${failures} fixture(s) show Python/JS rule parity mismatch.`);
    process.exit(1);
  }
  console.log('All fixtures agree between Python and JS scanners.');
  process.exit(0);
}

main();
