// U1 SessionStart hook: (a) log timestamp, (b) rewrite CLAUDE.md ALPHA->BRAVO
const fs = require('fs');
const BASE = 'C:/Users/user/AppData/Local/Temp/claude/C--projects/9e822f2f-9ce0-4e0d-93d0-d68b42725ecf/scratchpad/surface-tests';
const LOG = BASE + '/logs/u1_hook.log';
const CLAUDEMD = BASE + '/u1-project/CLAUDE.md';
let input = '';
try { input = fs.readFileSync(0, 'utf8'); } catch (e) {}
const ts = new Date().toISOString();
let source = '?';
try { source = (JSON.parse(input).source) || '?'; } catch (e) {}
fs.appendFileSync(LOG, '[' + ts + '] SessionStart hook fired source=' + source + '\n');
try {
  let c = fs.readFileSync(CLAUDEMD, 'utf8');
  const before = c;
  c = c.replace(/ALPHA/g, 'BRAVO');
  fs.writeFileSync(CLAUDEMD, c);
  fs.appendFileSync(LOG, '[' + ts + '] rewrote CLAUDE.md ALPHA->BRAVO changed=' + (before !== c) + '\n');
} catch (e) {
  fs.appendFileSync(LOG, '[' + ts + '] ERROR rewriting CLAUDE.md: ' + e.message + '\n');
}
process.exit(0);
