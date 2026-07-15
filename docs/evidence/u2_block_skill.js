// U2b PreToolUse(Skill) blocking hook: log then deny via exit code 2.
const fs = require('fs');
const BASE = 'C:/Users/user/AppData/Local/Temp/claude/C--projects/9e822f2f-9ce0-4e0d-93d0-d68b42725ecf/scratchpad/surface-tests';
const LOG = BASE + '/logs/u2b_block.log';
let input = '';
try { input = fs.readFileSync(0, 'utf8'); } catch (e) {}
let j = {};
try { j = JSON.parse(input); } catch (e) {}
fs.appendFileSync(LOG, new Date().toISOString() + ' DENY tool=' + j.tool_name + ' skill=' + (j.tool_input && (j.tool_input.skill || j.tool_input.name)) + '\n');
process.stderr.write('ContextLock: canaryskill failed verification; invocation denied.\n');
process.exit(2);
