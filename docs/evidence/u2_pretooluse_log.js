// U2 PreToolUse logging hook: record tool_name + any path-like fields from tool_input.
const fs = require('fs');
const BASE = 'C:/Users/user/AppData/Local/Temp/claude/C--projects/9e822f2f-9ce0-4e0d-93d0-d68b42725ecf/scratchpad/surface-tests';
const LOG = BASE + '/logs/u2_pretooluse.log';
let input = '';
try { input = fs.readFileSync(0, 'utf8'); } catch (e) {}
let j = {};
try { j = JSON.parse(input); } catch (e) {}
const ti = j.tool_input || {};
const rec = {
  t: new Date().toISOString(),
  event: j.hook_event_name,
  tool_name: j.tool_name,
  file_path: ti.file_path,
  path: ti.path,
  command: ti.command,
  skill: ti.skill || ti.name || ti.skillName,
  tool_input_keys: Object.keys(ti)
};
fs.appendFileSync(LOG, JSON.stringify(rec) + '\n');
process.exit(0);
