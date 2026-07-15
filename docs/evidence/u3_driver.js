// U3 driver: stream-json multi-turn. Turn 1, then add a UserPromptSubmit hook to
// settings.json, then Turn 2. If the marker file appears, hooks are re-read live.
const { spawn } = require('child_process');
const fs = require('fs');

const BASE = 'C:/Users/user/AppData/Local/Temp/claude/C--projects/9e822f2f-9ce0-4e0d-93d0-d68b42725ecf/scratchpad/surface-tests';
const PROJ = BASE + '/u3-project';
const SETTINGS = PROJ + '/.claude/settings.json';
const MARKER = BASE + '/logs/u3_marker.txt';
const EVLOG = BASE + '/logs/u3_events.log';

const HOOK_ADDED = {
  hooks: {
    UserPromptSubmit: [
      { hooks: [ { type: 'command', command: 'node ' + BASE + '/hooks/u3_marker.js', timeout: 30 } ] }
    ]
  }
};

// reset state
try { fs.unlinkSync(MARKER); } catch (e) {}
try { fs.unlinkSync(EVLOG); } catch (e) {}
fs.writeFileSync(SETTINGS, JSON.stringify({ hooks: {} }, null, 2));

function userMsg(text) {
  return JSON.stringify({ type: 'user', message: { role: 'user', content: [{ type: 'text', text }] } }) + '\n';
}

const child = spawn('claude', [
  '-p',
  '--input-format', 'stream-json',
  '--output-format', 'stream-json',
  '--verbose',
  '--model', 'haiku'
], { cwd: PROJ, stdio: ['pipe', 'pipe', 'pipe'], shell: true });

let buf = '';
let resultsSeen = 0;
let editedAfterTurn1 = false;
let turn2Sent = false;

function log(s) { fs.appendFileSync(EVLOG, s + '\n'); }

child.stdout.on('data', (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    let ev;
    try { ev = JSON.parse(line); } catch (e) { log('NONJSON: ' + line.slice(0, 200)); continue; }
    log('EVENT type=' + ev.type + (ev.subtype ? ' subtype=' + ev.subtype : ''));
    if (ev.type === 'result') {
      resultsSeen++;
      log('=> result #' + resultsSeen + ' result_text=' + JSON.stringify(ev.result || '').slice(0, 80));
      if (resultsSeen === 1 && !editedAfterTurn1) {
        editedAfterTurn1 = true;
        fs.writeFileSync(SETTINGS, JSON.stringify(HOOK_ADDED, null, 2));
        log('--- edited settings.json to add UserPromptSubmit hook ---');
        setTimeout(() => {
          child.stdin.write(userMsg('Reply with the two letters OK and nothing else.'));
          turn2Sent = true;
          log('--- sent turn 2 ---');
        }, 600);
      } else if (resultsSeen >= 2) {
        setTimeout(() => { try { child.stdin.end(); } catch (e) {} }, 400);
      }
    }
  }
});

child.stderr.on('data', (d) => log('STDERR: ' + d.toString().trim()));

child.on('spawn', () => {
  log('--- spawned; sending turn 1 ---');
  child.stdin.write(userMsg('Reply with the single word READY and nothing else.'));
});

child.on('close', (code) => {
  const markerExists = fs.existsSync(MARKER);
  log('--- child closed code=' + code + ' ---');
  console.log('CHILD_EXIT=' + code);
  console.log('RESULTS_SEEN=' + resultsSeen);
  console.log('TURN2_SENT=' + turn2Sent);
  console.log('MARKER_EXISTS=' + markerExists);
  if (markerExists) console.log('MARKER_CONTENT=' + fs.readFileSync(MARKER, 'utf8').trim());
});

// global safety timeout
setTimeout(() => { log('--- global timeout, killing ---'); try { child.stdin.end(); } catch (e) {} setTimeout(() => child.kill(), 1000); }, 120000);
