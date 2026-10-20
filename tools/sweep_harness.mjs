// sweep_harness.mjs -- the JavaScript side of `emuverify.py sweep`.
//
// One Node process serves a whole sweep. It imports the candidate's module
// once, then reads cases as JSON lines on stdin and writes one result line
// per case on stdout, in order:
//
//   in   {"id": 17, "args": [-256, 128, -1], "globals": {"g_limit": 10}}
//   out  {"id": 17, "result": {"ax": 0}, "calls": [], "pid": 4242}
//   out  {"id": 17, "error": "TypeError: ...", "calls": [], "pid": 4242}
//
// The first line out says whether the module loaded:
//
//   {"ready": true, "node": "v22.17.0", "pid": 4242}
//   {"ready": false, "error": "..."}
//
// The contract the candidate function sees is in tools/sweep.py and
// knowledge/18-oracle-sweeps.md: fn(args, ctx), with ctx.globals (frozen)
// and ctx.call(target, ...args), which records the call and returns its stub.
//
// Usage (by sweep.py, not by hand):
//   node sweep_harness.mjs /abs/path/port.mjs functionName '[100, null]'

import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const [modulePath, exportName, stubsJson] = process.argv.slice(2);
const stubs = JSON.parse(stubsJson || "[]");

// emuverify.py's stub for the n-th call of a case (n counts from 1), unless
// the domain names another.
function stubFor(n) {
  const given = stubs[n - 1];
  return given === null || given === undefined ? (0x1234 + n * 7) & 0xffff : given & 0xffff;
}

function say(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

// stdout carries the results, one line each. A candidate's console.log would
// land in the middle of them, so it goes to stderr instead.
console.log = (...args) => process.stderr.write(args.join(" ") + "\n");

let fn;
try {
  const mod = await import(pathToFileURL(modulePath).href);
  fn = mod[exportName];
  if (typeof fn !== "function") {
    throw new Error(`${modulePath} exports no function named ${exportName}`);
  }
} catch (e) {
  say({ ready: false, error: String((e && e.stack) || e) });
  process.exit(0);
}
say({ ready: true, node: process.version, pid: process.pid });

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (!line) continue;
  const c = JSON.parse(line);
  const calls = [];
  const ctx = {
    globals: Object.freeze({ ...c.globals }),
    call(target, ...args) {
      calls.push({ target: String(target), args });
      return stubFor(calls.length);
    },
  };
  try {
    const result = fn(c.args, ctx);
    say({ id: c.id, result: result === undefined ? null : result, calls, pid: process.pid });
  } catch (e) {
    say({ id: c.id, error: String((e && e.message) || e), calls, pid: process.pid });
  }
}
