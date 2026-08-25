"use strict";

// The observation half of this example's entry point. `entry.sh` is what Shard runs; this decides
// whether anything worth reporting happened.
//
// WHAT IT WATCHES, and why it is not "the read succeeded". `readNote` is SUPPOSED to read files —
// that is the feature. An entry point that fired whenever a read returned something would fire on
// every benign input beside it, Shard would reproduce the finding against those controls, and the
// finding would be refused. Correctly.
//
// So the marker means one specific thing: content that exists only OUTSIDE the notes directory came
// back out of a function whose whole job is to stay inside it.
//
// NOTHING BUT THE MARKER IS PRINTED. The note body is never echoed — printing what you were given is
// how an entry point ends up "demonstrating" its own echo.

const fs = require("fs");
const { readNote } = require("../app.js");

// Yours to choose, and specific enough that nothing else in your output can produce it.
const MARKER = "SHARD_NOTE_PATH_ESCAPED";

// A string that appears in exactly one file, and that file is not under the notes directory.
const SENTINEL = "vault-only";

const payload = process.argv[2];
if (!payload) {
  process.exit(2);
}

const name = fs.readFileSync(payload, "utf8").trim();
if (!name) {
  process.exit(0);
}

let body;
try {
  body = readNote(name);
} catch (err) {
  // A note that does not exist is the program working, not a finding.
  process.exit(0);
}

if (body.includes(SENTINEL)) {
  console.log(MARKER);
}
