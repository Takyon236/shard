"use strict";

// A pocket-sized note reader with one real defect, kept to a single page.
//
// The defect is the `path.join` on the line marked below. `path.join` NORMALISES `..` — it collapses
// the segment and returns a path outside the directory — it does not refuse it. That difference is
// the whole bug, and it is easy to miss because the code reads as though the join is the containment.

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "data");

/** Read a note by name, relative to the notes directory. */
function readNote(name) {
  // THE DEFECT. Nothing here checks that the result is still under ROOT.
  return fs.readFileSync(path.join(ROOT, name), "utf8");
}

module.exports = { ROOT, readNote };
