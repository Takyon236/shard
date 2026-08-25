<?php
// The observation half of this example's entry point.
//
// WHAT IT WATCHES, and why it is not "did the include succeed". `render` is SUPPOSED to include
// files — that is the feature. An entry point firing whenever a template rendered would fire on every
// benign input beside it, Shard would reproduce the finding against those controls, and refuse it.
//
// So the marker means one narrow thing: a PHP file from OUTSIDE the template root was EXECUTED. The
// sentinel `secrets.php` is the only file that can emit it, it sits beside the template directory
// rather than inside it, and no template name that stays under the root can reach it.
//
// The marker cannot come from the payload: the payload supplies a template NAME, and the only thing
// this witness prints is a literal it holds itself.
//
// NOTHING BUT THE MARKER IS PRINTED. The rendered page is never echoed — printing what you were given
// is how an entry point ends up demonstrating its own echo.

require_once __DIR__ . '/../render.php';

const MARKER = 'SHARD_TEMPLATE_ESCAPED_ROOT';

$payload = $argv[1] ?? null;
if ($payload === null) {
    exit(2);
}

$name = trim((string) file_get_contents($payload));
if ($name === '') {
    exit(0);
}

// A missing template makes `include` emit a warning. That is the renderer working on a name that does
// not exist, not a finding, so the warning must not reach the output the adjudicator reads.
error_reporting(0);
ini_set('display_errors', '0');

$rendered = \Demo\render($name);

if (strpos($rendered, MARKER) !== false) {
    echo MARKER . "\n";
}
