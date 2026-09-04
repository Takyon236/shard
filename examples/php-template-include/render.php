<?php
// A pocket-sized template renderer with one real defect, kept to a single page.
//
// The defect is the `include` on the marked line. It is there for a reason people actually have: the
// author wanted `?page=about` to render `templates/about.php`, and `include` is the shortest thing
// that does it. It also loads whatever path the caller can construct, because `include` resolves
// `..` rather than refusing it — the same mistake `path.join` invites in the Node example, in a
// language where the consequence is code EXECUTION rather than disclosure.

namespace Demo;

const TEMPLATE_ROOT = __DIR__ . '/templates';

/** Render a named template and return its output. */
function render(string $name): string
{
    ob_start();
    // THE DEFECT. Nothing here checks the resolved path is still under TEMPLATE_ROOT.
    include TEMPLATE_ROOT . '/' . $name . '.php';
    return (string) ob_get_clean();
}
