<?php
// SITS OUTSIDE templates/. It is a sentinel, not a secret: a file whose EXECUTION is observable, so a
// witness can tell "the renderer escaped its directory" from "the renderer did its job".
echo "SHARD_TEMPLATE_ESCAPED_ROOT";
