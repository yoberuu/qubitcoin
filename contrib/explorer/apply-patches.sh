#!/bin/sh
# Apply QubitCoin-specific patches to btc-rpc-explorer after clone.
set -e

EXPLORER_DIR="${1:-/workspace}"

echo "Applying QubitCoin overlay to ${EXPLORER_DIR}..."

cp -f /overlay/app/coins.js "${EXPLORER_DIR}/app/coins.js"
cp -f /overlay/app/coins/qbtc.js "${EXPLORER_DIR}/app/coins/qbtc.js"

UTILS="${EXPLORER_DIR}/app/utils.js"
SNIPPET="/overlay/patches/tryParseAddress.js.snippet"

python3 <<PYEOF
import re
from pathlib import Path

utils = Path("${UTILS}")
snippet = Path("${SNIPPET}").read_text()

text = utils.read_text()
pattern = r'function tryParseAddress\(address\) \{.*?\n\}\n+\s*const sleep'
match = re.search(pattern, text, re.DOTALL)
if not match:
    raise SystemExit("ERROR: tryParseAddress block not found — btc-rpc-explorer version may have changed")

patched = snippet.rstrip() + "\n\n\nconst sleep"
text = text[:match.start()] + patched + text[match.end():]
utils.write_text(text)
print("Patched tryParseAddress in utils.js")
PYEOF

echo "QubitCoin patches applied."
