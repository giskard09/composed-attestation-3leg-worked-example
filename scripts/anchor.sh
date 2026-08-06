#!/usr/bin/env bash
# Anchor leg 2's action_ref into AnchorRegistry on Base mainnet.
# Permissionless anchor(bytes32). Reads the ref from artifacts/manifest.json,
# writes tx/block into artifacts/anchor.json.
set -euo pipefail

REGISTRY="0x49fEcA52bC634a9Ab773226D16619deC547794aa"
RPC="${BASE_RPC:-https://mainnet.base.org}"
ART="$(cd "$(dirname "$0")/.." && pwd)/artifacts"

REF="$(python3 -c 'import json;print(json.load(open("'"$ART"'/manifest.json"))["leg2_ours"]["anchor_ref_bytes32"])')"
echo "Anchoring leg2 ref: $REF"
echo "Registry:           $REGISTRY (Base mainnet 8453)"

: "${OWNER_PRIVATE_KEY:?set OWNER_PRIVATE_KEY in env}"

OUT="$(cast send "$REGISTRY" "anchor(bytes32)" "$REF" \
  --rpc-url "$RPC" \
  --private-key "$OWNER_PRIVATE_KEY" \
  --json)"

echo "$OUT"

TX_HASH="$(echo "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["transactionHash"])')"
BLOCK="$(echo "$OUT" | python3 -c 'import json,sys;print(int(json.load(sys.stdin)["blockNumber"],16))')"

python3 -c "
import json
anchor = {
    'ref': '$REF',
    'tx_hash': '$TX_HASH',
    'block': $BLOCK,
    'registry': '$REGISTRY',
    'chain': 'Base mainnet (chainId 8453)',
    'rpc': '$RPC',
}
with open('$ART/anchor.json', 'w') as f:
    json.dump(anchor, f, indent=2, sort_keys=True)
    f.write('\n')
"
echo "wrote $ART/anchor.json"
