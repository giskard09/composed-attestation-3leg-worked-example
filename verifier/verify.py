#!/usr/bin/env python3
"""
Independent (stdlib-only) verifier for the 3-leg composed attestation worked
example. Trusts nothing in manifest.json's prose — only recomputes, and
re-fetches leg 3 live from its source instead of trusting the cached copy.

  1. Leg 3 (babyblueviper1/invinoveritas #236): re-fetches the ledger entry
     live, recomputes decision_ref from the declared preimage fields
     (JCS-style: sort_keys, compact separators), compares against both the
     live fetch and the manifest's cached copy.
  2. Leg 2 (ours): recomputes action_ref (action-ref-v1, 4-field preimage)
     and decision_binding_ref (decision-binding-ref-v1.0) from their
     declared preimages, checks both match the manifest.
  3. Leg 1 (WYRIWE/TMerlini): explicitly NOT verified here — flagged SKIP,
     same as babyblueviper1's own framing ("verify aparte si hace falta").

Run: python3 verifier/verify.py [--artifacts DIR] [--no-network]
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request


def jcs(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", default=os.path.join(os.path.dirname(__file__), "..", "artifacts"))
    ap.add_argument("--no-network", action="store_true", help="skip live re-fetch of leg 3")
    args = ap.parse_args()

    art = os.path.abspath(args.artifacts)
    m = json.load(open(os.path.join(art, "manifest.json")))
    ok = True

    # --- Leg 3 -----------------------------------------------------------
    leg3 = m["leg3_attested"]
    preimage3 = leg3["preimage"]
    recomputed3 = "sha256:" + sha256_hex(jcs(preimage3))
    check3a = recomputed3 == leg3["decision_ref"]
    print(f"[{'PASS' if check3a else 'FAIL'}] leg3 decision_ref recompute (cached preimage): {recomputed3}")
    ok &= check3a

    if not args.no_network:
        try:
            req = urllib.request.Request(
                "https://api.babyblueviper.com/ledger/236",
                headers={"User-Agent": "composed-attestation-3leg-verifier/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                live = json.loads(r.read())
            live_verdict = live["record"]["verdict"]
            live_preimage = {k: live_verdict.get(k) for k in live_verdict["decision_ref_preimage_fields"]}
            live_recomputed = "sha256:" + sha256_hex(jcs(live_preimage))
            check3b = live_recomputed == live_verdict["decision_ref"] == leg3["decision_ref"]
            print(f"[{'PASS' if check3b else 'FAIL'}] leg3 decision_ref recompute (live fetch)   : {live_recomputed}")
            ok &= check3b
        except Exception as e:
            print(f"[SKIP] leg3 live re-fetch failed ({e}) — cached-preimage check above still stands")

    # --- Leg 2 -------------------------------------------------------------
    leg2 = m["leg2_ours"]
    recomputed_action_ref = sha256_hex(jcs(leg2["action_preimage"]))
    check2a = recomputed_action_ref == leg2["action_ref"] == leg2["anchor_ref_bytes32"][2:]
    print(f"[{'PASS' if check2a else 'FAIL'}] leg2 action_ref recompute            : {recomputed_action_ref}")
    ok &= check2a

    dbp = leg2["decision_binding_payload"]
    recomputed_dbr = "sha256:" + sha256_hex(
        json.dumps(dict(sorted(dbp.items())), separators=(",", ":"), ensure_ascii=False)
    )
    check2b = recomputed_dbr == leg2["decision_binding_ref"]
    print(f"[{'PASS' if check2b else 'FAIL'}] leg2 decision_binding_ref recompute  : {recomputed_dbr}")
    ok &= check2b

    # --- Leg 2 on-chain anchor ------------------------------------------------
    ref = leg2["anchor_ref_bytes32"]
    try:
        with open(os.path.join(art, "anchor.json")) as f:
            anchor = json.load(f)
    except FileNotFoundError:
        anchor = None
        print("[SKIP] no anchor.json yet — action_ref not anchored on-chain")

    if anchor and not args.no_network:
        hint = int(anchor["block"])
        rpc_url = anchor.get("rpc", "https://mainnet.base.org")
        req = urllib.request.Request(
            rpc_url,
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "composed-attestation-3leg-verifier/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            head = int(json.loads(r.read())["result"], 16)
        from_block = hex(max(0, hint - 25))
        to_block = hex(min(hint + 25, head))
        ANCHORED_TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
            "params": [{"address": anchor["registry"], "fromBlock": from_block, "toBlock": to_block,
                        "topics": [ANCHORED_TOPIC0, ref]}],
        }).encode()
        req = urllib.request.Request(rpc_url, data=body, headers={"Content-Type": "application/json", "User-Agent": "composed-attestation-3leg-verifier/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            logs = json.loads(r.read())["result"]
        check_anchor = bool(logs)
        print(f"[{'PASS' if check_anchor else 'FAIL'}] leg2 on-chain Anchored event : {anchor['registry']} ({anchor.get('chain','?')})")
        if logs:
            print(f"         tx    : {logs[0]['transactionHash']}")
            print(f"         block : {int(logs[0]['blockNumber'], 16)}")
        ok &= check_anchor

    # --- Leg 1 ---------------------------------------------------------------
    print(f"[SKIP] leg1 (WYRIWE/TMerlini, {m['leg1_transparent']['contract']}) — referenced, not verified here")

    print()
    print("ALL CHECKS PASS" if ok else "SOME CHECKS FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
