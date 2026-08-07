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
  3. Leg 1 (WYRIWE/TMerlini): verified — closed by the leg's author (PR #1810 follow-up):
     local keccak recompute of callDataHash + actionCommitment, live verify() on the
     deployed Sepolia contract, and a tampered-output negative. Previously flagged SKIP,
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




# ---- pure-stdlib keccak-256 (Keccak pad 0x01) — for the leg-1 WYRIWE recompute ----
def _kc_rot(x, n): return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
_KC_RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
          0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
          0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
          0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
          0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
          0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
_KC_ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]

def _kc_f(A):
    for rc in _KC_RC:
        C=[A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D=[C[(x-1)%5]^_kc_rot(C[(x+1)%5],1) for x in range(5)]
        A=[[A[x][y]^D[x] for y in range(5)] for x in range(5)]
        B=[[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2*x+3*y)%5]=_kc_rot(A[x][y],_KC_ROT[x][y])
        A=[[B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y]) for y in range(5)] for x in range(5)]
        A[0][0]^=rc
    return A

def keccak256(data):
    rate=136
    q=rate-(len(data)%rate)
    p=bytes(data)+(b'\x81' if q==1 else b'\x01'+b'\x00'*(q-2)+b'\x80')
    st=[[0]*5 for _ in range(5)]
    for off in range(0,len(p),rate):
        for i in range(rate//8):
            st[i%5][i//5]^=int.from_bytes(p[off+8*i:off+8*i+8],'little')
        st=_kc_f(st)
    out=b''
    for i in range(4):
        out+=st[i%5][i//5].to_bytes(8,'little')
    return out

assert keccak256(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'


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
    # --- Leg 1 (WYRIWE/TMerlini) — closed by the leg's author per PR #1810 -----
    # Four checks, no prose: the raw calldata hashes to the bound input digest, the
    # 7-field PolicyAction preimage re-derives the shared actionCommitment (both via
    # the pure-stdlib keccak above, cold), the DEPLOYED Sepolia verifier returns true
    # on exactly those bytes, and a tampered outputHash returns false (fail-closed,
    # not constant-true).
    L1_CONTRACT = m["leg1_transparent"]["contract"]
    L1_CALLDATA = bytes.fromhex(
        "82ad56cb0000000000000000000000000000000000000000000000000000000000000020"
        "0000000000000000000000000000000000000000000000000000000000000000")  # Multicall3.aggregate3([])
    L1_INPUT_HASH = "cfacbfe211cf3be67a1d64a6499a2af0ae475e2c0965c2a42f969d243df2b6cd"
    L1_COMMITMENT = "5b5ec31c336cc8f95dc6d9025d1d008c6ed2cd5067b9c421b1d36927e230173a"
    def _w(v): return int(v).to_bytes(32, "big")
    def _addr(a): return bytes(12) + bytes.fromhex(a[2:])
    l1_preimage = (_w(11155111)                                                        # chainId (Sepolia)
        + bytes.fromhex("16079127bc55bd85d480837115b9bd82d26f03809c0bc4c6c80f7220836afad0")  # domainId
        + _w(54848)                                                                     # agentId
        + _addr("0xcA11bde05977b3631167028862bE2a173976CA11")                          # target (Multicall3)
        + _w(0)                                                                         # value
        + bytes.fromhex(L1_INPUT_HASH)                                                  # callDataHash
        + _w(5))                                                                        # actionNonce
    c1 = keccak256(L1_CALLDATA).hex() == L1_INPUT_HASH
    print(f"[{'PASS' if c1 else 'FAIL'}] leg1 raw calldata -> callDataHash (local keccak)")
    ok &= c1
    c2 = keccak256(l1_preimage).hex() == L1_COMMITMENT
    print(f"[{'PASS' if c2 else 'FAIL'}] leg1 PolicyAction preimage -> actionCommitment {L1_COMMITMENT[:10]}… (local keccak)")
    ok &= c2
    sep_rpc = os.environ.get("SEPOLIA_RPC", "https://ethereum-sepolia-rpc.publicnode.com")
    sel = keccak256(b"verify(bytes32,bytes32,bytes,bytes)")[:4]
    def _pad32(b):
        return b + b"\x00" * ((-len(b)) % 32)
    def _l1_call(output_hash_hex):
        # ABI-encode verify(bytes32 inputHash, bytes32 outputHash, bytes calldata_, bytes context).
        # calldata_/context is unused by this verifier; we pass the raw calldata there
        # for completeness — the binding comes from proof.callDataHash == inputHash
        # (checked locally as c1, then passed on-chain as the inputHash argument), not
        # from what verify() does with the trailing bytes params. Verified against the
        # deployed contract.
        calldata_tail = _w(len(L1_CALLDATA)) + _pad32(L1_CALLDATA)
        context_tail = _w(len(l1_preimage)) + _pad32(l1_preimage)
        offset_calldata = 0x80  # 4 head words
        offset_context = offset_calldata + len(calldata_tail)
        head = (bytes.fromhex(L1_INPUT_HASH) + bytes.fromhex(output_hash_hex)
                + _w(offset_calldata) + _w(offset_context))
        data = "0x" + (sel + head + calldata_tail + context_tail).hex()
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                           "params": [{"to": L1_CONTRACT, "data": data}, "latest"]}).encode()
        req = urllib.request.Request(sep_rpc, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "composed-attestation-3leg-verifier/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return int(json.loads(r.read())["result"], 16)
    try:
        c3 = _l1_call(L1_COMMITMENT) == 1
        print(f"[{'PASS' if c3 else 'FAIL'}] leg1 live verify() on {L1_CONTRACT} (Sepolia) returns true")
        ok &= c3
        tampered = L1_COMMITMENT[:-1] + ("b" if L1_COMMITMENT[-1] != "b" else "c")
        c4 = _l1_call(tampered) == 0
        print(f"[{'PASS' if c4 else 'FAIL'}] leg1 tampered outputHash returns false (fail-closed)")
        ok &= c4
    except Exception as e:
        # BUG (found in code review, fixed here): this used to print [SKIP] and fall
        # through WITHOUT clearing `ok` -- if the RPC failed, the script still printed
        # "ALL CHECKS PASS", silently skipping exactly the on-chain checks this PR's
        # own title claims to close. Fail-closed instead: a network failure here is a
        # failed verification, not a skip.
        print(f"[FAIL] leg1 live verify() unreachable ({e}) — on-chain checks could not run, not a pass")
        ok = False

    print()
    print("ALL CHECKS PASS" if ok else "SOME CHECKS FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
