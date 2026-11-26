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

Output contract (README, "Verifier output contract"): every check is PASS, FAIL
or INCONCLUSIVE (could not query: neither a pass nor a refutation). Exit 0 =
no FAIL and no INCONCLUSIVE; 1 = at least one FAIL; 2 = no FAIL but at least
one INCONCLUSIVE. Env: BASE_RPC (leg 2 on-chain; wins over anchor.json),
SEPOLIA_RPC (leg 1), VERIFY_BACKOFF_S (retry backoff base, default 1).
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

RESULTS = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0}
ATTEMPTS = 3
BACKOFF_S = float(os.environ.get("VERIFY_BACKOFF_S", "1"))
UA = "composed-attestation-3leg-verifier/1.0"


def emit(status, text):
    RESULTS[status] += 1
    print(f"[{status}] {text}")


class Unreachable(Exception):
    """A remote source could not be queried (not: it answered and refuted)."""


class Reverted(Unreachable):
    """The RPC answered: the call reverted. A determinate answer, not a transport
    failure. Callers that can interpret a revert catch this first; anywhere else it
    still reads as could-not-query (Unreachable), so no other check changes."""


class NoData(Exception):
    """The RPC answered an eth_call with empty data ("0x"): there is no contract
    code at the address, or nothing there answers the call. A determinate negative."""


def _fetch(req):
    """urlopen with bounded retry on transient failures (429, 5xx, timeout,
    connection errors). Raises Unreachable when all attempts fail."""
    last = None
    for i in range(ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if not (e.code == 429 or 500 <= e.code < 600):
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last = e
        if i < ATTEMPTS - 1:
            time.sleep(BACKOFF_S * (2 ** i))
    raise Unreachable(f"{type(last).__name__}: {last}")


def _rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json", "User-Agent": UA})
    raw = _fetch(req)
    try:
        resp = json.loads(raw)
    except ValueError as e:
        raise Unreachable(f"non-JSON RPC response: {e}")
    err = resp.get("error") if isinstance(resp, dict) else None
    if isinstance(err, dict) and (err.get("code") == 3 or "revert" in str(err.get("message", "")).lower()):
        raise Reverted(f"execution reverted: {str(err)[:120]}")
    if not isinstance(resp, dict) or "result" not in resp:
        raise Unreachable(f"RPC returned no result: {str(resp)[:120]}")
    return resp["result"]


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
    ap.add_argument("--no-network", action="store_true", help="do not touch the network: every check that needs it is reported INCONCLUSIVE (not run), exit 2")
    args = ap.parse_args()

    art = os.path.abspath(args.artifacts)
    m = json.load(open(os.path.join(art, "manifest.json")))
    ok = True

    # --- Leg 3 -----------------------------------------------------------
    leg3 = m["leg3_attested"]
    preimage3 = leg3["preimage"]
    recomputed3 = "sha256:" + sha256_hex(jcs(preimage3))
    check3a = recomputed3 == leg3["decision_ref"]
    emit("PASS" if check3a else "FAIL", f"leg3 decision_ref recompute (cached preimage): {recomputed3}")
    ok &= check3a

    if args.no_network:
        emit("INCONCLUSIVE", "leg3 live re-fetch not run (--no-network); cached-preimage check above still stands")
    else:
        try:
            req = urllib.request.Request(
                "https://api.babyblueviper.com/ledger/236",
                headers={"User-Agent": UA},
            )
            live = json.loads(_fetch(req))
            live_verdict = live["record"]["verdict"]
            live_preimage = {k: live_verdict.get(k) for k in live_verdict["decision_ref_preimage_fields"]}
        except (Unreachable, ValueError, KeyError, TypeError, AttributeError) as e:
            emit("INCONCLUSIVE", f"leg3 live re-fetch could not be completed ({e}); cached-preimage check above still stands")
        else:
            live_recomputed = "sha256:" + sha256_hex(jcs(live_preimage))
            check3b = live_recomputed == live_verdict["decision_ref"] == leg3["decision_ref"]
            emit("PASS" if check3b else "FAIL", f"leg3 decision_ref recompute (live fetch)   : {live_recomputed}")
            ok &= check3b

    # --- Leg 2 -------------------------------------------------------------
    leg2 = m["leg2_ours"]
    recomputed_action_ref = sha256_hex(jcs(leg2["action_preimage"]))
    check2a = recomputed_action_ref == leg2["action_ref"] == leg2["anchor_ref_bytes32"][2:]
    emit("PASS" if check2a else "FAIL", f"leg2 action_ref recompute            : {recomputed_action_ref}")
    ok &= check2a

    dbp = leg2["decision_binding_payload"]
    recomputed_dbr = "sha256:" + sha256_hex(
        json.dumps(dict(sorted(dbp.items())), separators=(",", ":"), ensure_ascii=False)
    )
    check2b = recomputed_dbr == leg2["decision_binding_ref"]
    emit("PASS" if check2b else "FAIL", f"leg2 decision_binding_ref recompute  : {recomputed_dbr}")
    ok &= check2b

    # --- Leg 2 on-chain anchor ------------------------------------------------
    ref = leg2["anchor_ref_bytes32"]
    try:
        with open(os.path.join(art, "anchor.json")) as f:
            anchor = json.load(f)
    except FileNotFoundError:
        anchor = None
        emit("INCONCLUSIVE", "no anchor.json yet — action_ref not anchored on-chain")

    if anchor and args.no_network:
        emit("INCONCLUSIVE", "leg2 on-chain Anchored event not run (--no-network)")
    elif anchor:
        hint = int(anchor["block"])
        # BASE_RPC (verifier-side), when set, wins over the artifact's own "rpc"
        # field. Without it the default still comes from anchor.json, i.e. the
        # artifact chooses the oracle: a declared residual (see README).
        env_rpc = os.environ.get("BASE_RPC")
        rpc_url = env_rpc or anchor.get("rpc", "https://mainnet.base.org")
        rpc_src = "BASE_RPC env" if env_rpc else "artifact anchor.json"
        ANCHORED_TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"
        label = f"leg2 on-chain Anchored event : {anchor['registry']} ({anchor.get('chain','?')}) [rpc: {rpc_src}]"
        try:
            head = int(_rpc(rpc_url, "eth_blockNumber", []), 16)
            from_block = hex(max(0, hint - 25))
            to_block = hex(min(hint + 25, head))
            logs = _rpc(rpc_url, "eth_getLogs", [{"address": anchor["registry"],
                        "fromBlock": from_block, "toBlock": to_block,
                        "topics": [ANCHORED_TOPIC0, ref]}])
            if not isinstance(logs, list):
                raise Unreachable(f"eth_getLogs result is not a list: {str(logs)[:80]}")
        except (Unreachable, ValueError, TypeError) as e:
            emit("INCONCLUSIVE", f"{label} — could not query the RPC ({e}); not a pass, not a refutation")
        else:
            # Do not trust the RPC's filtering: re-check each returned log client-side.
            good = [l for l in logs if isinstance(l, dict)
                    and str(l.get("address", "")).lower() == anchor["registry"].lower()
                    and not l.get("removed")
                    and len(l.get("topics") or []) >= 2
                    and str(l["topics"][0]).lower() == ANCHORED_TOPIC0
                    and str(l["topics"][1]).lower() == ref.lower()]
            check_anchor = bool(good)
            emit("PASS" if check_anchor else "FAIL", label)
            if good:
                print(f"         tx    : {good[0].get('transactionHash')}")
                print(f"         block : {int(good[0]['blockNumber'], 16)}")
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
    emit("PASS" if c1 else "FAIL", f"leg1 raw calldata -> callDataHash (local keccak)")
    ok &= c1
    c2 = keccak256(l1_preimage).hex() == L1_COMMITMENT
    emit("PASS" if c2 else "FAIL", f"leg1 PolicyAction preimage -> actionCommitment {L1_COMMITMENT[:10]}… (local keccak)")
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
        res = _rpc(sep_rpc, "eth_call", [{"to": L1_CONTRACT, "data": data}, "latest"])
        if res in ("0x", ""):
            raise NoData("eth_call returned no data")
        return int(res, 16)
    if args.no_network:
        emit("INCONCLUSIVE", "leg1 live verify() + tampered-output negative not run (--no-network)")
    else:
        # An answer the RPC gave is classified as an answer: empty data (no code at the
        # address) or a revert on the bound input is FAIL, not "could not be queried".
        # Only transport failures and unusable responses are INCONCLUSIVE.
        bound = f"leg1 live verify() on {L1_CONTRACT} (Sepolia)"
        queried = True   # False only when the RPC could not be reached at all
        try:
            r3 = _l1_call(L1_COMMITMENT)
        except NoData:
            emit("FAIL", f"{bound} returned no data: no contract code at that address, or no verify() there")
            ok = False
        except Reverted as e:
            emit("FAIL", f"{bound} reverted on the bound input, expected true ({e})")
            ok = False
        except (Unreachable, ValueError, TypeError) as e:
            # The RPC could not be queried: neither a pass nor a refutation. Never
            # a pass (see summary / exit code 2), and never a silent skip.
            emit("INCONCLUSIVE", f"{bound} could not be queried ({e})")
            queried = False
        else:
            c3 = r3 == 1
            emit("PASS" if c3 else "FAIL", f"{bound} returns true")
            ok &= c3
        tampered = L1_COMMITMENT[:-1] + ("b" if L1_COMMITMENT[-1] != "b" else "c")
        if queried:   # unreachable: one INCONCLUSIVE for leg 1, as before
            try:
                r4 = _l1_call(tampered)
            except NoData:
                emit("FAIL", "leg1 tampered outputHash: verify() returned no data (no contract code at that address)")
                ok = False
            except Reverted:
                # Rejecting the tampered output by reverting is still fail-closed.
                emit("PASS", "leg1 tampered outputHash is rejected (verify() reverts: fail-closed)")
            except (Unreachable, ValueError, TypeError) as e:
                emit("INCONCLUSIVE", f"leg1 tampered outputHash check could not be queried ({e})")
            else:
                c4 = r4 == 0
                emit("PASS" if c4 else "FAIL", "leg1 tampered outputHash returns false (fail-closed)")
                ok &= c4

    print()
    print(f"{RESULTS['PASS']} PASS, {RESULTS['FAIL']} FAIL, {RESULTS['INCONCLUSIVE']} INCONCLUSIVE")
    if RESULTS["FAIL"]:
        print("SOME CHECKS FAILED")
        sys.exit(1)
    if RESULTS["INCONCLUSIVE"]:
        print("INCONCLUSIVE: no check failed, but not every check could run — this is NOT a pass")
        sys.exit(2)
    print("ALL CHECKS PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
