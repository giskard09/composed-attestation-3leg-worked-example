"""Offline tests for verifier/verify.py network behaviour.

No real network: urllib.request.urlopen is replaced by a local fake. Run:
    python3 -I tests/test_verify_network.py
"""
import contextlib
import importlib.util
import io
import json
import os
import sys
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ART = os.path.join(ROOT, "artifacts")
TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"

os.environ["VERIFY_BACKOFF_S"] = "0"


def load():
    spec = importlib.util.spec_from_file_location("verify_under_test", os.path.join(ROOT, "verifier", "verify.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MANIFEST = json.load(open(os.path.join(ART, "manifest.json")))
ANCHOR = json.load(open(os.path.join(ART, "anchor.json")))
REF = MANIFEST["leg2_ours"]["anchor_ref_bytes32"]


def live_ledger():
    leg3 = MANIFEST["leg3_attested"]
    fields = list(leg3["preimage"].keys())
    verdict = dict(leg3["preimage"])
    verdict["decision_ref_preimage_fields"] = fields
    verdict["decision_ref"] = leg3["decision_ref"]
    return {"record": {"verdict": verdict}}


def good_log(**over):
    log = {"address": ANCHOR["registry"], "topics": [TOPIC0, REF], "removed": False,
           "transactionHash": ANCHOR["tx_hash"], "blockNumber": hex(ANCHOR["block"])}
    log.update(over)
    return log


class Resp:
    def __init__(self, body): self.body = body
    def read(self): return self.body
    def __enter__(self): return self
    def __exit__(self, *a): return False


def http_err(code):
    return urllib.error.HTTPError("http://x", code, "err", {}, None)


class Net:
    """Scripted fake network. getlogs/sepolia are lists of actions consumed in
    order (last one repeats): ('ok', value) | ('http', code) | ('rpcerr',) | ('revert',)."""
    def __init__(self, getlogs=None, sepolia=None, ledger=None):
        self.getlogs = getlogs or [("ok", [good_log()])]
        self.sepolia = sepolia or [("ok", "0x1"), ("ok", "0x0")]
        self.ledger = ledger or [("ok", live_ledger())]
        self.calls = []
        self.chain_id = 11155111
        self._n = {"getlogs": 0, "sepolia": 0, "ledger": 0}

    def _take(self, kind, script):
        i = min(self._n[kind], len(script) - 1)
        self._n[kind] += 1
        return script[i]

    def urlopen(self, req, timeout=None):
        url = req.full_url
        self.calls.append(url)
        if "babyblueviper" in url:
            act = self._take("ledger", self.ledger)
            return self._act(act, raw=True)
        body = json.loads(req.data)
        m = body["method"]
        if m == "eth_blockNumber":
            return Resp(json.dumps({"result": hex(ANCHOR["block"] + 5)}).encode())
        if m == "eth_getLogs":
            return self._act(self._take("getlogs", self.getlogs))
        if m == "eth_chainId":
            return Resp(json.dumps({"result": hex(self.chain_id)}).encode())
        if m == "eth_call":
            return self._act(self._take("sepolia", self.sepolia))
        raise AssertionError(m)

    def _act(self, act, raw=False):
        if act[0] == "http":
            raise http_err(act[1])
        if act[0] == "rpcerr":
            return Resp(json.dumps({"error": {"code": -32005, "message": "rate limited"}}).encode())
        if act[0] == "revert":
            return Resp(json.dumps({"jsonrpc": "2.0", "id": 1,
                                    "error": {"code": 3, "message": "execution reverted"}}).encode())
        if act[0] == "notjson":
            return Resp(b"<html>nope</html>")
        return Resp(json.dumps(act[1] if raw else {"result": act[1]}).encode())


def run(net, *argv, env=None):
    mod = load()
    mod.urllib.request.urlopen = net.urlopen
    old_env = dict(os.environ)
    for k in ("BASE_RPC", "SEPOLIA_RPC"):
        os.environ.pop(k, None)
    os.environ.update(env or {})
    out = io.StringIO()
    code = None
    old_argv = sys.argv
    sys.argv = ["verify.py", "--artifacts", ART, *argv]
    try:
        with contextlib.redirect_stdout(out):
            try:
                mod.main()
            except SystemExit as e:
                code = e.code
    finally:
        sys.argv = old_argv
        os.environ.clear(); os.environ.update(old_env)
    return code, out.getvalue()


class T(unittest.TestCase):
    def test_all_good(self):
        code, out = run(Net())
        self.assertEqual(code, 0, out)
        self.assertIn("ALL CHECKS PASS", out)
        self.assertIn("0 FAIL, 0 INCONCLUSIVE", out)

    def test_429_exhausted_is_inconclusive_not_traceback(self):
        net = Net(getlogs=[("http", 429)])
        code, out = run(net)
        self.assertEqual(code, 2, out)
        self.assertIn("[INCONCLUSIVE] leg2 on-chain Anchored event", out)
        self.assertNotIn("ALL CHECKS PASS", out)
        self.assertEqual(net._n["getlogs"], 3)  # bounded retry

    def test_429_then_ok_retries(self):
        code, out = run(Net(getlogs=[("http", 429), ("http", 429), ("ok", [good_log()])]))
        self.assertEqual(code, 0, out)

    def test_http_404_not_retried(self):
        net = Net(getlogs=[("http", 404)])
        code, out = run(net)
        self.assertEqual(code, 2, out)
        self.assertEqual(net._n["getlogs"], 1)

    def test_jsonrpc_error_body_is_inconclusive(self):
        code, out = run(Net(getlogs=[("rpcerr",)]))
        self.assertEqual(code, 2, out)
        self.assertIn("could not query the RPC", out)

    def test_non_json_body_is_inconclusive(self):
        code, out = run(Net(getlogs=[("notjson",)]))
        self.assertEqual(code, 2, out)

    def test_event_absent_is_fail_not_inconclusive(self):
        code, out = run(Net(getlogs=[("ok", [])]))
        self.assertEqual(code, 1, out)
        self.assertIn("[FAIL] leg2 on-chain Anchored event", out)

    def test_rpc_returns_log_for_wrong_ref_is_fail(self):
        bad = good_log(topics=[TOPIC0, "0x" + "00" * 32])
        code, out = run(Net(getlogs=[("ok", [bad])]))
        self.assertEqual(code, 1, out)

    def test_rpc_returns_log_for_wrong_address_is_fail(self):
        bad = good_log(address="0x" + "11" * 20)
        code, out = run(Net(getlogs=[("ok", [bad])]))
        self.assertEqual(code, 1, out)

    def test_removed_log_is_fail(self):
        code, out = run(Net(getlogs=[("ok", [good_log(removed=True)])]))
        self.assertEqual(code, 1, out)

    def test_base_rpc_env_wins_over_artifact(self):
        net = Net()
        code, out = run(net, env={"BASE_RPC": "https://rpc.example.invalid/base"})
        self.assertEqual(code, 0, out)
        self.assertIn("[rpc: BASE_RPC env]", out)
        hit = [u for u in net.calls if "example.invalid" in u]
        self.assertTrue(hit)
        self.assertFalse([u for u in net.calls if u == ANCHOR["rpc"]])

    def test_artifact_rpc_used_without_env_and_labelled(self):
        net = Net()
        code, out = run(net)
        self.assertIn("[rpc: artifact anchor.json]", out)
        self.assertTrue([u for u in net.calls if u == ANCHOR["rpc"]])

    def test_no_network_touches_nothing_and_is_not_a_pass(self):
        net = Net()
        code, out = run(net, "--no-network")
        self.assertEqual(net.calls, [])
        self.assertEqual(code, 2, out)
        self.assertNotIn("ALL CHECKS PASS", out)
        self.assertIn("leg1 live verify()", out)

    def test_leg3_live_unreachable_is_inconclusive(self):
        code, out = run(Net(ledger=[("http", 503)]))
        self.assertEqual(code, 2, out)
        self.assertIn("[INCONCLUSIVE] leg3 live re-fetch", out)

    def test_leg3_live_mismatch_is_fail(self):
        led = live_ledger()
        led["record"]["verdict"]["decision_ref"] = "sha256:" + "0" * 64
        code, out = run(Net(ledger=[("ok", led)]))
        self.assertEqual(code, 1, out)

    def test_sepolia_unreachable_is_inconclusive(self):
        code, out = run(Net(sepolia=[("http", 429)]))
        self.assertEqual(code, 2, out)
        self.assertIn("[INCONCLUSIVE] leg1 live verify()", out)

    def test_sepolia_false_is_fail(self):
        code, out = run(Net(sepolia=[("ok", "0x0"), ("ok", "0x0")]))
        self.assertEqual(code, 1, out)

    def test_sepolia_tampered_true_is_fail(self):
        code, out = run(Net(sepolia=[("ok", "0x1"), ("ok", "0x1")]))
        self.assertEqual(code, 1, out)

    # --- leg 1: the RPC answered, so its answer is classified, never "could not be queried" ---

    def test_sepolia_no_code_is_fail_not_inconclusive(self):
        # eth_call to an address with no contract code answers "0x"
        code, out = run(Net(sepolia=[("ok", "0x")]))
        self.assertEqual(code, 1, out)
        self.assertIn("[FAIL] leg1 live verify()", out)
        self.assertIn("returned no data", out)
        # the bound call is classified FAIL; the control is reported as not informative
        self.assertNotIn("[INCONCLUSIVE] leg1 live verify()", out)

    def test_sepolia_bound_call_reverts_is_fail(self):
        code, out = run(Net(sepolia=[("revert",), ("ok", "0x0")]))
        self.assertEqual(code, 1, out)
        self.assertIn("reverted on the bound input", out)

    def test_sepolia_tampered_revert_is_fail_closed(self):
        code, out = run(Net(sepolia=[("ok", "0x1"), ("revert",)]))
        self.assertEqual(code, 0, out)
        self.assertIn("[PASS] leg1 tampered outputHash is rejected", out)

    # --- the negative control counts only against a bound call that returned true ---

    def test_both_calls_revert_control_is_not_a_pass(self):
        code, out = run(Net(sepolia=[("revert",), ("revert",)]))
        self.assertEqual(code, 1, out)
        self.assertIn("[FAIL] leg1 live verify()", out)
        self.assertIn("[INCONCLUSIVE] leg1 tampered outputHash negative control not run", out)
        self.assertNotIn("[PASS] leg1 tampered", out)

    def test_both_calls_no_code_control_is_not_a_pass(self):
        code, out = run(Net(sepolia=[("ok", "0x"), ("ok", "0x")]))
        self.assertEqual(code, 1, out)
        self.assertIn("negative control not informative", out)
        self.assertNotIn("[PASS] leg1 tampered", out)

    def test_bound_false_and_tampered_false_control_is_not_a_pass(self):
        code, out = run(Net(sepolia=[("ok", "0x0"), ("ok", "0x0")]))
        self.assertEqual(code, 1, out)
        self.assertIn("negative control not informative", out)
        self.assertNotIn("[PASS] leg1 tampered", out)

    def test_wrong_chain_rpc_is_inconclusive_not_no_contract(self):
        net = Net(sepolia=[("ok", "0x"), ("ok", "0x")])
        net.chain_id = 1
        code, out = run(net)
        self.assertEqual(code, 2, out)
        self.assertIn("not Sepolia", out)
        self.assertNotIn("[FAIL] leg1", out)
        self.assertEqual(out.count("[INCONCLUSIVE] leg1"), 1, out)

    def test_sepolia_non_revert_rpc_error_stays_inconclusive(self):
        # a JSON-RPC error that is not a revert (rate limit) is still could-not-query
        code, out = run(Net(sepolia=[("rpcerr",)]))
        self.assertEqual(code, 2, out)
        self.assertIn("[INCONCLUSIVE] leg1 live verify()", out)
        self.assertEqual(out.count("[INCONCLUSIVE]"), 1, out)

    def test_revert_on_base_rpc_stays_inconclusive_for_leg2(self):
        # only leg 1 interprets a revert; leg 2's behaviour is unchanged
        code, out = run(Net(getlogs=[("revert",)]))
        self.assertEqual(code, 2, out)
        self.assertIn("[INCONCLUSIVE] leg2 on-chain Anchored event", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
