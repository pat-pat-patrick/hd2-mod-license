"""Tests for the Lua check, on PUC Lua 5.1 (the game's VM) and LuaJIT.

Licenses are signed with the fixture key a (fixtures/test_keys.json, test only).
With --chunk the tests run against a build (tools/build_check.py) instead of the
readable source; a build baked with the fixture declaration (--allow-test-key)
passes them all.

Needs the `lupa` and `cryptography` packages. Run from anywhere:
    python tools/test_check.py
    python tools/test_check.py --chunk dist/license_check.lua
"""
import argparse
import base64
import json
import math
import os
import sys
import tempfile
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
MEMBER = "1a2b3c4d5e6f7081"          # in fixtures/license_a.txt
NOW = 1900000000                     # between its issued and expires
ISSUED, EXPIRES = 1793600714, 2108960714


def rr_hex(n):
    k = math.ceil(len(n) * 4 / 26)
    r = format(pow(2, 2 * 26 * k, int(n, 16)), "x")
    return "0" + r if len(r) % 2 else r


class Suite:
    def __init__(self, runtime, chunk):
        self.runtime, self.code = runtime, open(chunk, encoding="utf-8").read()
        keys = json.load(open(os.path.join(REPO, "fixtures", "test_keys.json")))
        self.n = keys["a"]["n"].lower()
        self.key = {"issuer": "issuer.test", "n": self.n, "rr": rr_hex(self.n)}
        self.priv = serialization.load_der_private_key(base64.b64decode(keys["a"]["pkcs8"]), None)
        self.license_a = open(os.path.join(REPO, "fixtures", "license_a.txt"), encoding="utf-8").read()
        self.fails = 0
        # check() reads <APPDATA>\Arrowhead\Helldivers2\licenses\<issuer>.txt. With APPDATA "."
        # that is, on Linux, one file name with backslashes in it, in the working directory.
        self.cwd = tempfile.mkdtemp()
        os.environ["APPDATA"] = "."

    def sign(self, accounts, issued, expires, issuer="issuer.test"):
        body = "HD2 MOD LICENSE 1\nissuer=%s\naccounts=%s\nissued=%d\nexpires=%d\nholder=t\n" % (
            issuer, ",".join(accounts), issued, expires)
        sig = self.priv.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256())
        return body + "sig=" + sig.hex() + "\n"

    def put(self, text):
        name = ".\\Arrowhead\\Helldivers2\\licenses\\issuer.test.txt"
        path = os.path.join(self.cwd, name)
        # on Windows the backslashes are folders, which must exist; on Linux the
        # name is one file in the working directory, whose folder exists already
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def state(self, prelude="", peer="os.time"):
        """A fresh Lua state: the game's peer_id is `peer`; `prelude` runs before the check loads."""
        L = self.runtime.LuaRuntime(unpack_returned_tuples=True)
        L.execute("python = nil; package.loaded.python = nil")
        os.chdir(self.cwd)
        L.execute("stingray = { Network = { peer_id = %s } }" % peer)
        L.execute(prelude)
        L.globals().M = L.eval("loadstring")(self.code, "license_check")()
        L.globals().KEY = L.table_from(self.key)
        return L

    def verify(self, L, text, now, account, key="KEY"):
        L.globals().TEXT = text
        r = L.eval("{M.verify(TEXT, %s, %d, '%s')}" % (key, now, account))
        return "pass" if r[1] else r[2]

    def check(self, L):
        r = L.eval("{M.check(KEY)}")
        return "pass" if r[1] else r[2]

    def expect(self, label, got, want):
        ok = got == want
        self.fails += not ok
        print(("  ok    " if ok else "  FAIL  ") + label + ": " + repr(got) + ("" if ok else ", want " + repr(want)))

    def run(self):
        L = self.state()
        v = lambda text, now, account=MEMBER, key="KEY": self.verify(L, text, now, account, key)
        self.expect("fixture license", v(self.license_a, NOW), "pass")
        self.expect("another account", v(self.license_a, NOW, "ffffffffffffffff"), "account")
        self.expect("expired", v(self.license_a, EXPIRES), "expired")
        self.expect("clock over a day before issue", v(self.license_a, ISSUED - 86401), "clock")
        self.expect("clock an hour before issue", v(self.license_a, ISSUED - 3600), "pass")
        no_issued = self.sign([MEMBER], 0, EXPIRES).replace("issued=0\n", "")
        self.expect("no issued", v(no_issued, NOW), "malformed")
        L.globals().SMALL = L.table_from({"issuer": "issuer.test", "n": self.n[:256], "rr": "01"})
        self.expect("1024-bit key", v(self.license_a, NOW, key="SMALL"), "key")
        L.globals().NOTOP = L.table_from({"issuer": "issuer.test", "n": "0" + self.n[1:], "rr": self.key["rr"]})
        self.expect("key without its top bit", v(self.license_a, NOW, key="NOTOP"), "key")

        # check(): os.time stands in for the game's peer_id, a C function; the license names
        # the ids it returns over the next minutes (its digits read as hex)
        t = int(time.time())
        self.put(self.sign(["%016d" % (t + i) for i in range(-5, 300)], t - 3600, t + 86400))
        self.expect("untouched game, a member here", self.check(self.state()), "pass")
        L2 = self.state()
        L2.execute("os.time = function() return 1 end")
        self.expect("script replaces os.time after load", self.check(L2), "pass")
        self.expect("peer id 0", self.check(self.state("", "collectgarbage")), "no_account")
        self.expect("no Network yet", self.check(self.state("stingray = nil")), "no_account")
        self.expect("no debug library", self.check(self.state("debug = nil")), "no_debug")
        wrap = "coroutine.wrap(function() while true do coroutine.yield(%s) end end)"
        tampered = {
            "peer_id is Lua": ("", "function() return '%s' end" % MEMBER),
            "peer_id is coroutine.wrap": ("", wrap % ("'%s'" % MEMBER)),
            "peer_id is string.gmatch": ("", "string.gmatch('%s', '.+')" % MEMBER),
            "peer_id is io.read": ("", "io.read"),
            "peer_id is io.lines": ("", "io.lines('%s')" % os.path.join(REPO, "README.md").replace("\\", "/")),
            "os.time is Lua": ("os.time = function() return %d end" % NOW, "os.time"),
            "os.time is coroutine.wrap": ("os.time = " + wrap % NOW, "os.time"),
            "io.read is Lua": ("local r = io.read; io.read = function(...) return r(...) end", "os.time"),
            "string.find is Lua": ("local f = string.find; string.find = function(...) return f(...) end", "os.time"),
            "debug.getinfo says C for all": ("local g = debug.getinfo; debug.getinfo = function(f, w) "
                                             "local i = g(f, w); i.what = 'C'; return i end", "os.time"),
        }
        for label, (prelude, peer) in tampered.items():
            self.expect(label, self.check(self.state(prelude, peer)), "tampered")
        self.put(self.sign([MEMBER], t - 3600, t + 86400))
        self.expect("untouched game, not a member here", self.check(self.state()), "account")
        return self.fails


def main():
    ap = argparse.ArgumentParser(description="Test the Lua license check.")
    ap.add_argument("--chunk", default=os.path.join(REPO, "lua", "license_check.lua"),
                    help="the check to test: the readable source, or a build baked with the fixture key")
    chunk = os.path.abspath(ap.parse_args().chunk)
    import lupa.lua51
    import lupa.luajit21
    fails = 0
    for name, runtime in (("PUC Lua 5.1", lupa.lua51), ("LuaJIT", lupa.luajit21)):
        print(name)
        fails += Suite(runtime, chunk).run()
    print("%d failed" % fails if fails else "all passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
