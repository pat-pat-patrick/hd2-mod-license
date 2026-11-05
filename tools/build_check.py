"""Build one mod's license check from lua/license_check.lua.

The build is made for one issuer and key: they are baked into the source
(BAKED) before Prometheus (https://github.com/prometheus-lua/Prometheus)
obfuscates it, so the key a mod ships sits inside the obfuscated code rather
than in plain Lua next to it, and the mod calls check() with no argument. Every
build is laid out afresh (Prometheus seeds from the clock unless --seed is
given), so no two mods ship the same file and no one patch fits them all.

After building, the output is loaded on PUC Lua 5.1 (the game's VM) and tested:
a fixture license still verifies (the arithmetic survived obfuscation), the
baked key is the one asked for, and an untouched game is not taken as tampered.

Prometheus runs on LuaJIT / Lua 5.1; both backends come from the `lupa` package.
Point the build at a Prometheus checkout with --prometheus or PROMETHEUS_DIR.

Usage (run from the repo root):
    python tools/build_check.py --declaration path/to/mod/hd2_license.json
    python tools/build_check.py --issuer license.example.com --modulus <hex n>
    python tools/build_check.py --declaration ... --no-debug   # game Lua without debug.getinfo
"""
import argparse
import json
import math
import os
import re
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BITS = 26                      # the check's limb size
BAKED_LINE = "local BAKED = nil\n"
NO_DEBUG_LINE = "local NO_DEBUG = false\n"


def rr_hex(n_hex):
    """R^2 mod n in the check's limb base B = 2^26, k = ceil(nbits / 26)."""
    k = math.ceil(len(n_hex) * 4 / BITS)
    r = format(pow(2, 2 * BITS * k, int(n_hex, 16)), "x")
    return "0" + r if len(r) % 2 else r


def test_moduli():
    """The test-only keys' moduli (fixtures/test_keys.json): their private keys are public."""
    keys = json.load(open(os.path.join(REPO, "fixtures", "test_keys.json")))
    return {k["n"].lower().lstrip("0") for k in keys.values() if isinstance(k, dict) and "n" in k}


def key_of(issuer, n_hex, allow_test_key=False):
    """The key table the check takes, after the same tests the check makes."""
    issuer = (issuer or "").strip().lower()
    n_hex = (n_hex or "").strip().lower().lstrip("0")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", issuer):
        raise SystemExit("issuer must be a host name (lower case letters, digits, . and -): %r" % issuer)
    if not re.fullmatch(r"[89a-f][0-9a-f]{511}", n_hex):
        raise SystemExit("the key must be an RSA-2048 modulus: 512 hex digits, top bit set")
    if int(n_hex, 16) % 2 == 0:
        raise SystemExit("the modulus is even: not an RSA key")
    if n_hex in test_moduli() and not allow_test_key:
        raise SystemExit("this is a test-only key from fixtures/test_keys.json, whose private half is public:\n"
                         "anyone could sign licenses for it. Use the issuer's real key. (--allow-test-key\n"
                         "makes a test build, which must never ship.)")
    return {"issuer": issuer, "n": n_hex, "rr": rr_hex(n_hex)}


def baked_source(infile, key, no_debug):
    src = open(infile, encoding="utf-8").read()
    if src.count(BAKED_LINE) != 1 or src.count(NO_DEBUG_LINE) != 1:
        raise SystemExit("%s: expected one %r and one %r line" % (infile, BAKED_LINE, NO_DEBUG_LINE))
    lua_key = 'local BAKED = { issuer = "%s", n = "%s", rr = "%s" }\n' % (key["issuer"], key["n"], key["rr"])
    src = src.replace(BAKED_LINE, lua_key)
    if no_debug:
        src = src.replace(NO_DEBUG_LINE, "local NO_DEBUG = true\n")
    return src


def obfuscate(prometheus_dir, preset, infile, outfile, seed, drop_steps=""):
    import lupa.luajit21 as luajit
    driver = os.path.join(HERE, "run_prometheus.lua")
    L = luajit.LuaRuntime(unpack_returned_tuples=True)
    chunk = L.eval("loadfile")(driver)
    if chunk is None:
        raise SystemExit("cannot load run_prometheus.lua")
    # The driver prints its own "OK ..." line via io.write to this stdout.
    chunk(prometheus_dir.replace("\\", "/"), preset,
          infile.replace("\\", "/"), outfile.replace("\\", "/"),
          "" if seed is None else str(seed), drop_steps or "")


def verify(outfile, key, no_debug):
    """Load the build on PUC Lua 5.1 and test it."""
    import lupa.lua51 as puc

    keys = json.load(open(os.path.join(REPO, "fixtures", "test_keys.json")))
    fixture = {"issuer": "issuer.test", "n": keys["a"]["n"].lower()}
    fixture["rr"] = rr_hex(fixture["n"])
    ltext = open(os.path.join(REPO, "fixtures", "license_a.txt"), encoding="utf-8").read()
    ACCOUNT = "1a2b3c4d5e6f7081"   # listed in license_a's accounts
    NOW = 1900000000               # between issued and expires

    L = puc.LuaRuntime(unpack_returned_tuples=True)
    L.execute("python = nil; package.loaded.python = nil")
    if no_debug:
        L.execute("debug = nil")
    # an untouched game: peer_id is a C function (os.time stands in)
    L.execute("stingray = { Network = { peer_id = os.time } }")
    code = open(outfile, encoding="utf-8").read()
    r = L.eval("loadstring")(code, "license_check")
    fn = r[0] if isinstance(r, tuple) else r
    if fn is None:
        raise SystemExit("verify: the build does not load: " + str(r[1]))
    M = fn()
    L.globals().M = M
    L.globals().FIXTURE = L.table_from(fixture)
    L.globals().LTEXT = ltext

    def call(expr):
        res = L.eval("{" + expr + "}")
        return res[1], res[2]

    ok, _ = call("M.verify(LTEXT, FIXTURE, %d, '%s')" % (NOW, ACCOUNT))
    if not ok:
        raise SystemExit("verify: a valid fixture license did NOT verify")
    ok, why = call("M.verify(LTEXT, nil, %d, '%s')" % (NOW, ACCOUNT))
    want = "fields" if key["issuer"] == "issuer.test" and key["n"] == fixture["n"] else "issuer"
    got = "fields" if ok else why
    if got != want:
        raise SystemExit("verify: with the baked key the fixture gave %r, not %r" % (got, want))
    ok, why = call("M.check()")
    if not ok and why in ("tampered", "no_debug", "key"):
        raise SystemExit("verify: on an untouched game check() said %r" % why)
    print("verify: fixture license verified, key %s baked in, untouched game not tampered (%s)  OK"
          % (key["issuer"], "licensed" if ok else why))


def main():
    ap = argparse.ArgumentParser(description="Build one mod's license check.")
    ap.add_argument("--declaration", help="the mod's hd2_license.json: its issuer and key")
    ap.add_argument("--issuer", help="the issuer's host name (instead of --declaration)")
    ap.add_argument("--modulus", help="the RSA-2048 modulus n, hex (instead of --declaration)")
    ap.add_argument("--allow-test-key", action="store_true",
                    help="build with a test-only key from fixtures/ (tests only: never ship it)")
    ap.add_argument("--no-debug", action="store_true",
                    help="for a game whose Lua has no debug.getinfo (check() says no_debug)")
    ap.add_argument("--prometheus", default=os.environ.get("PROMETHEUS_DIR"),
                    help="Prometheus checkout (or set PROMETHEUS_DIR)")
    ap.add_argument("--preset", default="Medium",
                    help="Prometheus preset: Minify|Weak|Medium|Strong (default Medium)")
    ap.add_argument("--in", dest="infile",
                    default=os.path.join(REPO, "lua", "license_check.lua"))
    ap.add_argument("--out", dest="outfile",
                    default=os.path.join(REPO, "dist", "license_check.lua"))
    ap.add_argument("--seed", type=int, default=None,
                    help="fixed Prometheus seed (>0), for tests only: a release build is laid out afresh")
    ap.add_argument("--drop-step", action="append", default=[],
                    help="preset step to remove, e.g. AntiTamper (repeatable)")
    ap.add_argument("--no-verify", action="store_true", help="skip the PUC 5.1 tests")
    a = ap.parse_args()

    if a.declaration:
        d = json.load(open(a.declaration, encoding="utf-8"))
        if d.get("protocol") != 1:
            raise SystemExit("%s: protocol is not 1" % a.declaration)
        key = key_of(d.get("issuer"), d.get("key"), a.allow_test_key)
    elif a.issuer and a.modulus:
        key = key_of(a.issuer, a.modulus, a.allow_test_key)
    else:
        raise SystemExit("give --declaration hd2_license.json, or --issuer and --modulus")

    if not a.prometheus or not os.path.isdir(a.prometheus):
        raise SystemExit(
            "Prometheus checkout not found. Clone\n"
            "  https://github.com/prometheus-lua/Prometheus\n"
            "and pass --prometheus <dir> or set PROMETHEUS_DIR.")

    os.makedirs(os.path.dirname(os.path.abspath(a.outfile)), exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "license_check.lua")
        with open(src, "w", encoding="utf-8", newline="\n") as f:
            f.write(baked_source(a.infile, key, a.no_debug))
        obfuscate(a.prometheus, a.preset, src, a.outfile, a.seed, ",".join(a.drop_step))
    if not a.no_verify:
        verify(a.outfile, key, a.no_debug)
    print("wrote " + a.outfile)


if __name__ == "__main__":
    main()
