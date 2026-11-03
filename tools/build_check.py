"""Build the embedded, obfuscated license check from lua/license_check.lua.

Runs Prometheus (https://github.com/prometheus-lua/Prometheus) over the plain
source and writes the obfuscated artifact to dist/license_check.lua. By default
it then verifies the output on PUC Lua 5.1 (the game's VM) against a fixture
license, so a broken build fails here instead of in game.

Prometheus runs on LuaJIT / Lua 5.1; both backends come from the `lupa` package.
Point the build at a Prometheus checkout with --prometheus or the PROMETHEUS_DIR
environment variable (no path is baked in). The preset defaults to Medium. By
default Prometheus seeds its layout from the clock, so each build differs; pass
--seed N (N > 0) for a reproducible layout.

Usage (run from the repo root):
    python tools/build_check.py
    python tools/build_check.py --preset Weak
    PROMETHEUS_DIR=/path/to/Prometheus python tools/build_check.py
"""
import argparse
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


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


def verify(outfile):
    """Load the obfuscated artifact on PUC Lua 5.1 and verify a fixture license."""
    import json
    import lupa.lua51 as puc

    keys = json.load(open(os.path.join(REPO, "fixtures", "test_keys.json")))
    n_hex = keys["a"]["n"].lower()
    ltext = open(os.path.join(REPO, "fixtures", "license_a.txt"), encoding="utf-8").read()

    # R^2 mod n, in the module's limb base B = 2^26, k = ceil(nbits / 26)
    BITS = 26
    k = math.ceil(len(n_hex) * 4 / BITS)
    rr_hex = format(pow(2, 2 * BITS * k, int(n_hex, 16)), "x")
    if len(rr_hex) % 2:
        rr_hex = "0" + rr_hex

    ACCOUNT = "1a2b3c4d5e6f7081"   # listed in license_a's accounts
    NOW = 1900000000               # between issued and expires

    L = puc.LuaRuntime(unpack_returned_tuples=True)
    L.execute("python = nil; package.loaded.python = nil")
    code = open(outfile, encoding="utf-8").read()
    r = L.eval("loadstring")(code, "license_check")
    fn = r[0] if isinstance(r, tuple) else r
    if fn is None:
        raise SystemExit("verify: obfuscated output does not load: " + str(r[1]))
    M = fn()
    L.globals().M = M
    L.globals().KEY = L.table_from({"issuer": "issuer.test", "n": n_hex, "rr": rr_hex})
    L.globals().LTEXT = ltext
    ok = L.eval("M.verify(LTEXT, KEY, %d, '%s')" % (NOW, ACCOUNT))
    if not ok:
        raise SystemExit("verify: a valid fixture license did NOT verify")
    print("verify: fixture license verified on PUC Lua 5.1  OK")


def main():
    ap = argparse.ArgumentParser(description="Build the obfuscated license check.")
    ap.add_argument("--prometheus", default=os.environ.get("PROMETHEUS_DIR"),
                    help="Prometheus checkout (or set PROMETHEUS_DIR)")
    ap.add_argument("--preset", default="Medium",
                    help="Prometheus preset: Minify|Weak|Medium|Strong (default Medium)")
    ap.add_argument("--in", dest="infile",
                    default=os.path.join(REPO, "lua", "license_check.lua"))
    ap.add_argument("--out", dest="outfile",
                    default=os.path.join(REPO, "dist", "license_check.lua"))
    ap.add_argument("--seed", type=int, default=None,
                    help="fixed Prometheus seed (>0) for a reproducible layout")
    ap.add_argument("--drop-step", action="append", default=[],
                    help="preset step to remove, e.g. AntiTamper (repeatable)")
    ap.add_argument("--no-verify", action="store_true", help="skip the PUC 5.1 check")
    a = ap.parse_args()

    if not a.prometheus or not os.path.isdir(a.prometheus):
        raise SystemExit(
            "Prometheus checkout not found. Clone\n"
            "  https://github.com/prometheus-lua/Prometheus\n"
            "and pass --prometheus <dir> or set PROMETHEUS_DIR.")

    os.makedirs(os.path.dirname(a.outfile), exist_ok=True)
    obfuscate(a.prometheus, a.preset, a.infile, a.outfile, a.seed, ",".join(a.drop_step))
    if not a.no_verify:
        verify(a.outfile)
    print("wrote " + a.outfile)


if __name__ == "__main__":
    main()
