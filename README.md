# HD2 Mod License

Membership licenses for Helldivers 2 Lua mods. A player signs in to the mod author's own issuer from HD2 Mod Quick Deploy and receives a signed license; the mod checks it offline when it loads. Nothing goes over the network while the game runs.

**Status: draft 1 (2026-11-02).** The specification is written in Chinese; an English translation will follow.

## How it works

- The mod package declares its issuer and public key in `hd2_license.json`.
- The player signs in to that issuer from the manager. The issuer checks the membership and signs a license that names the player's game account. The browser comes back to the computer that started the sign-in (a loopback redirect with PKCE, RFC 8252), and only the manager there can collect the license. A sign-in link made by someone else and opened by a member therefore leads nowhere.
- The manager writes the license to `%APPDATA%\Arrowhead\Helldivers2\licenses\<issuer>.txt` and renews it before it expires.
- At load the mod runs its build of `license_check.lua` once: signature (RSA-2048, SHA-256), issuer, expiry, and whether `Network.peer_id()` is one of the licensed accounts. It costs about 10 ms on the game's Lua 5.1.

Each creator's licenses come from an issuer that signs with that creator's own key. The manager works with any issuer that answers the three endpoints in the specification. This repository holds no issuer.

## What it does not do

The signature stops anyone from forging a license. It does not stop someone from editing a mod's Lua and removing the check. What it stops is copying a licensed mod's files to someone else.

The check runs in the game's shared Lua state, so it also refuses to trust what another script could have replaced there. It takes the library functions it uses as it loads. When it runs, it requires `peer_id`, `os.time`, `os.getenv`, `io.open` and its own tools to be the game's C functions. That rules out Lua code, and C functions wrapped around script values such as `coroutine.wrap`, `string.gmatch`, `io.lines` and `io.read`. Otherwise it answers `tampered`. This stops a script that replaces one function to fake the account id or the time. It stops nothing more. A script of about ten lines that loads before the mod can replace `debug.getinfo` with one that calls both a fake `peer_id` and itself C functions, then fake `peer_id`, and a copied license passes (reproduced on PUC 5.1, 2026-11-05). That script is not specific to any mod: it works against every mod's build alike. So does a script that controls how the mod's chunk is loaded (its environment, `loadstring`). A check that runs in the mod's own Lua cannot close this, because a script loaded earlier can change everything the check can see. The protection that counts is obfuscation and a separate build for every mod: removing or changing the check has to be done one mod at a time.

## Contents

| Path | Contents |
|---|---|
| [spec/protocol.zh-CN.md](spec/protocol.zh-CN.md) | The protocol: the mod's declaration, account ids, issuer endpoints, license file, what the manager and the mod do |
| [spec/static-resources.zh-CN.md](spec/static-resources.zh-CN.md) | Protocol extension (draft): protecting and tracing static-resource mods (textures, models, audio) that carry no Lua — per-account sealed delivery and a forensic watermark |
| [lua/license_check.lua](lua/license_check.lua) | The check, in readable form: plain Lua 5.1, no bit library, no ffi |
| [tools/](tools/) | `build_check.py` builds one mod's check: its key baked in, obfuscated; `test_check.py` tests the check |
| [plugin/](plugin/) | `HD2QD.License.dll`, the manager's side: a plugin of HD2 Mod Quick Deploy that signs the player in, writes and renews the license, and marks the mods that need one (`plugin\build.bat`) |
| [fixtures/](fixtures/) | Test-only keys and licenses; they sign nothing real. Their private keys are public: the build refuses them, and so does the issuer |

## Building a mod's check

`lua/license_check.lua` is the readable source. A mod never ships it, and no two
mods ship the same build. `tools/build_check.py` makes a build for one mod:

- It bakes the mod's issuer and key into the source, so the check takes no key from
  the mod and none sits in plain Lua next to it.
- It runs [Prometheus](https://github.com/prometheus-lua/Prometheus) over the source.
  The layout is fresh each time, so no patch made for one mod's file fits another's.
- It loads the result on PUC Lua 5.1 (the game's VM). There it confirms that a fixture
  license still verifies, that the baked key is the one asked for, and that an untouched
  game is not taken as tampered. A broken build fails here, not in game.

```bash
PROMETHEUS_DIR=/path/to/Prometheus python tools/build_check.py --declaration path/to/mod/hd2_license.json --drop-step AntiTamper --out path/to/mod/license_check.lua
```

The mod loads that file once and keeps its own reference to `check`, so a later
script cannot swap it in a shared table:

```lua
local check = LICENSE.check     -- LICENSE: what the built file returns
local ok, why = check()         -- once, at load
```

- `--declaration` reads the issuer and key from the mod's `hd2_license.json`; or
  give `--issuer` and `--modulus`. Only an RSA-2048 key is taken. A test-only key from
  `fixtures/` is refused: its private half is in this repository, so anyone could sign
  licenses for it. `--allow-test-key` builds one anyway, for tests; such a build must never ship.
- Clone Prometheus anywhere and point at it with `--prometheus <dir>` or
  `PROMETHEUS_DIR`. The build needs the `lupa` Python package (LuaJIT + Lua 5.1).
- `--preset` is `Medium` by default (register VM, string encryption; about +0.8 s
  one-time load on the game's Lua, zero per-frame cost because the check runs once
  at load). `Weak` is lighter (+40 ms, no VM); `Strong` is heavier and not worth
  its startup cost here.
- **`--drop-step AntiTamper` is required for a mod that ships through the hd2fake
  gate.** Medium's AntiTamper step deliberately performs `number - "string"`
  arithmetic inside `pcall` to fingerprint the error message; the gate reads those
  by-design swallowed errors as a mod hiding faults and refuses the build. The
  check still verifies with AntiTamper in place, but dropping it is cheap here:
  AntiTamper guards against live debuggers and beautifiers, not against someone
  deleting the check, which is already out of scope. Dropping it keeps the register
  VM and string encryption — the parts that hide the key and the logic. The check
  itself raises no error inside `pcall` when the game has `debug.getinfo`.
- **Try every new build once in the game, untouched.** If `check()` answers
  `tampered` there, the game provides one of the functions above in a form the check
  does not expect. If it answers `no_debug`, the game's Lua has no `debug.getinfo`:
  rebuild with `--no-debug`. Such a build then tells only Lua code from C functions.
- `--seed N` is for tests only. A release build is laid out afresh.

`dist/` is where a build goes by default; it is not committed.

Prometheus is not public-domain. Its license requires that a product which embeds
its output credit it. So **a mod that ships a build of the check must carry
this line** somewhere reasonably prominent — the mod's README, its in-manager
description, or an About/Credits screen:

> Based on Prometheus by Elias Oelschner, https://github.com/prometheus-lua/Prometheus

## Tests

`plugin\build.bat` runs the plugin's tests. `python tools/test_check.py` tests the
Lua check on PUC Lua 5.1 and LuaJIT (it needs `lupa` and `cryptography`); with
`--chunk <build>` it tests a build instead. The fixtures are test-only keys and licenses made by the issuer's tooling; they sign nothing real.

## License

MIT
