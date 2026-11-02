# HD2 Mod License

Membership licenses for Helldivers 2 Lua mods. A player signs in to the mod author's own issuer from HD2 Mod Quick Deploy and receives a signed license; the mod checks it offline when it loads. Nothing goes over the network while the game runs.

**Status: draft 1 (2026-11-02).** The specification is written in Chinese; an English translation will follow.

## How it works

- The mod package declares its issuer and public key in `hd2_license.json`.
- The player signs in to that issuer from the manager. The issuer checks the membership and signs a license that names the player's game account.
- The manager writes the license to `%APPDATA%\Arrowhead\Helldivers2\licenses\<issuer>.txt` and renews it before it expires.
- At load the mod runs `license_check.lua` once: signature (RSA-2048, SHA-256), issuer, expiry, and whether `Network.peer_id()` is one of the licensed accounts. It costs about 10 ms on the game's Lua 5.1.

Each author runs their own issuer with their own key. The manager works with any issuer that answers the three endpoints in the specification.

## What it does not do

The signature stops anyone from forging a license. It does not stop someone from editing a mod's Lua and removing the check. What it stops is copying a licensed mod's files to someone else.

## Contents

| Path | Contents |
|---|---|
| [spec/protocol.zh-CN.md](spec/protocol.zh-CN.md) | The protocol: the mod's declaration, account ids, issuer endpoints, license file, what the manager and the mod do |
| [lua/license_check.lua](lua/license_check.lua) | The check a mod embeds: plain Lua 5.1, no bit library, no ffi |
| [worker/](worker/) | An issuer for Cloudflare Workers, with Patreon as the members' list |
| [fixtures/](fixtures/) | Test-only keys and licenses; they sign nothing real |

## Running an issuer

The Worker uses only Cloudflare's free plan (Workers and KV).

1. `node worker/make_key.mjs` makes your signing key in `%USERPROFILE%\hd2_license_keys`. Keep the private key out of every repository.
2. Register a client in Patreon's developer portal, with the redirect URI `https://<your issuer>/callback`.
3. Copy `worker/wrangler.example.toml` to `worker/wrangler.toml` and fill it in.
4. In `worker/`, run:
   - `npx wrangler login`
   - `npx wrangler kv namespace create LICENSES`, and put the id into `wrangler.toml`
   - `npx wrangler secret put PATREON_CLIENT_SECRET`
   - `npx wrangler secret put SIGNING_KEY`, and paste `signing_key.private.txt`
   - `npx wrangler secret put ADMIN_TOKEN`
   - `npx wrangler deploy`
5. `node worker/lua_key.mjs <signing_key.public.txt> <your issuer> "<your name>"` prints the key for your mod's Lua and the `hd2_license.json` for its package.

Use your own domain: `*.workers.dev` cannot be reached from mainland China.

### Admin requests

Send them with the header `Authorization: Bearer <ADMIN_TOKEN>`.

- `POST /admin/issue {"accounts": ["<id>"], "days": 365, "holder": "<name>"}` issues a license by hand, for example to a player without Patreon. The longest allowed is 3650 days.
- `POST /admin/unbind {"holder": "p:<Patreon user id>"}` clears a member's bound accounts, so they can sign in from another game account.

## Tests

`node worker/test.mjs` runs the issuer's flows against an in-memory KV and a fake Patreon. `node worker/make_fixtures.mjs` replaces the fixtures.

## License

MIT
