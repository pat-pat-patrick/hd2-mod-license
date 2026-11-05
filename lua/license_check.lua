-- HD2 Mod License: the check a mod runs, in plain Lua 5.1 (the game's VM
-- has no bit library and no ffi). See ../spec/protocol.zh-CN.md.
--
-- A mod does not ship this readable file. It ships a build made for it by
-- tools/build_check.py, with its issuer and key baked into the obfuscated code
-- (BAKED below), and calls check() once at load, keeping its own reference:
--
--   local check = LICENSE.check            -- right after loading the chunk
--   local ok, why = check()
--   if not ok then ... end      -- why: see below; "no_account": ask later
--
-- Unbaked (this file as it is, for tests) check(KEY) takes the key instead:
-- {issuer = <host>, n = <modulus hex>, rr = <R^2 mod n hex, R = 2^(26*k)>}.
--
-- The manager writes the license to
-- %APPDATA%\Arrowhead\Helldivers2\licenses\<issuer>.txt:
--
--   HD2 MOD LICENSE 1
--   issuer=<host>
--   accounts=<16 hex>[,<16 hex>]
--   issued=<unix time>
--   expires=<unix time>
--   holder=<who>
--   sig=<hex RSASSA-PKCS1-v1_5 SHA-256 over every byte before this line>
--
-- one such license per member who signed in on this computer, one after
-- another (two players sharing a computer each keep theirs); any may pass.
--
-- The account is Network.peer_id(), the id the game names the player's save
-- file after (saves\<id>_user_settings.config).
--
-- M.check([key]) -> true, fields | false, reason
--   reasons: "missing", "malformed", "issuer", "signature", "expired",
--            "clock" (the computer's clock is before the license was issued),
--            "account", "key" (the key is not an RSA-2048 key),
--            "tampered" (a function the check reads the game through has been
--            replaced by script), "no_debug" (the game's Lua has no
--            debug.getinfo: build with --no-debug), "no_account" (peer id
--            not known yet: ask again later)

-- The key, baked in by tools/build_check.py; nil in the readable source.
local BAKED = nil
-- true (build_check.py --no-debug) for a game whose Lua has no debug library:
-- the check then cannot see through C-function fakes (see native below).
local NO_DEBUG = false

-- Everything the check calls, taken once as the chunk loads: a script that
-- replaces a library function after that does not reach the check, and no
-- string method is looked up through the strings' shared metatable.
local type, tostring, tonumber, pcall, rawget, setmetatable =
  type, tostring, tonumber, pcall, rawget, setmetatable
local floor, ceil = math.floor, math.ceil
local byte, char, sub, rep, format, find, match, gmatch, gsub, lower =
  string.byte, string.char, string.sub, string.rep, string.format,
  string.find, string.match, string.gmatch, string.gsub, string.lower
local concat = table.concat
local os_time, os_getenv, io_open, io_read, io_type = os.time, os.getenv, io.open, io.read, io.type
local G = _G
local dbg = rawget(G, "debug")
local getinfo = type(dbg) == "table" and dbg.getinfo or nil
local getupvalue = type(dbg) == "table" and dbg.getupvalue or nil
local dump = string.dump
local co = rawget(G, "coroutine")
local co_wrap = type(co) == "table" and co.wrap or nil

local M = {}

-- -------------------------------------------------------------- 32-bit ops
-- Words are numbers in [0, 2^32). XOR and AND go a nibble at a time.

local XOR, AND = {}, {}
for a = 0, 15 do
  for b = 0, 15 do
    local x, y, r, s, p = a, b, 0, 0, 1
    for _ = 1, 4 do
      local i, j = x % 2, y % 2
      if i ~= j then r = r + p end
      if i == 1 and j == 1 then s = s + p end
      x, y, p = (x - i) / 2, (y - j) / 2, p * 2
    end
    XOR[a * 16 + b], AND[a * 16 + b] = r, s
  end
end

local function bop(t, a, b)
  local r, p = 0, 1
  for _ = 1, 8 do
    local x, y = a % 16, b % 16
    r = r + t[x * 16 + y] * p
    a, b, p = (a - x) / 16, (b - y) / 16, p * 16
  end
  return r
end

local function bxor(a, b) return bop(XOR, a, b) end
local function band(a, b) return bop(AND, a, b) end
local function rotr(x, n)
  local lo = x % 2 ^ n
  return (x - lo) / 2 ^ n + lo * 2 ^ (32 - n)
end
local function shr(x, n) return floor(x / 2 ^ n) end

-- ----------------------------------------------------------------- SHA-256

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function sha256(msg)
  local len = #msg
  local bits = len * 8
  msg = msg .. "\128" .. rep("\0", (55 - len) % 64)
  local tail = {}
  for i = 7, 0, -1 do tail[#tail + 1] = char(floor(bits / 2 ^ (i * 8)) % 256) end
  msg = msg .. concat(tail)

  local h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
  local w = {}
  for at = 1, #msg, 64 do
    for i = 0, 15 do
      local b1, b2, b3, b4 = byte(msg, at + i * 4, at + i * 4 + 3)
      w[i] = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
    end
    for i = 16, 63 do
      local a, b = w[i - 15], w[i - 2]
      local s0 = bxor(bxor(rotr(a, 7), rotr(a, 18)), shr(a, 3))
      local s1 = bxor(bxor(rotr(b, 17), rotr(b, 19)), shr(b, 10))
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % 4294967296
    end
    local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
    for i = 0, 63 do
      local S1 = bxor(bxor(rotr(e, 6), rotr(e, 11)), rotr(e, 25))
      local ch = bxor(band(e, f), band(4294967295 - e, g))
      local t1 = (hh + S1 + ch + K[i + 1] + w[i]) % 4294967296
      local S0 = bxor(bxor(rotr(a, 2), rotr(a, 13)), rotr(a, 22))
      local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
      local t2 = (S0 + maj) % 4294967296
      hh, g, f, e, d, c, b, a = g, f, e, (d + t1) % 4294967296, c, b, a, (t1 + t2) % 4294967296
    end
    h[1], h[2], h[3], h[4] = (h[1] + a) % 4294967296, (h[2] + b) % 4294967296, (h[3] + c) % 4294967296, (h[4] + d) % 4294967296
    h[5], h[6], h[7], h[8] = (h[5] + e) % 4294967296, (h[6] + f) % 4294967296, (h[7] + g) % 4294967296, (h[8] + hh) % 4294967296
  end
  local out = {}
  for i = 1, 8 do out[i] = format("%08x", h[i]) end
  return concat(out)
end
M.sha256 = sha256

-- ---------------------------------------------------------------- big numbers
-- Little-endian arrays of 26-bit limbs, 1-based. 26 bits keeps every
-- product plus carries under 2^53, where doubles stay exact.

local BITS = 26
local B = 2 ^ BITS

local function from_hex(hex, limbs)
  local t = {}
  for i = 1, limbs do t[i] = 0 end
  local pos = 0
  for i = #hex, 1, -1 do
    local v = tonumber(sub(hex, i, i), 16)
    if not v then return nil end
    local li, off = floor(pos / BITS) + 1, pos % BITS
    if off + 4 <= BITS then
      if li <= limbs then t[li] = t[li] + v * 2 ^ off end
    else
      local room = 2 ^ (BITS - off)
      local lo = v % room
      if li <= limbs then t[li] = t[li] + lo * 2 ^ off end
      if li + 1 <= limbs then t[li + 1] = t[li + 1] + (v - lo) / room
      elseif v ~= lo then return nil end
    end
    if li > limbs and v ~= 0 then return nil end
    pos = pos + 4
  end
  return t
end

local function less(a, b, k)
  for i = k, 1, -1 do
    if a[i] ~= b[i] then return a[i] < b[i] end
  end
  return false
end

-- a * b / R mod n (Montgomery, CIOS), with np = -n^-1 mod B.
local function montmul(a, b, n, np, k)
  local t = {}
  for i = 1, k + 2 do t[i] = 0 end
  for i = 1, k do
    local ai, carry = a[i], 0
    for j = 1, k do
      local s = t[j] + ai * b[j] + carry
      carry = floor(s / B)
      t[j] = s - carry * B
    end
    local s = t[k + 1] + carry
    carry = floor(s / B)
    t[k + 1] = s - carry * B
    t[k + 2] = t[k + 2] + carry

    local m = (t[1] * np) % B
    carry = floor((t[1] + m * n[1]) / B)
    for j = 2, k do
      s = t[j] + m * n[j] + carry
      carry = floor(s / B)
      t[j - 1] = s - carry * B
    end
    s = t[k + 1] + carry
    carry = floor(s / B)
    t[k] = s - carry * B
    t[k + 1] = t[k + 2] + carry
    t[k + 2] = 0
  end
  if t[k + 1] > 0 or not less(t, n, k) then
    local borrow = 0
    for j = 1, k do
      local s = t[j] - n[j] - borrow
      if s < 0 then s, borrow = s + B, 1 else borrow = 0 end
      t[j] = s
    end
  end
  t[k + 1], t[k + 2] = nil, nil
  return t
end

-- Prepared once per key: limbs of n and R^2 mod n, and np. Only an RSA-2048
-- key is taken (512 hex digits, top bit set), as the specification says: a
-- smaller modulus could be factored, so a key that is not one is refused.
local prepared = setmetatable({}, { __mode = "k" })
local function prepare(key)
  if type(key) ~= "table" then return nil end
  local p = prepared[key]
  if p then return p end
  local n_hex, rr_hex = key.n, key.rr
  if type(n_hex) ~= "string" or type(rr_hex) ~= "string" then return nil end
  n_hex = lower(n_hex)
  if #n_hex ~= 512 or not match(n_hex, "^[89a-f]%x+$") or not match(rr_hex, "^%x+$") then return nil end
  local k = ceil(#n_hex * 4 / BITS)
  local n, rr = from_hex(n_hex, k), from_hex(rr_hex, k)
  if not n or not rr or n[1] % 2 == 0 or not less(rr, n, k) then return nil end
  local x, n0 = 1, n[1]
  for _ = 1, 5 do                       -- Newton: inverse of n0 mod 2^26
    x = (x * ((2 - (n0 * x) % B) % B)) % B
  end
  p = { k = k, n = n, rr = rr, np = (B - x) % B, bytes = #n_hex / 2 }
  prepared[key] = p
  return p
end

-- sig^65537 mod n compared with the PKCS#1 v1.5 encoding of the SHA-256.
local DIGEST_INFO = "3031300d060960864801650304020105000420"
local function verify_signature(message, sig_hex, key)
  local p = prepare(key)
  if not p then return false end
  if #sig_hex ~= p.bytes * 2 then return false end
  local s = from_hex(sig_hex, p.k)
  if not s or not less(s, p.n, p.k) then return false end
  local one = { 1 }
  for i = 2, p.k do one[i] = 0 end
  local a = montmul(s, p.rr, p.n, p.np, p.k)
  local x = a
  for _ = 1, 16 do x = montmul(x, x, p.n, p.np, p.k) end
  x = montmul(montmul(x, a, p.n, p.np, p.k), one, p.n, p.np, p.k)

  local pad = p.bytes - 3 - #DIGEST_INFO / 2 - 32
  local want = from_hex("0001" .. rep("ff", pad) .. "00" .. DIGEST_INFO .. sha256(message), p.k)
  for i = 1, p.k do
    if x[i] ~= want[i] then return false end
  end
  return true
end
M.verify_signature = verify_signature

-- ------------------------------------------------------------------ license

-- A clock this far behind a license's issue time is still taken: a computer
-- whose clock is off by some hours should not lose a license just issued.
local CLOCK_SLACK = 86400

-- text -> fields | nil, reason. now: unix time; account: 16 hex or nil.
-- One license. The cheap tests come first, so the signature (the 9 ms) is
-- checked only for a license that names this account and has not run out.
local function one(text, key, now, account)
  local at = find(text, "\nsig=", 1, true)
  if not at then return nil, "malformed" end
  local signed = sub(text, 1, at)
  local sig = match(sub(text, at + 5), "^(%x+)\n?$")
  if not sig then return nil, "malformed" end
  local fields = {}
  for k, v in gmatch(signed, "\n([%w_]+)=([^\n]*)") do fields[k] = v end
  local expires, issued = tonumber(fields.expires), tonumber(fields.issued)
  if not fields.accounts or not expires or not issued or not fields.issuer then return nil, "malformed" end
  if fields.issuer ~= key.issuer then return nil, "issuer" end
  if account then
    local found = false
    for a in gmatch(fields.accounts, "[^,]+") do
      if a == account then found = true end
    end
    if not found then return nil, "account" end
  end
  if now then
    if not (now < expires) then return nil, "expired" end
    if not (now >= issued - CLOCK_SLACK) then return nil, "clock" end
  end
  if not verify_signature(signed, lower(sig), key) then return nil, "signature" end
  return fields
end

-- How near a license came to passing: the reason given when none passes.
local NEAR = { malformed = 1, issuer = 2, account = 3, expired = 4, clock = 5, signature = 6 }

-- text -> fields | nil, reason. The file holds one license per member who
-- signed in on this computer, one after another; any of them may pass.
-- key: the baked key when nil (a build's own tests pass a fixture key).
local function verify(text, key, now, account)
  key = key or BAKED
  if not prepare(key) or type(key.issuer) ~= "string" then return nil, "key" end
  if type(text) ~= "string" then return nil, "malformed" end
  text = gsub(text, "\r", "")
  local header = "HD2 MOD LICENSE 1\n"
  local reason = nil
  local at = 1
  while true do
    local s = find(text, header, at, true)
    if not s or (s ~= 1 and sub(text, s - 1, s - 1) ~= "\n") then
      if s then at = s + 1 else break end
    else
      local e = find(text, "\n" .. header, s, true)
      local fields, why = one(sub(text, s, e or #text), key, now, account)
      if fields then return fields end
      if reason == nil or NEAR[why] > NEAR[reason] then reason = why end
      if not e then break end
      at = e + 1
    end
  end
  return nil, reason or "malformed"
end
M.verify = verify

-- ------------------------------------------------------------- the game side

-- True when f is a function of the game or of Lua itself (C), and not one a
-- script made: not Lua code, nor a C function wrapped around script values
-- (coroutine.wrap holds a thread, string.gmatch a string, io.lines a file).
-- source: the function stands for something the game tells the check (the
-- account, the time, the license file), so a returner of fixed values that
-- holds a string, a function or a file is refused too, as is io.read.
-- Where the VM cannot show a C function's upvalues (PUC 5.1), one that has
-- any is refused: the library functions and the game's bindings have none.
-- Without debug.getinfo (a --no-debug build) string.dump tells Lua code from
-- C, and nothing more; with neither, nothing can be told: true. string.dump
-- is not called when getinfo is there, so no error is raised and caught.
local function probe() end
local see_c_upvalues = nil
local function native(f, source)
  if type(f) ~= "function" then return false end
  if getinfo then
    local ok, info = pcall(getinfo, f, "Su")
    if not ok or type(info) ~= "table" or info.what ~= "C" then return false end
    local nups = tonumber(info.nups) or 0
    if nups > 0 then
      if not see_c_upvalues then return false end
      for i = 1, nups do
        local got, name, v = pcall(getupvalue, f, i)
        if not got or name == nil then return false end
        local t = type(v)
        if t == "thread" then return false end
        if source and (t == "string" or t == "function" or (t == "userdata" and io_type and io_type(v))) then return false end
      end
    end
  elseif dump and pcall(dump, f) then           -- only Lua functions dump
    return false
  end
  if source and f == io_read then return false end
  return true
end

-- The tools native() uses must tell the truth about a function known to be
-- Lua (probe) and be the game's own themselves.
local function tools_honest()
  if getinfo then
    local ok, info = pcall(getinfo, probe, "S")
    if not ok or type(info) ~= "table" or info.what ~= "Lua" then return false end
    -- can this VM show a C function's upvalues? coroutine.wrap makes one with a thread
    see_c_upvalues = false
    if getupvalue and native(getupvalue) and co_wrap and native(co_wrap) then
      local got, name, v = pcall(getupvalue, co_wrap(probe), 1)
      see_c_upvalues = got and name ~= nil and type(v) == "thread"
    end
  end
  if dump and not getinfo and not pcall(dump, probe) then return false end
  local tools = { getinfo or false, dump or false, getupvalue or false }
  for i = 1, 3 do
    if tools[i] and not native(tools[i]) then return false end
  end
  local used = { type, tostring, tonumber, pcall, rawget, setmetatable, floor, ceil,
                 byte, char, sub, rep, format, find, match, gmatch, gsub, lower, concat,
                 io_read, io_type }
  for i = 1, 21 do
    if not native(used[i]) then return false end
  end
  return native(os_time, true) and native(os_getenv, true) and native(io_open, true)
end

local function license_path(issuer)
  if type(issuer) ~= "string" or not match(issuer, "^[%w][%w%.%-]*$") then return nil end
  local ok, dir = pcall(os_getenv, "APPDATA")
  if not ok or type(dir) ~= "string" then return nil end
  return dir .. "\\Arrowhead\\Helldivers2\\licenses\\" .. issuer .. ".txt"
end

-- The game's peer id as 16 hex digits; nil while the game has none. false
-- when the function it comes from has been replaced. An id with fewer than 8
-- significant hex digits (0, a placeholder) is not an account.
local function own_account()
  local st = rawget(G, "stingray")
  local net = type(st) == "table" and rawget(st, "Network") or nil
  if type(net) ~= "table" or rawget(net, "peer_id") == nil then net = rawget(G, "Network") end
  if type(net) ~= "table" then return nil end
  local f = rawget(net, "peer_id")
  if f == nil then return nil end
  if not native(f, true) then return false end
  local ok, id = pcall(f)
  if not ok or id == nil then return nil end
  id = lower(tostring(id))
  if #id > 16 or not match(id, "^%x+$") then return nil end
  id = rep("0", 16 - #id) .. id
  if sub(id, 1, 8) == "00000000" then return nil end
  return id
end

function M.check(key)
  key = BAKED or key
  if not prepare(key) or type(key.issuer) ~= "string" then return false, "key" end
  if not getinfo and not NO_DEBUG then return false, "no_debug" end
  if not tools_honest() then return false, "tampered" end
  local account = own_account()
  if account == false then return false, "tampered" end
  if not account then return false, "no_account" end
  local now = os_time()
  if type(now) ~= "number" then return false, "tampered" end
  local path = license_path(key.issuer)
  local f = path and io_open(path, "rb")
  if not f then return false, "missing" end
  local text = f:read("*a")
  f:close()
  local fields, why = verify(text, key, now, account)
  if not fields then return false, why end
  return true, fields
end

return M
