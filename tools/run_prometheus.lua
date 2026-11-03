-- Obfuscate one Lua file with Prometheus. Driven from build_check.py under a
-- LuaJIT / Lua 5.1 runtime: Prometheus itself needs LuaJIT or Lua 5.1 to run,
-- and its output is plain Lua 5.1 that the game's VM loads.
--
-- Based on Prometheus by Elias Oelschner, https://github.com/prometheus-lua/Prometheus
--
-- args: <prometheus_src_dir> <preset> <input.lua> <output.lua> [seed] [drop_steps]
-- A seed > 0 makes the layout reproducible; otherwise Prometheus seeds from the
-- clock and every build differs. drop_steps is a comma-separated list of step
-- names to remove from the preset (e.g. "AntiTamper").
local src_dir, preset, infile, outfile, seed, drop_steps = ...
arg = arg or {}   -- Prometheus config.lua iterates the global arg table
-- The prometheus module lives under <checkout>/src; accept either the checkout
-- root or the src dir.
package.path = table.concat({
	src_dir .. "/src/?.lua",
	src_dir .. "/src/?/init.lua",
	src_dir .. "/?.lua",
	src_dir .. "/?/init.lua",
	package.path,
}, ";")

local Prometheus = require("prometheus")
Prometheus.Logger.logLevel = Prometheus.Logger.LogLevel.Error  -- quiet

local f = assert(io.open(infile, "r"))
local code = f:read("*a"); f:close()

local cfg = Prometheus.Presets[preset]
assert(cfg, "unknown preset: " .. tostring(preset))
seed = tonumber(seed)
if seed and seed > 0 then
	cfg.Seed = seed
end
if drop_steps and #drop_steps > 0 then
	local drop = {}
	for name in drop_steps:gmatch("[^,]+") do drop[name] = true end
	local kept = {}
	for _, step in ipairs(cfg.Steps) do
		if not drop[step.Name] then kept[#kept + 1] = step end
	end
	cfg.Steps = kept
end
local pipeline = Prometheus.Pipeline:fromConfig(cfg)
local t0 = os.clock()
local out = pipeline:apply(code, infile)
local dt = os.clock() - t0

-- The Generated Output Exception (Prometheus LICENSE section 4) does not require
-- this header on the artifact; it only keeps the file traceable. The binding
-- attribution lives in the repo README (LICENSE section 2d).
local header = "-- Obfuscated with Prometheus by Elias Oelschner, "
	.. "https://github.com/prometheus-lua/Prometheus\n"

local o = assert(io.open(outfile, "w"))
o:write(header); o:write(out); o:close()
io.write(string.format("OK preset=%s in=%d out=%d time=%.2fs\n", preset, #code, #out, dt))
