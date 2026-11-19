using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Hd2Qd.License
{
    /// <summary>(1.6.0) Per-account segments (spec sections 4 to 6 of
    /// CONTRACT_sealed_lua). A mod whose hd2_license.json has "segments": {id, count, version} ships only
    /// a shell; its Lua comes from the issuer, one variant per segment for each game account.
    /// This claims them (POST /segments with a member's renew token), checks the signed receipt
    /// against the key the mod declares and the texts it covers, and only then writes
    /// licenses\&lt;issuer&gt;\segments\&lt;id&gt;\&lt;version&gt;\seg1.lua..segN.lua + receipt.txt, as one folder
    /// moved into place, so the shell never reads half a set or two accounts' halves.
    ///
    /// The folder holds one account's set (the shell reads no account): the most recently
    /// played account here that a member signed in here has bound. Versions no mod in the
    /// library uses any more are removed, for ids a library mod still declares. Each claim is
    /// written to this plugin's own payload.log (in the manager's settings folder, under
    /// license\), never to the manager's problem reports.</summary>
    public static partial class Plugin
    {
        const string SegmentsHeader = "HD2 MOD SEGMENTS 1\n";
        const string SegmentsHeader2 = "HD2 MOD SEGMENTS 2\n";   // (1.7.0, C1) a sealed version's receipt
        static readonly Regex PayloadId = new Regex("^[a-z0-9][a-z0-9._-]{0,63}$");
        static readonly Regex VersionTag = new Regex(@"(?<![\w.])v\d+(?:\.\d+)+(?![\w.])");
        static readonly Regex WholeVersion = new Regex(@"^v\d+(?:\.\d+)+\z");   // \z: "$" would let a trailing newline through
        static readonly Regex OwnFolder = new Regex(@"^(?:v\d+(?:\.\d+)+|\.v\d+(?:\.\d+)+\.(?:new|old)-[0-9a-f]{8})$");
        /// <summary>One claim or clean at a time in this process (the start, a row, a command).</summary>
        static readonly object segmentsLock = new object();

        /// <summary>{id, count, version} for a mod that declares segments, null for one that does
        /// not, {error} for a declaration or manifest that cannot be read.</summary>
        public static Dictionary<string, object> SegmentsOf(string modFolder)
        {
            Dictionary<string, object> d;
            try
            {
                var path = Path.Combine(modFolder, FileName);
                if (!File.Exists(path)) return null;
                d = Json.Parse(File.ReadAllText(path)) as Dictionary<string, object>;
            }
            catch (Exception e) when (e is FormatException || e is IOException || e is UnauthorizedAccessException) { return null; }
            var s = Json.Obj(d, "segments");
            if (s == null) return null;
            var id = Json.Str(s, "id");
            long count = Json.Long(s, "count");
            if (id == null || !PayloadId.IsMatch(id) || count < 1 || count > 64) return Err("bad_declaration");
            // (1.7.0, C1, CONTRACT section 12.2) "sealed": 1 -> the segments live as ciphertext and
            // are decrypted per game session (Session.cs). No "sealed" -> the plaintext path (1.6.0).
            bool sealedV = Json.Long(s, "sealed") == 1;
            // the version the shell was built for: "segments".version when the mod declares it (a
            // published package's Name carries no version), else the last vX.Y.Z in the Name. A
            // declared version must be a whole tag: it names a folder on disk.
            if (s.ContainsKey("version"))
            {
                var declared = Json.Str(s, "version");
                if (declared == null || !WholeVersion.IsMatch(declared)) return Err("bad_declaration");
                return new Dictionary<string, object> { ["id"] = id, ["count"] = count, ["version"] = declared, ["sealed"] = sealedV };
            }
            string name = null;
            try
            {
                var m = Path.Combine(modFolder, "manifest.json");
                if (File.Exists(m)) name = Json.Str(Json.Parse(File.ReadAllText(m)) as Dictionary<string, object>, "Name");
            }
            catch (Exception e) when (e is FormatException || e is IOException || e is UnauthorizedAccessException) { }
            var tags = name == null ? null : VersionTag.Matches(name);
            if (tags == null || tags.Count == 0) return Err("no_version");
            return new Dictionary<string, object> { ["id"] = id, ["count"] = count, ["version"] = tags[tags.Count - 1].Value, ["sealed"] = sealedV };
        }

        static string SegmentsRoot(string appData, string issuer, string id) =>
            Path.Combine(LicenseDir(appData), issuer.Replace(':', '_'), "segments", id);

        /// <summary>The folder the shell reads one version from.</summary>
        public static string SegmentsFolder(string appData, string issuer, string id, string version) =>
            Path.Combine(SegmentsRoot(appData, issuer, id), version);

        /// <summary>The fields of a receipt signed by key for issuer, else null (a license's rules:
        /// CR dropped, RSASSA-PKCS1-v1_5 SHA-256 over every byte before "sig=").</summary>
        static Dictionary<string, string> VerifyReceipt(string text, string issuer, string key)
        {
            text = text.Replace("\r", "");
            int at = text.IndexOf("\nsig=", StringComparison.Ordinal);
            if ((!text.StartsWith(SegmentsHeader, StringComparison.Ordinal) && !text.StartsWith(SegmentsHeader2, StringComparison.Ordinal)) || at < 0) return null;
            string signed = text.Substring(0, at + 1), sig = text.Substring(at + 5).Trim();
            var f = Fields(signed);
            if (!f.TryGetValue("issuer", out var iss) || iss != issuer) return null;
            var modulus = Bytes(key);
            if (!Regex.IsMatch(sig, "^[0-9a-fA-F]+$") || sig.Length != modulus.Length * 2) return null;
            using (var rsa = new RSACng())
            {
                rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = new byte[] { 1, 0, 1 } });
                if (!rsa.VerifyData(Encoding.UTF8.GetBytes(signed), Bytes(sig), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return null;
            }
            return f;
        }

        static string Utf8Sha256(string text)
        {
            using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(text)));
        }

        /// <summary>Whether this computer holds a good set for the version: every segN and a
        /// receipt signed by key for this id, version and the texts on disk. The account in it
        /// is returned (null when the set is missing or not good).</summary>
        public static string HeldAccount(string appData, Dictionary<string, object> decl, Dictionary<string, object> seg)
        {
            string issuer = Json.Str(decl, "issuer"), id = Json.Str(seg, "id"), version = Json.Str(seg, "version"), key = Json.Str(decl, "key");
            var dir = SegmentsFolder(appData, issuer, id, version);
            long count = Json.Long(seg, "count");
            // (1.7.0, C1) a sealed version keeps the ciphertext (seg<i>.enc) resident; the receipt's
            // sealed_hash covers it, so a held set can be checked offline, without the content key.
            // The plaintext seg<i>.lua appears only while the game runs (Session.cs).
            bool sealedV = Json.Bool(seg, "sealed");
            try
            {
                var receipt = Path.Combine(dir, "receipt.txt");
                if (!File.Exists(receipt)) return null;
                // a SEGMENTS 2 (sealed) receipt is held only as ciphertext, whatever the mod's
                // hd2_license.json says: with "sealed" taken out of it, plaintext seg*.lua matched
                // the receipt's segments_hash and counted as a claim (audit, 2026-11-19)
                using (var r = new StreamReader(receipt))
                    if (r.ReadLine() == SegmentsHeader2.TrimEnd('\n')) sealedV = true;
                string ext = sealedV ? "enc" : "lua", hashField = sealedV ? "sealed_hash" : "segments_hash";
                // the rows ask on every redraw: the files are read again only when one changed
                var stamp = new StringBuilder(key).Append('|').Append(ext).Append('|').Append(File.GetLastWriteTimeUtc(receipt).Ticks);
                for (long i = 1; i <= count; i++)
                {
                    var fi = new FileInfo(Path.Combine(dir, "seg" + i + "." + ext));
                    if (!fi.Exists) return null;
                    stamp.Append('|').Append(fi.LastWriteTimeUtc.Ticks).Append(':').Append(fi.Length);
                }
                lock (heldCache)
                    if (heldCache.TryGetValue(dir, out var c) && c.Stamp == stamp.ToString()) return c.Account;
                var f = VerifyReceipt(File.ReadAllText(receipt), issuer, key);
                string account = null;
                if (f != null && f.TryGetValue("id", out var rid) && rid == id && f.TryGetValue("version", out var rv) && rv == version)
                    using (var sha = SHA256.Create())
                    {
                        // the bytes on disk, as the issuer hashed the UTF-8 of the texts (or blobs) joined
                        for (long i = 1; i <= count; i++)
                        {
                            var b = File.ReadAllBytes(Path.Combine(dir, "seg" + i + "." + ext));
                            sha.TransformBlock(b, 0, b.Length, null, 0);
                        }
                        sha.TransformFinalBlock(new byte[0], 0, 0);
                        if (f.TryGetValue(hashField, out var h) && h == Hex(sha.Hash) && f.TryGetValue("account", out var a)) account = a;
                    }
                lock (heldCache) heldCache[dir] = (stamp.ToString(), account);
                return account;
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException) { return null; }
        }

        static readonly Dictionary<string, (string Stamp, string Account)> heldCache =
            new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase);

        /// <summary>The accounts here that a member signed in here has bound, most played first,
        /// each with the renew tokens to try (the member whose license names it first).</summary>
        static List<(string Account, List<string> Tokens)> BoundAccounts(string home, string appData, Dictionary<string, object> decl)
        {
            string issuer = Json.Str(decl, "issuer"), key = Json.Str(decl, "key");
            var list = new List<(string, List<string>)>();
            var rec = IssuerRecord(home, issuer);
            if (Json.Str(rec, "key") != key) return list;
            var tokens = RenewTokens(rec);
            if (tokens.Count == 0) return list;
            var held = ReadLicense(appData, issuer) is string lt ? Licenses(lt, issuer, key) : new List<Dictionary<string, string>>();
            foreach (var account in Accounts(appData))
            {
                var naming = new HashSet<string>(held.Where(f => Named(f).Contains(account)).Select(Holder));
                if (naming.Count == 0) continue;
                list.Add((account, tokens.OrderBy(t => naming.Contains(t.Holder) ? 0 : 1).Select(t => t.Token).ToList()));
            }
            return list;
        }

        /// <summary>The last claim per mod folder, for the card and the row: "claimed",
        /// "pending" (the author has not uploaded this version yet), or an error.</summary>
        static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> lastClaim =
            new System.Collections.Concurrent.ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Claims the segments of one mod when this computer has no good set for its
        /// version (or force): {claimed: true, account} | {claimed: false, why: "held"|
        /// "not_signed_in"} | {error}: "payload_pending" (the version is not uploaded yet),
        /// "bad_receipt", "network", the issuer's refusal, "bad_declaration", "no_version".</summary>
        public static Dictionary<string, object> ClaimSegments(string home, string appData, string modFolder, bool force = false)
        {
            Dictionary<string, object> r;
            lock (segmentsLock) r = ClaimOne(home, appData, modFolder, force);
            var seg = SegmentsOf(modFolder);
            string what = Json.Str(r, "error") ?? (Json.Bool(r, "claimed") ? "claimed" : Json.Str(r, "why"));
            if (what == "payload_pending") what = "pending";
            if (what != null) lastClaim[modFolder] = what == "held" ? "claimed" : what;
            if (Json.Str(r, "why") != "held")
                Log(home, Path.GetFileName(modFolder.TrimEnd('\\', '/')) + " " + Json.Str(seg, "id") + " " + Json.Str(seg, "version") + ": "
                    + what + (Json.Str(r, "account") is string a ? " (account " + a + ")" : ""));
            return r;
        }

        static Dictionary<string, object> ClaimOne(string home, string appData, string modFolder, bool force)
        {
            var decl = Declaration(modFolder);
            if (decl == null || Json.Str(decl, "error") != null) return Err("bad_declaration");
            var seg = SegmentsOf(modFolder);
            if (seg == null) return Err("bad_declaration");
            if (Json.Str(seg, "error") != null) return seg;
            string issuer = Json.Str(decl, "issuer"), key = Json.Str(decl, "key"), id = Json.Str(seg, "id"), version = Json.Str(seg, "version");
            int count = (int)Json.Long(seg, "count");
            // (1.7.0, C1) a sealed version is claimed as ciphertext (enc=1): the resident files are
            // seg<i>.enc and the receipt is a SEGMENTS 2 receipt whose sealed_hash covers them.
            bool sealedV = Json.Bool(seg, "sealed");
            string ext = sealedV ? "enc" : "lua", hashField = sealedV ? "sealed_hash" : "segments_hash";
            var bound = BoundAccounts(home, appData, decl);
            if (bound.Count == 0) return new Dictionary<string, object> { ["claimed"] = false, ["why"] = "not_signed_in" };
            var held = HeldAccount(appData, decl, seg);
            if (!force && held != null && bound.Any(b => b.Account == held))
                return new Dictionary<string, object> { ["claimed"] = false, ["why"] = "held", ["account"] = held };

            string error = null;
            foreach (var (account, tokens) in bound)
                foreach (var token in tokens)
                {
                    var req = new Dictionary<string, object> { ["id"] = id, ["version"] = version, ["account"] = account, ["renew"] = token };
                    if (sealedV) req["enc"] = 1;
                    var (status, body) = Post(issuer, "/segments", req);
                    if (status == 409) return Err(Json.Str(body, "error") ?? "payload_pending");
                    if (status == 403) { error = error ?? Json.Str(body, "error") ?? "unknown"; continue; }
                    if (status != 200) return Err("network");
                    var texts = (Json.List(body, "segments") ?? new List<object>()).OfType<string>().ToList();
                    var receipt = Json.Str(body, "receipt");
                    var f = receipt == null ? null : VerifyReceipt(receipt, issuer, key);
                    if (f == null || texts.Count != count
                        || !f.TryGetValue("id", out var rid) || rid != id
                        || !f.TryGetValue("version", out var rv) || rv != version
                        || !f.TryGetValue("account", out var ra) || ra != account
                        || !f.TryGetValue(hashField, out var rh) || rh != Utf8Sha256(string.Concat(texts)))
                    { error = error ?? "bad_receipt"; continue; }
                    WriteSegments(appData, issuer, id, version, texts, receipt, ext);
                    return new Dictionary<string, object> { ["claimed"] = true, ["account"] = account };
                }
            return Err(error ?? "unknown");
        }

        /// <summary>The set, written whole into a new folder beside the version's, then moved into
        /// place; an older set for the version goes after.</summary>
        static void WriteSegments(string appData, string issuer, string id, string version, List<string> texts, string receipt, string ext = "lua")
        {
            var dir = SegmentsFolder(appData, issuer, id, version);
            var root = Path.GetDirectoryName(dir);
            Directory.CreateDirectory(root);
            var tmp = Path.Combine(root, "." + version + ".new-" + Hex(Random(4)));
            Directory.CreateDirectory(tmp);
            var utf8 = new UTF8Encoding(false);
            for (int i = 0; i < texts.Count; i++) File.WriteAllText(Path.Combine(tmp, "seg" + (i + 1) + "." + ext), texts[i], utf8);
            File.WriteAllText(Path.Combine(tmp, "receipt.txt"), receipt.Replace("\r", ""), utf8);
            string old = null;
            if (Directory.Exists(dir))
            {
                old = Path.Combine(root, "." + version + ".old-" + Hex(Random(4)));
                Directory.Move(dir, old);
            }
            Directory.Move(tmp, dir);
            if (old != null) TryDelete(old);
        }

        static void TryDelete(string dir)
        {
            try { Directory.Delete(dir, true); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
        }

        /// <summary>Removes the version folders of the ids the library's mods declare that no mod
        /// in the library is at (and what an interrupted write left). An id no mod declares any
        /// more is left alone: a library read empty must not wipe every set. The removed folders.</summary>
        public static List<string> CleanSegments(string appData, IEnumerable<Dictionary<string, object>> library)
        {
            var inUse = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);   // root -> versions
            foreach (var m in library)
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path)) continue;
                var decl = Declaration(path);
                var seg = decl == null || Json.Str(decl, "error") != null ? null : SegmentsOf(path);
                if (seg == null || Json.Str(seg, "error") != null) continue;
                var root = SegmentsRoot(appData, Json.Str(decl, "issuer"), Json.Str(seg, "id"));
                if (!inUse.TryGetValue(root, out var set)) inUse[root] = set = new HashSet<string>(StringComparer.Ordinal);
                set.Add(Json.Str(seg, "version"));
            }
            var removed = new List<string>();
            foreach (var kv in inUse)
            {
                if (!Directory.Exists(kv.Key)) continue;
                foreach (var dir in Directory.GetDirectories(kv.Key))
                {
                    var name = Path.GetFileName(dir);
                    if (kv.Value.Contains(name)) continue;
                    // only what this plugin writes: a version, or what an interrupted write left
                    if (!OwnFolder.IsMatch(name)) continue;
                    TryDelete(dir);
                    if (!Directory.Exists(dir)) removed.Add(dir);
                }
            }
            return removed;
        }

        /// <summary>Every library mod that declares segments: claimed where this computer lacks a
        /// good set; then the versions no longer used are removed. True when one was claimed.</summary>
        public static bool ClaimAll(Dictionary<string, object> host, bool force = false)
        {
            bool any = false;
            string home = Home(host), appData = AppData(host);
            var library = LibraryOf(host);
            foreach (var m in library)
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path) || SegmentsOf(path) == null) continue;
                try { any |= Json.Bool(ClaimSegments(home, appData, path, force), "claimed"); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException)
                {
                    lastClaim[path] = "other";
                    Log(home, Path.GetFileName(path.TrimEnd('\\', '/')) + ": " + e.GetType().Name + " " + e.Message);
                }
            }
            try
            {
                List<string> removed;
                lock (segmentsLock) removed = CleanSegments(appData, library);
                foreach (var gone in removed) Log(home, "removed " + gone.Substring(LicenseDir(appData).Length).TrimStart('\\'));
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
            return any;
        }

        // -- in the background, once per version ---------------------------------------------

        static readonly HashSet<string> tried = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static int claiming;

        /// <summary>From a mod's row (the library changed, or the window drew it): when the mod's
        /// version has no good set here, one claim in the background, once per version per run
        /// of the manager. Never blocks the row.</summary>
        static void ClaimLater(Dictionary<string, object> host, string modFolder, Dictionary<string, object> seg)
        {
            lock (tried)
                if (!tried.Add(modFolder + "|" + Json.Str(seg, "version"))) return;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                if (Interlocked.Exchange(ref claiming, 1) == 1) { lock (tried) tried.Remove(modFolder + "|" + Json.Str(seg, "version")); return; }
                try { ClaimAll(host); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException) { }
                finally { Interlocked.Exchange(ref claiming, 0); }
                RefreshFromWorker(host);
            });
        }

        /// <summary>What the row and the card say about a mod's segments: "claimed", "pending",
        /// "not_signed_in", "missing" (not claimed yet), or the last claim's error.</summary>
        public static string SegmentsState(string home, string appData, string modFolder)
        {
            var decl = Declaration(modFolder);
            var seg = SegmentsOf(modFolder);
            if (seg == null || decl == null || Json.Str(decl, "error") != null) return null;
            if (Json.Str(seg, "error") != null) return Json.Str(seg, "error");
            var held = HeldAccount(appData, decl, seg);
            if (held != null) return "claimed";
            return lastClaim.TryGetValue(modFolder, out var last) && last != "claimed" ? last : "missing";
        }

        // -- payload.log --------------------------------------------------------------------

        static readonly object logLock = new object();
        const long LogMax = 256 * 1024;

        /// <summary>The plugin's own log of claims: home\license\payload.log (the previous one kept
        /// as payload.previous.log past 256 KB). Not the manager's log, not its reports.</summary>
        public static string LogPath(string home) => Path.Combine(home, "license", "payload.log");

        static void Log(string home, string line)
        {
            lock (logLock)
                try
                {
                    var path = LogPath(home);
                    Directory.CreateDirectory(Path.GetDirectoryName(path));
                    if (File.Exists(path) && new FileInfo(path).Length > LogMax)
                    {
                        var prev = Path.Combine(Path.GetDirectoryName(path), "payload.previous.log");
                        if (File.Exists(prev)) File.Delete(prev);
                        File.Move(path, prev);
                    }
                    File.AppendAllText(path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + line + Environment.NewLine, new UTF8Encoding(false));
                }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
        }
    }
}
