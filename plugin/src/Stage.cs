using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Hd2Qd.License
{
    /// <summary>(1.12.0) Protected game packages (spec/static-resources.zh-CN.md draft 4, deploy
    /// "game"; hd2_diag\LARGE_ASSET_PROTECTION.zh-CN.md). A mod of hundreds of MB of models and
    /// textures ships its patch files sealed in its own zip, under protected/, all under one key
    /// K_c; the issuer gates only that key, plus the account's variant of a few fingerprinted files
    /// (the parts of a joined receipt, N may be 0). The receipt's base= is the SHA-256 of
    /// protected/manifest.json:
    ///   {format: 1, wire, files: [{path, size, sealed, plain}], parts: [{path, size}]}
    /// (paths relative to the mod's folder, '/' separated; files[i] is sealed at
    /// protected/&lt;path&gt;.seal; parts[p] is the receipt's p-th part.)
    ///
    /// The manager (host["stage"], a folder on the game's drive) deploys from the folder this
    /// plugin fills, laid out as the mod's own: ModSource says where, once it is ready;
    /// PrepareDeploy decrypts what is missing; EndSession removes a session-mode mod's plaintext
    /// after the manager deployed without it. A file once written whole is never rewritten (the
    /// manager keeps its hard link by the file's identity); a file another name still links
    /// (the game's data folder) is never deleted here.</summary>
    public static partial class Plugin
    {
        const string ManifestRel = "protected\\manifest.json";
        const string ReadyFile = ".hd2qd_ready";
        static readonly object stageLock = new object();

        sealed class GameManifest
        {
            public string Wire, Base;
            public List<(string Path, long Size, string Plain)> Files = new List<(string, long, string)>();
            public List<(string Path, long Size)> Parts = new List<(string, long)>();
            public long Total => Files.Sum(f => f.Size) + Parts.Sum(p => p.Size);
        }

        static readonly char[] BadNameChars = Path.GetInvalidFileNameChars();

        /// <summary>A manifest path as a relative Windows path inside the mod: '/' separated, no
        /// empty, "." or ".." part, no drive, no character a file name cannot have. Else null.</summary>
        static string SafeRel(string p)
        {
            if (string.IsNullOrEmpty(p) || p.Length > 400 || p.StartsWith("/", StringComparison.Ordinal)) return null;
            var parts = p.Split('/');
            foreach (var x in parts)
                if (x.Length == 0 || x == "." || x == ".." || x.IndexOfAny(BadNameChars) >= 0 || x.EndsWith(".", StringComparison.Ordinal) || x.EndsWith(" ", StringComparison.Ordinal)) return null;
            return string.Join("\\", parts);
        }

        static readonly Dictionary<string, (string Stamp, GameManifest M)> manifestCache =
            new Dictionary<string, (string, GameManifest)>(StringComparer.OrdinalIgnoreCase);

        /// <summary>The mod's protected/manifest.json, read and checked (format 1, safe distinct
        /// paths, hashes as hex), with Base its bytes' SHA-256. Null when it is missing or bad.
        /// Read again only when the file changed.</summary>
        static GameManifest ReadManifest(string modFolder)
        {
            var fi = new FileInfo(Path.Combine(modFolder, ManifestRel));
            if (!fi.Exists) return null;
            var stamp = fi.LastWriteTimeUtc.Ticks + ":" + fi.Length;
            lock (manifestCache)
                if (manifestCache.TryGetValue(fi.FullName, out var c) && c.Stamp == stamp) return c.M;
            GameManifest m = null;
            try
            {
                if (fi.Length <= 16 * 1024 * 1024)
                {
                    var bytes = File.ReadAllBytes(fi.FullName);
                    var d = Json.Parse(Encoding.UTF8.GetString(bytes)) as Dictionary<string, object>;
                    m = ParseManifest(d, Sha256Bytes(bytes));
                }
            }
            catch (Exception e) when (e is FormatException || e is IOException || e is UnauthorizedAccessException) { m = null; }
            lock (manifestCache) manifestCache[fi.FullName] = (stamp, m);
            return m;
        }

        static GameManifest ParseManifest(Dictionary<string, object> d, string baseHash)
        {
            if (d == null || Json.Long(d, "format") != 1) return null;
            var m = new GameManifest { Wire = Json.Str(d, "wire"), Base = baseHash };
            if (m.Wire == null || !PayloadId.IsMatch(m.Wire)) return null;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var o in Json.List(d, "files") ?? new List<object>())
            {
                var x = o as Dictionary<string, object>;
                var rel = SafeRel(Json.Str(x, "path"));
                string plain = Json.Str(x, "plain"), sealedHash = Json.Str(x, "sealed");
                long size = Json.Long(x, "size");
                if (rel == null || !seen.Add(rel) || size < 0 || plain == null || !Regex.IsMatch(plain, "^[0-9a-f]{64}\\z")
                    || sealedHash == null || !Regex.IsMatch(sealedHash, "^[0-9a-f]{64}\\z")) return null;
                m.Files.Add((rel, size, plain));
            }
            foreach (var o in Json.List(d, "parts") ?? new List<object>())
            {
                var x = o as Dictionary<string, object>;
                var rel = SafeRel(Json.Str(x, "path"));
                long size = Json.Long(x, "size");
                if (rel == null || !seen.Add(rel) || size < 0) return null;
                m.Parts.Add((rel, size));
            }
            if (m.Parts.Count > 64 || m.Files.Count + m.Parts.Count == 0) return null;
            return m;
        }

        /// <summary>Where a protected package is staged: &lt;stage&gt;\license\&lt;issuer&gt;\&lt;wire&gt;.&lt;base, 12 hex&gt;.
        /// A new build (another manifest) gets its own folder.</summary>
        static string StageDir(string stageRoot, string issuer, GameManifest m) =>
            Path.Combine(stageRoot, "license", issuer.Replace(':', '_'), m.Wire + "." + m.Base.Substring(0, 12));

        static string StageRoot(Dictionary<string, object> host) =>
            host != null && host.TryGetValue("stage", out var s) && s is string root && root.Length > 0 ? root : null;

        /// <summary>The ready mark's fields (written last, after every file), or null.</summary>
        static Dictionary<string, object> ReadyOf(string dir)
        {
            try
            {
                var path = Path.Combine(dir, ReadyFile);
                return File.Exists(path) ? Json.Parse(File.ReadAllText(path)) as Dictionary<string, object> : null;
            }
            catch (Exception e) when (e is FormatException || e is IOException || e is UnauthorizedAccessException) { return null; }
        }

        /// <summary>Whether every file the manifest names is in the stage folder at its size (no
        /// hashing: each was checked as it was written, and is never written again).</summary>
        static bool AllThere(string dir, GameManifest m) =>
            m.Files.All(f => SizeIs(Path.Combine(dir, f.Path), f.Size)) && m.Parts.All(p => File.Exists(Path.Combine(dir, p.Path)));

        static bool SizeIs(string path, long size)
        {
            var fi = new FileInfo(path);
            return fi.Exists && fi.Length == size;
        }

        // ------------------------------------------------------------ the manager's calls

        /// <summary>(1.12.0, the manager's call, at most once per mod per state read) For a mod with
        /// a protected game package: {folder, mode} when its plaintext is staged (folder is laid out
        /// as the mod's own); {folder: "", mode, why} when it is not (why in the manager's language).
        /// Null for any other mod. Reads only the manifest and the files' sizes; no key, no request.</summary>
        public static Dictionary<string, object> ModSource(string modFolder, Dictionary<string, object> host)
        {
            var pay = PayloadOf(modFolder);
            if (pay == null || !GameForm(pay) && Json.Str(pay, "error") == null) return null;
            string lang = Words.Lang(host);
            var mode = Json.Str(pay, "mode") ?? "deploy";
            Dictionary<string, object> NotReady(string key) =>
                new Dictionary<string, object> { ["folder"] = "", ["mode"] = mode, ["why"] = Words.Get(lang, key) };
            if (Json.Str(pay, "error") != null) return Json.Str(pay, "error") == "update_manager" ? null : NotReady("stage_bad_declaration");
            var decl = Declaration(modFolder);
            if (decl == null || Json.Str(decl, "error") != null) return NotReady("stage_bad_declaration");
            var root = StageRoot(host);
            if (root == null) return NotReady("stage_no_game");
            try
            {
                var m = ReadManifest(modFolder);
                if (m == null || m.Wire != Json.Str(pay, "wire")) return NotReady("stage_bad_package");
                var dir = StageDir(root, Json.Str(decl, "issuer"), m);
                var ready = ReadyOf(dir);
                if (ready == null || Json.Str(ready, "base") != m.Base || !AllThere(dir, m))
                    return NotReady(mode == "session" ? "stage_session" : "stage_not_ready");
                return new Dictionary<string, object> { ["folder"] = dir, ["mode"] = mode };
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return NotReady("stage_not_ready"); }
        }

        /// <summary>(1.12.0, the manager's call, on a background thread before a deploy and before
        /// starting a game) Stages every enabled library mod's protected game package that is not
        /// staged yet: its key from the cache within the receipt's grace, else from the issuer;
        /// the account's fingerprinted files from the package fetched for it. host["for_session"]:
        /// also the session-mode mods (else only "deploy" ones). True when anything was written.</summary>
        public static bool PrepareDeploy(Dictionary<string, object> host)
        {
            var root = StageRoot(host);
            if (root == null) return false;
            bool forSession = host.TryGetValue("for_session", out var fs) && fs is bool b && b;
            bool any = false;
            foreach (var m in LibraryOf(host))
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path) || m.TryGetValue("enabled", out var en) && en is bool on && !on) continue;
                var pay = PayloadOf(path);
                if (pay == null || !GameForm(pay)) continue;
                if (Json.Str(pay, "mode") == "session" && !forSession) continue;
                try { lock (stageLock) any |= StageMod(host, path); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException)
                { Log(Home(host), IssuerOf(path), PayLabel(path, pay) + ": staging failed: " + e.GetType().Name + " " + e.Message); }
            }
            return any;
        }

        /// <summary>(1.12.0, the manager's call, after it deployed without the session-mode mods)
        /// Every session-mode package's staged plaintext goes: the ready mark first, then each file
        /// no other name links (one the game's data folder still links stays, and goes on the next
        /// call, once a deploy dropped it).</summary>
        public static void EndSession(Dictionary<string, object> host)
        {
            var root = StageRoot(host);
            if (root == null) return;
            lock (stageLock)
                foreach (var m in LibraryOf(host))
                {
                    var path = Json.Str(m, "path");
                    if (path == null || !Directory.Exists(path)) continue;
                    var pay = PayloadOf(path);
                    if (pay == null || !GameForm(pay) || Json.Str(pay, "mode") != "session") continue;
                    var decl = Declaration(path);
                    var man = ReadManifest(path);
                    if (decl == null || Json.Str(decl, "error") != null || man == null) continue;
                    var kept = RemoveStaged(StageDir(root, Json.Str(decl, "issuer"), man));
                    Log(Home(host), Json.Str(decl, "issuer"), PayLabel(path, pay) + ": session ended, plaintext removed" + (kept > 0 ? " (" + kept + " file(s) still deployed, removed next time)" : ""));
                }
        }

        // ------------------------------------------------------------ staging

        /// <summary>Stages one mod. False when it already was, or could not be (logged).</summary>
        static bool StageMod(Dictionary<string, object> host, string modFolder)
        {
            string home = Home(host), appData = AppData(host), root = StageRoot(host);
            var decl = Declaration(modFolder);
            var pay = PayloadOf(modFolder);
            if (decl == null || Json.Str(decl, "error") != null || pay == null || Json.Str(pay, "error") != null) return false;
            string issuer = Json.Str(decl, "issuer"), label = PayLabel(modFolder, pay);
            var m = ReadManifest(modFolder);
            if (m == null || m.Wire != Json.Str(pay, "wire")) { Log(home, issuer, label + ": protected/manifest.json is missing or does not fit the declaration"); return false; }
            var dir = StageDir(root, issuer, m);

            // the account's package: its receipt (and fingerprinted parts), fetched if not held yet
            var held = PayloadHeld(appData, decl, pay);
            if (held == null)
            {
                ClaimPayload(home, appData, modFolder);
                held = PayloadHeld(appData, decl, pay);
                if (held == null) { Log(home, issuer, label + ": not staged (no member content fetched for an account of this computer)"); return false; }
            }
            var resDir = PayloadFolder(appData, issuer, pay);
            var f = VerifyPayloadReceipt(File.ReadAllText(Path.Combine(resDir, "receipt.txt")), issuer, Json.Str(decl, "key"));
            if (f == null || !f.TryGetValue("base", out var baseHash) || baseHash != m.Base || !Joined(f) || PartsOf(f) != m.Parts.Count)
            {
                Log(home, issuer, label + ": the receipt does not sign this mod's protected/manifest.json (another build?): not staged");
                return false;
            }
            string mark = f.TryGetValue("mark", out var mk) ? mk : "";
            var ready = ReadyOf(dir);
            if (ready != null && Json.Str(ready, "base") == m.Base && Json.Str(ready, "mark") == mark && AllThere(dir, m)) return false;

            byte[] key = CachedPayloadKey(home, appData, issuer, pay, held, f["sealed_hash"]) ?? PayloadSessionKey(home, appData, decl, pay, held);
            if (key == null) { Log(home, issuer, label + ": not staged (no key: offline past grace, or another computer)"); return false; }
            try
            {
                // a replaced package (PayloadSessionKey fetched again) brings a new receipt
                f = VerifyPayloadReceipt(File.ReadAllText(Path.Combine(resDir, "receipt.txt")), issuer, Json.Str(decl, "key"));
                if (f == null || !f.TryGetValue("base", out baseHash) || baseHash != m.Base || Sha256Bytes(key) != f["key_hash"]) return false;
                mark = f.TryGetValue("mark", out mk) ? mk : "";

                long missing = m.Files.Where(x => !SizeIs(Path.Combine(dir, x.Path), x.Size)).Sum(x => x.Size) + m.Parts.Sum(p => p.Size);
                if (!RoomFor(root, missing))
                {
                    Log(home, issuer, label + ": not staged (not enough free space on the game's drive: " + missing / (1024 * 1024) + " MB needed)");
                    return false;
                }
                Directory.CreateDirectory(dir);
                TryDeleteFile(Path.Combine(dir, ReadyFile));
                int wrote = 0;
                foreach (var x in m.Files)
                {
                    var target = Path.Combine(dir, x.Path);
                    if (SizeIs(target, x.Size)) continue;                         // written whole before: never again
                    var source = Path.Combine(modFolder, "protected", x.Path + ".seal");
                    if (!File.Exists(source)) { Log(home, issuer, label + ": " + x.Path + ".seal is missing from the mod: not staged"); return false; }
                    if (!DecryptFileTo(key, source, target, x.Size, x.Plain)) { Log(home, issuer, label + ": " + x.Path + " did not decrypt to what the manifest signs: not staged"); return false; }
                    wrote++;
                }
                // the account's fingerprinted files: the parts, decrypted together against plain_hash
                var pieces = ReadPieces(resDir, f);
                if (pieces == null || JoinedHash(pieces, f) != f["sealed_hash"]) { Log(home, issuer, label + ": the fingerprinted files are not all here: not staged"); return false; }
                var plains = OpenEach(key, pieces, f);
                if (plains == null) { Log(home, issuer, label + ": the fingerprinted files did not decrypt to what the receipt signs: not staged"); return false; }
                for (int p = 0; p < m.Parts.Count; p++)
                {
                    var target = Path.Combine(dir, m.Parts[p].Path);
                    if (File.Exists(target) && Sha256Bytes(File.ReadAllBytes(target)) == Sha256Bytes(plains[p])) continue;
                    WriteWhole(target, plains[p]);
                    wrote++;
                }
                foreach (var pl in plains) Array.Clear(pl, 0, pl.Length);
                WriteWhole(Path.Combine(dir, ReadyFile), Encoding.UTF8.GetBytes(Json.Write(new Dictionary<string, object>
                {
                    ["base"] = m.Base, ["mark"] = mark, ["account"] = held, ["mode"] = Json.Str(pay, "mode"), ["wire"] = m.Wire,
                })));
                Log(home, issuer, label + ": staged for the manager (" + wrote + " file(s) written, account " + held + ")");
                return true;
            }
            finally { Array.Clear(key, 0, key.Length); }
        }

        /// <summary>Whether the game's drive has room for these bytes and 1 GB besides.</summary>
        static bool RoomFor(string root, long bytes)
        {
            try { return new DriveInfo(Path.GetPathRoot(Path.GetFullPath(root))).AvailableFreeSpace >= bytes + (1L << 30); }
            catch (Exception e) when (e is ArgumentException || e is IOException || e is UnauthorizedAccessException) { return true; }
        }

        /// <summary>Decrypts one sealed file (IV(16) ‖ AES-256-CBC/PKCS7) into target, streaming: the
        /// plaintext is hashed as it is written to a temporary name and moved into place only when
        /// its size and SHA-256 are the manifest's. False (nothing left behind) otherwise.</summary>
        static bool DecryptFileTo(byte[] key, string sealedPath, string target, long size, string plainHash)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            var tmp = target + ".new-" + Hex(Random(4));
            bool ok = false;
            try
            {
                using (var src = new FileStream(sealedPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
                {
                    if (src.Length <= 16 || (src.Length - 16) % 16 != 0) return false;
                    var iv = new byte[16];
                    if (src.Read(iv, 0, 16) != 16) return false;
                    using (var aes = Aes.Create())
                    {
                        aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = key; aes.IV = iv;
                        using (var dec = aes.CreateDecryptor())
                        using (var cs = new CryptoStream(src, dec, CryptoStreamMode.Read))
                        using (var sha = SHA256.Create())
                        using (var dst = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20))
                        {
                            var buf = new byte[1 << 20];
                            long total = 0;
                            int n;
                            while ((n = cs.Read(buf, 0, buf.Length)) > 0)
                            {
                                total += n;
                                if (total > size) return false;
                                sha.TransformBlock(buf, 0, n, null, 0);
                                dst.Write(buf, 0, n);
                            }
                            sha.TransformFinalBlock(new byte[0], 0, 0);
                            if (total != size || Hex(sha.Hash) != plainHash) return false;
                        }
                    }
                }
                if (File.Exists(target)) File.Delete(target);       // a wrong size: only this name goes
                File.Move(tmp, target);
                ok = true;
                return true;
            }
            catch (CryptographicException) { return false; }
            finally { if (!ok) TryDeleteFile(tmp); }
        }

        /// <summary>Bytes written whole through a temporary name.</summary>
        static void WriteWhole(string target, byte[] bytes)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            var tmp = target + ".new-" + Hex(Random(4));
            File.WriteAllBytes(tmp, bytes);
            if (File.Exists(target)) File.Delete(target);
            File.Move(tmp, target);
        }

        static void TryDeleteFile(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
        }

        /// <summary>A stage folder's plaintext: the ready mark first (so the manager stops deploying
        /// it), then every file only this name links, then the empty folders. The number of files
        /// kept because another name (the game's data folder) still links them.</summary>
        static int RemoveStaged(string dir)
        {
            if (!Directory.Exists(dir)) return 0;
            TryDeleteFile(Path.Combine(dir, ReadyFile));
            int kept = 0;
            foreach (var file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
            {
                if (LinkCount(file) > 1) { kept++; continue; }
                TryDeleteFile(file);
            }
            foreach (var d in Directory.GetDirectories(dir, "*", SearchOption.AllDirectories).OrderByDescending(x => x.Length).Concat(new[] { dir }))
                try { if (!Directory.EnumerateFileSystemEntries(d).Any()) Directory.Delete(d); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
            return kept;
        }

        /// <summary>(1.12.0) A member whose membership the issuer refused (not_member, banned): every
        /// protected package of this mod staged here goes (a deploy then drops the mod).</summary>
        static void RemoveStage(Dictionary<string, object> host, string modFolder)
        {
            var root = StageRoot(host);
            var decl = Declaration(modFolder);
            var m = ReadManifest(modFolder);
            if (root == null || decl == null || Json.Str(decl, "error") != null || m == null) return;
            lock (stageLock)
            {
                var kept = RemoveStaged(StageDir(root, Json.Str(decl, "issuer"), m));
                Log(Home(host), Json.Str(decl, "issuer"), Path.GetFileName(modFolder.TrimEnd('\\', '/')) + ": membership refused, staged plaintext removed" + (kept > 0 ? " (" + kept + " file(s) still deployed until the next deploy)" : ""));
            }
        }

        static readonly Regex OwnStageFolder = new Regex(@"^[a-z0-9][a-z0-9._-]{0,63}\.[0-9a-f]{12}$");

        /// <summary>(1.12.0) The stage folders of an issuer the library uses that no library mod's
        /// manifest names any more (an old build or version, a mod taken out). The removed folders.</summary>
        static List<string> CleanStages(Dictionary<string, object> host, IEnumerable<Dictionary<string, object>> library)
        {
            var root = StageRoot(host);
            var removed = new List<string>();
            if (root == null) return removed;
            var inUse = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var issuers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in library)
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path)) continue;
                var pay = PayloadOf(path);
                var decl = Declaration(path);
                if (pay == null || !GameForm(pay) || decl == null || Json.Str(decl, "error") != null) continue;
                var man = ReadManifest(path);
                var issuerDir = Path.Combine(root, "license", Json.Str(decl, "issuer").Replace(':', '_'));
                issuers.Add(issuerDir);
                if (man != null) inUse.Add(StageDir(root, Json.Str(decl, "issuer"), man));
            }
            lock (stageLock)
                foreach (var issuerDir in issuers)
                {
                    if (!Directory.Exists(issuerDir)) continue;
                    foreach (var dir in Directory.GetDirectories(issuerDir))
                    {
                        if (inUse.Contains(dir) || !OwnStageFolder.IsMatch(Path.GetFileName(dir))) continue;
                        RemoveStaged(dir);
                        if (!Directory.Exists(dir)) removed.Add(dir);
                    }
                }
            return removed;
        }

        // ------------------------------------------------------------ hard links

        [StructLayout(LayoutKind.Sequential)]
        struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

        /// <summary>How many names the file has (2 and more: the manager deployed it by a hard link
        /// that is still in place). 0 when it cannot be read.</summary>
        static int LinkCount(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    return GetFileInformationByHandle(fs.SafeFileHandle, out var info) ? (int)info.NumberOfLinks : 0;
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return 0; }
        }
    }
}
