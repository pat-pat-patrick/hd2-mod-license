using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Hd2Qd.License
{
    /// <summary>(1.7.0, C1 session credential: CONTRACT_sealed_lua section 12). A sealed version
    /// keeps only ciphertext (seg&lt;i&gt;.enc) on disk, so a copied folder cannot run and a patched
    /// gate decrypts nothing. The plaintext the shell reads (seg&lt;i&gt;.lua) exists only while the
    /// game runs: this watches for the game process, and at a game start asks the issuer for the
    /// version's content key K_v (POST /session, cached machine-bound with DPAPI to a grace so a
    /// short offline spell still plays), decrypts the ciphertext into plaintext, and at the game's
    /// exit removes the plaintext again. No key ever touches the game; decryption is the manager's.
    ///
    /// The watermark and tracing are untouched: the decrypted plaintext still carries the account's
    /// combo (trace_leak hits it). Beyond the grace, or on another machine, the key is unavailable
    /// and the segments stay sealed.</summary>
    public static partial class Plugin
    {
        /// <summary>Whether helldivers2.exe runs; tests replace it.</summary>
        public static Func<bool> GameRunning = () =>
        {
            try { return Process.GetProcessesByName("helldivers2").Length > 0; }
            catch (Exception e) when (e is InvalidOperationException || e is System.ComponentModel.Win32Exception) { return false; }
        };

        // the DPAPI cache's entropy: a fixed app label, so another program's DPAPI blob is never read
        static readonly byte[] KeyEntropy = Encoding.ASCII.GetBytes("hd2qd-license-session-1");
        const string KeyCacheFile = "key.dpapi";

        static Timer gameTimer;
        static Dictionary<string, object> gameHost;
        static bool? gameWas;         // null until the first tick settles the initial state
        static readonly object gameLock = new object();
        static int gameBusy;

        /// <summary>From the manager's start on: a sealed version is decrypted for the game while it
        /// runs, and the plaintext removed when it stops. One timer for the process, made once (never
        /// a loop: 2026-10-26 a watcher loop leaked kernel pool). The first tick settles the initial
        /// state: if the game is already up it decrypts now; if it is down it clears any plaintext a
        /// crash left behind.</summary>
        public static void WatchGame(Dictionary<string, object> host)
        {
            lock (gameLock)
            {
                gameHost = host;
                if (gameTimer == null) gameTimer = new Timer(_ => GameTick(), null, 0, 5000);
            }
        }

        static void GameTick()
        {
            // a tick is cheap (one process enumeration) unless the game just came or went; never two
            // passes at once, and a long decrypt/clean never stacks up behind the timer
            if (Interlocked.Exchange(ref gameBusy, 1) == 1) return;
            try
            {
                var host = gameHost;
                if (host == null) return;
                bool now = GameRunning();
                if (gameWas == now) return;              // no change (and not the first tick)
                gameWas = now;
                if (now) OnGameStart(host); else OnGameStop(host);
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException) { }
            finally { Interlocked.Exchange(ref gameBusy, 0); }
        }

        /// <summary>A game start: every library mod that ships sealed segments and holds its version's
        /// ciphertext here is decrypted into the plaintext the shell reads, if the content key can be
        /// had (online now, or cached within the grace). True when any set was decrypted.</summary>
        public static bool OnGameStart(Dictionary<string, object> host)
        {
            bool any = false;
            string home = Home(host), appData = AppData(host);
            lock (segmentsLock)
                foreach (var m in LibraryOf(host))
                {
                    var path = Json.Str(m, "path");
                    if (path == null || !Directory.Exists(path)) continue;
                    var seg = SegmentsOf(path);
                    if (seg == null || Json.Str(seg, "error") != null || !Json.Bool(seg, "sealed")) continue;
                    var decl = Declaration(path);
                    if (decl == null || Json.Str(decl, "error") != null) continue;
                    try
                    {
                        var held = HeldAccount(appData, decl, seg);
                        if (held == null) continue;                 // no resident ciphertext to open
                        var key = SessionKey(home, appData, decl, seg, held);
                        if (key == null) { Log(home, SegLabel(path, seg) + ": sealed (no session key: offline past grace, or another computer)"); continue; }
                        if (DecryptPlain(appData, decl, seg, key)) { any = true; Log(home, SegLabel(path, seg) + ": decrypted for this session (account " + held + ")"); }
                        else Log(home, SegLabel(path, seg) + ": the content did not decrypt to what the receipt signs (sealed)");
                        Array.Clear(key, 0, key.Length);
                    }
                    catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException)
                    { Log(home, SegLabel(path, seg) + ": " + e.GetType().Name); }
                }
            return any;
        }

        /// <summary>A game stop (or the manager's start with the game down): the plaintext of every
        /// sealed version here is removed, leaving the ciphertext, the receipt and the key cache.</summary>
        public static void OnGameStop(Dictionary<string, object> host)
        {
            lock (segmentsLock) ClearAllPlain(Home(host), AppData(host));
        }

        static string SegLabel(string path, Dictionary<string, object> seg) =>
            Path.GetFileName(path.TrimEnd('\\', '/')) + " " + Json.Str(seg, "id") + " " + Json.Str(seg, "version");

        /// <summary>The content key K_v for a held sealed version: from the issuer now (POST /session,
        /// then kept machine-bound to its grace), or from that cache while a spell offline lasts
        /// within the grace. Null when neither can give it (offline past grace, or a cache made on
        /// another computer or for another account does not open).</summary>
        static byte[] SessionKey(string home, string appData, Dictionary<string, object> decl, Dictionary<string, object> seg, string account)
        {
            string issuer = Json.Str(decl, "issuer"), id = Json.Str(seg, "id"), version = Json.Str(seg, "version");
            var tokens = BoundAccounts(home, appData, decl).FirstOrDefault(b => b.Account == account).Tokens ?? new List<string>();
            foreach (var token in tokens)
            {
                var (status, body) = Post(issuer, "/session", new Dictionary<string, object>
                { ["id"] = id, ["version"] = version, ["account"] = account, ["renew"] = token });
                if (status != 200) continue;              // refused or unreachable: fall back to the cached key within grace
                var k = Json.Str(body, "key");
                byte[] key = TryBase64(k);
                if (key == null || key.Length != 32) continue;
                long grace = Json.Long(body, "grace");
                CacheKey(appData, issuer, id, version, key, account, Now() + Math.Max(0, grace));
                return key;
            }
            return CachedKey(appData, issuer, id, version, account);
        }

        static byte[] TryBase64(string s)
        {
            try { return s == null ? null : Convert.FromBase64String(s); }
            catch (FormatException) { return null; }
        }

        static void CacheKey(string appData, string issuer, string id, string version, byte[] key, string account, long expires)
        {
            var dir = SegmentsFolder(appData, issuer, id, version);
            Directory.CreateDirectory(dir);
            var record = Json.Write(new Dictionary<string, object>
            { ["k"] = Convert.ToBase64String(key), ["account"] = account, ["exp"] = expires });
            var prot = ProtectedData.Protect(Encoding.UTF8.GetBytes(record), KeyEntropy, DataProtectionScope.CurrentUser);
            var path = Path.Combine(dir, KeyCacheFile);
            var tmp = path + ".tmp";
            File.WriteAllBytes(tmp, prot);
            if (File.Exists(path)) File.Delete(path);
            File.Move(tmp, path);
        }

        static byte[] CachedKey(string appData, string issuer, string id, string version, string account)
        {
            var path = Path.Combine(SegmentsFolder(appData, issuer, id, version), KeyCacheFile);
            if (!File.Exists(path)) return null;
            try
            {
                // DPAPI(CurrentUser): this fails on another machine or user, so a copied cache opens nothing
                var bytes = ProtectedData.Unprotect(File.ReadAllBytes(path), KeyEntropy, DataProtectionScope.CurrentUser);
                var d = Json.Parse(Encoding.UTF8.GetString(bytes)) as Dictionary<string, object>;
                if (Json.Str(d, "account") != account || Json.Long(d, "exp") <= Now()) return null;
                var key = TryBase64(Json.Str(d, "k"));
                return key != null && key.Length == 32 ? key : null;
            }
            catch (Exception e) when (e is CryptographicException || e is FormatException || e is IOException || e is UnauthorizedAccessException) { return null; }
        }

        /// <summary>Decrypts the resident ciphertext of a sealed version with K_v and, when the
        /// plaintext matches the receipt's segments_hash, writes seg&lt;i&gt;.lua (the files the shell
        /// reads) whole, each through a temporary name so the shell never reads a half-written file.
        /// False when the key is wrong or the content does not check out: nothing is written.</summary>
        static bool DecryptPlain(string appData, Dictionary<string, object> decl, Dictionary<string, object> seg, byte[] key)
        {
            string issuer = Json.Str(decl, "issuer"), keyMod = Json.Str(decl, "key"), id = Json.Str(seg, "id"), version = Json.Str(seg, "version");
            int count = (int)Json.Long(seg, "count");
            var dir = SegmentsFolder(appData, issuer, id, version);
            var receipt = Path.Combine(dir, "receipt.txt");
            if (!File.Exists(receipt)) return false;
            var f = VerifyReceipt(File.ReadAllText(receipt), issuer, keyMod);
            if (f == null || !f.TryGetValue("segments_hash", out var want)) return false;

            var plain = new string[count];
            var utf8 = new UTF8Encoding(false);
            for (int i = 1; i <= count; i++)
            {
                var enc = Path.Combine(dir, "seg" + i + ".enc");
                if (!File.Exists(enc)) return false;
                var blob = TryBase64(File.ReadAllText(enc, utf8));
                if (blob == null || blob.Length <= 16) return false;
                plain[i - 1] = utf8.GetString(AesCbcDecrypt(key, blob));
            }
            if (Utf8Sha256(string.Concat(plain)) != want) return false;    // wrong key or tampered: fail closed

            var tmp = new string[count];
            for (int i = 1; i <= count; i++)
            {
                tmp[i - 1] = Path.Combine(dir, "seg" + i + ".lua.new-" + Hex(Random(4)));
                File.WriteAllText(tmp[i - 1], plain[i - 1], utf8);
            }
            for (int i = 1; i <= count; i++)
            {
                var lua = Path.Combine(dir, "seg" + i + ".lua");
                if (File.Exists(lua)) File.Delete(lua);
                File.Move(tmp[i - 1], lua);
            }
            return true;
        }

        /// <summary>AES-256-CBC/PKCS7 of blob = IV(16) ‖ ciphertext (CONTRACT section 12.3). The
        /// receipt's signed segments_hash authenticates the plaintext, so CBC needs no separate tag.</summary>
        static byte[] AesCbcDecrypt(byte[] key, byte[] blob)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                var iv = new byte[16];
                Array.Copy(blob, 0, iv, 0, 16);
                aes.IV = iv;
                using (var dec = aes.CreateDecryptor())
                    return dec.TransformFinalBlock(blob, 16, blob.Length - 16);
            }
        }

        /// <summary>Removes the per-session plaintext (seg*.lua) from every sealed version folder
        /// here -- a folder that has a seg*.enc. The ciphertext, receipt and key cache stay.</summary>
        static void ClearAllPlain(string home, string appData)
        {
            var root = LicenseDir(appData);
            if (!Directory.Exists(root)) return;
            // licenses\<issuer>\segments\<id>\<version>\
            foreach (var iss in SafeDirs(root))
                foreach (var segRoot in SafeDirs(iss).Where(d => string.Equals(Path.GetFileName(d), "segments", StringComparison.Ordinal)))
                    foreach (var idDir in SafeDirs(segRoot))
                        foreach (var ver in SafeDirs(idDir))
                        {
                            try
                            {
                                if (!Directory.EnumerateFiles(ver, "seg*.enc").Any()) continue;   // not a sealed set
                                foreach (var lua in Directory.GetFiles(ver, "seg*.lua")) File.Delete(lua);
                            }
                            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
                        }
        }

        static IEnumerable<string> SafeDirs(string dir)
        {
            try { return Directory.GetDirectories(dir); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return Enumerable.Empty<string>(); }
        }
    }
}
