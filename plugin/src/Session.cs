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
                bool first = gameWas == null;
                gameWas = now;
                // the game already running at this program's first look: it started before the
                // manager, so what is decrypted now comes too late for this game
                if (now) OnGameStart(host, first);
                else
                {
                    OnGameStop(host);
                    if (!first) Log(Home(host), null, "game stopped: readable member content removed");   // (1.9.0)
                }
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException) { }
            finally { Interlocked.Exchange(ref gameBusy, 0); }
        }

        /// <summary>A game start: every library mod that ships sealed segments and holds its version's
        /// ciphertext here is decrypted into the plaintext the shell reads, if the content key can be
        /// had (online now, or cached within the grace). True when any set was decrypted.</summary>
        public static bool OnGameStart(Dictionary<string, object> host) => OnGameStart(host, false);

        /// <summary>How the last game start went for a sealed mod (its folder), when it went wrong:
        /// "late" (the game started before this program, so its content stayed locked that game),
        /// "no_key" (no content key: offline past the grace). Null when it was unlocked in time.
        /// For the mod's row in the manager (ModNote); kept for this program's run only.</summary>
        public static string LastUnlock(string modFolder)
        {
            lock (lastUnlock) return modFolder != null && lastUnlock.TryGetValue(modFolder, out var v) ? v : null;
        }

        static readonly Dictionary<string, string> lastUnlock = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        static void SetLastUnlock(string modFolder, string what)
        {
            lock (lastUnlock) { if (what == null) lastUnlock.Remove(modFolder); else lastUnlock[modFolder] = what; }
        }

        public static bool OnGameStart(Dictionary<string, object> host, bool late)
        {
            bool any = false;
            string home = Home(host), appData = AppData(host);
            int sealedCount = 0;
            lock (segmentsLock)
                foreach (var m in LibraryOf(host))
                {
                    var path = Json.Str(m, "path");
                    if (path == null || !Directory.Exists(path)) continue;
                    var seg = SegmentsOf(path);
                    if (seg == null || Json.Str(seg, "error") != null || !Json.Bool(seg, "sealed")) continue;
                    var decl = Declaration(path);
                    if (decl == null || Json.Str(decl, "error") != null) continue;
                    sealedCount++;
                    try
                    {
                        var held = HeldAccount(appData, decl, seg);
                        // no resident ciphertext to open: said, so a log shows why the mod stayed quiet (1.9.0)
                        if (held == null) { Log(home, Json.Str(decl, "issuer"), SegLabel(path, seg) + ": nothing to unlock (no member content downloaded here for an account of this computer)"); continue; }
                        var key = SessionKey(home, appData, decl, seg, held);
                        if (key == null) { SetLastUnlock(path, "no_key"); Log(home, Json.Str(decl, "issuer"), SegLabel(path, seg) + ": sealed (no session key: offline past grace, or another computer)"); continue; }
                        if (DecryptPlain(appData, decl, seg, key))
                        {
                            any = true;
                            SetLastUnlock(path, late ? "late" : null);
                            Log(home, Json.Str(decl, "issuer"), SegLabel(path, seg) + (late ? ": decrypted, but the game started before this program: unlocked from the next game" : ": decrypted for this session") + " (account " + held + ")");
                        }
                        else Log(home, Json.Str(decl, "issuer"), SegLabel(path, seg) + ": the content did not decrypt to what the receipt signs (sealed)");
                        Array.Clear(key, 0, key.Length);
                    }
                    catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException)
                    { Log(home, Json.Str(decl, "issuer"), SegLabel(path, seg) + ": " + e.GetType().Name); }
                }
            // (1.10.0) the payloads: a mod with both is counted once
            lock (segmentsLock)
            {
                var (payAny, _) = UnlockPayloads(host, late);
                any |= payAny;
                sealedCount += LibraryOf(host).Count(m => Json.Str(m, "path") is string p && Directory.Exists(p)
                    && PayloadOf(p) is Dictionary<string, object> pay && Json.Str(pay, "error") == null && !Json.Bool(SegmentsOf(p), "sealed"));
            }
            // (1.9.0) every game start, so a log tells a game this program saw from one it never saw
            Log(home, null, (late ? "the game was already running at this program's start" : "game started") + ": " + sealedCount + " mod(s) with sealed member content in the library");
            return any;
        }

        /// <summary>A game stop (or the manager's start with the game down): the plaintext of every
        /// sealed version here is removed, leaving the ciphertext, the receipt and the key cache.</summary>
        public static void OnGameStop(Dictionary<string, object> host)
        {
            lock (segmentsLock)
            {
                ClearAllPlain(Home(host), AppData(host));
                ClearPayloadPlain(AppData(host));       // (1.10.0)
            }
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
                var (status, body) = Post(home, issuer, "/session", new Dictionary<string, object>
                { ["id"] = id, ["version"] = version, ["account"] = account, ["renew"] = token });
                if (status != 200) continue;              // refused or unreachable: fall back to the cached key within grace
                var k = Json.Str(body, "key");
                byte[] key = TryBase64(k);
                if (key == null || key.Length != 32) continue;
                // kept for the grace only with the issuer's signed ticket, whose expiry the
                // cache then follows: the expiry used to be a field of the DPAPI record, which the
                // player can unprotect and rewrite (audit, 2026-11-19). An issuer that sends no good
                // ticket gives this session its key and nothing to keep.
                var ticket = Json.Str(body, "ticket");
                if (ticket != null && VerifyTicket(ticket, issuer, PinnedKey(home, issuer), id, version, account, key) != null)
                    CacheKey(appData, issuer, id, version, key, account, ticket);
                return key;
            }
            return CachedKey(home, appData, issuer, id, version, account);
        }

        const string SessionHeader = "HD2 MOD SESSION 1\n";
        // the local clock may be this much behind the issuer's and a ticket still counts (seconds)
        const long ClockSlack = 600;

        /// <summary>The key the member signed in with pinned for this issuer (the one claims check).</summary>
        static string PinnedKey(string home, string issuer) => Json.Str(IssuerRecord(home, issuer), "key");

        /// <summary>The fields of an issuer's session ticket (POST /session) when it is signed by the
        /// pinned key and names this id, version, account and the key it came with; else null.</summary>
        static Dictionary<string, string> VerifyTicket(string text, string issuer, string pinned, string id, string version, string account, byte[] key)
        {
            if (text == null || pinned == null) return null;
            text = text.Replace("\r", "");
            int at = text.IndexOf("\nsig=", StringComparison.Ordinal);
            if (!text.StartsWith(SessionHeader, StringComparison.Ordinal) || at < 0) return null;
            string signed = text.Substring(0, at + 1), sig = text.Substring(at + 5).Trim();
            var f = Fields(signed);
            if (!f.TryGetValue("issuer", out var iss) || iss != issuer) return null;
            if (!f.TryGetValue("id", out var tid) || tid != id || !f.TryGetValue("version", out var tv) || tv != version
                || !f.TryGetValue("account", out var ta) || ta != account) return null;
            if (!f.TryGetValue("issued", out var issued) || !long.TryParse(issued, out _)
                || !f.TryGetValue("expires", out var exp) || !long.TryParse(exp, out _)) return null;
            using (var sha = SHA256.Create())
                if (!f.TryGetValue("key_hash", out var kh) || kh != Hex(sha.ComputeHash(key))) return null;
            var modulus = Bytes(pinned);
            if (!System.Text.RegularExpressions.Regex.IsMatch(sig, "^[0-9a-fA-F]+$") || sig.Length != modulus.Length * 2) return null;
            using (var rsa = new RSACng())
            {
                rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = new byte[] { 1, 0, 1 } });
                if (!rsa.VerifyData(Encoding.UTF8.GetBytes(signed), Bytes(sig), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return null;
            }
            return f;
        }

        static byte[] TryBase64(string s)
        {
            try { return s == null ? null : Convert.FromBase64String(s); }
            catch (FormatException) { return null; }
        }

        static void CacheKey(string appData, string issuer, string id, string version, byte[] key, string account, string ticket)
        {
            var dir = SegmentsFolder(appData, issuer, id, version);
            Directory.CreateDirectory(dir);
            var record = Json.Write(new Dictionary<string, object>
            { ["k"] = Convert.ToBase64String(key), ["account"] = account, ["t"] = ticket });
            var prot = ProtectedData.Protect(Encoding.UTF8.GetBytes(record), KeyEntropy, DataProtectionScope.CurrentUser);
            var path = Path.Combine(dir, KeyCacheFile);
            var tmp = path + ".tmp";
            File.WriteAllBytes(tmp, prot);
            if (File.Exists(path)) File.Delete(path);
            File.Move(tmp, path);
        }

        /// <summary>The cached key while its signed ticket holds: the ticket's own expiry, and a clock
        /// no earlier than when the issuer signed it (a clock set back before that is not trusted:
        /// audit, 2026-11-19). A record without a good ticket opens nothing.</summary>
        static byte[] CachedKey(string home, string appData, string issuer, string id, string version, string account)
        {
            var path = Path.Combine(SegmentsFolder(appData, issuer, id, version), KeyCacheFile);
            if (!File.Exists(path)) return null;
            try
            {
                // DPAPI(CurrentUser): this fails on another machine or user, so a copied cache opens nothing
                var bytes = ProtectedData.Unprotect(File.ReadAllBytes(path), KeyEntropy, DataProtectionScope.CurrentUser);
                var d = Json.Parse(Encoding.UTF8.GetString(bytes)) as Dictionary<string, object>;
                if (Json.Str(d, "account") != account) return null;
                var key = TryBase64(Json.Str(d, "k"));
                if (key == null || key.Length != 32) return null;
                var f = VerifyTicket(Json.Str(d, "t"), issuer, PinnedKey(home, issuer), id, version, account, key);
                if (f == null) return null;
                long now = Now(), issued = long.Parse(f["issued"]), expires = long.Parse(f["expires"]);
                return now < expires && now >= issued - ClockSlack ? key : null;
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

        /// <summary>Removes the per-session plaintext (seg*.lua) from every version folder here whose
        /// plaintext is not a claim of its own: everything but a set whose receipt is a SEGMENTS 1
        /// (plaintext-era) receipt signed by the issuer's pinned key. A sealed set is known by that
        /// signed receipt, not by its seg*.enc being there: with the .enc deleted and "sealed" taken
        /// out of the mod, the plaintext used to be left for good (audit, 2026-11-19). The
        /// ciphertext, receipt and key cache stay.</summary>
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
                                var lua = Directory.GetFiles(ver, "seg*.lua");
                                if (lua.Length == 0 || PlaintextClaim(home, Path.GetFileName(iss), ver)) continue;
                                foreach (var f in lua) File.Delete(f);
                            }
                            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
                        }
        }

        /// <summary>Whether a version folder's receipt is a plaintext-era (SEGMENTS 1) receipt that
        /// the issuer named by the folder signed with the key pinned for it.</summary>
        static bool PlaintextClaim(string home, string issuerFolder, string ver)
        {
            var receipt = Path.Combine(ver, "receipt.txt");
            if (!File.Exists(receipt)) return false;
            var text = File.ReadAllText(receipt).Replace("\r", "");
            if (!text.StartsWith(SegmentsHeader, StringComparison.Ordinal)) return false;
            // the folder is the issuer's host with ':' made '_' (SegmentsRoot)
            foreach (var issuer in new[] { issuerFolder, issuerFolder.Replace('_', ':') }.Distinct())
            {
                var pinned = PinnedKey(home, issuer);
                if (pinned != null && VerifyReceipt(text, issuer, pinned) != null) return true;
            }
            return false;
        }

        static IEnumerable<string> SafeDirs(string dir)
        {
            try { return Directory.GetDirectories(dir); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return Enumerable.Empty<string>(); }
        }
    }
}
