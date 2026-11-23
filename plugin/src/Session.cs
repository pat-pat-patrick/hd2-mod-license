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
                if (gameTimer == null)
                {
                    RetireOlderCopies(host);
                    gameTimer = new Timer(_ => GameTick(), null, 0, 5000);
                }
            }
        }

        /// <summary>(1.11.5) A plugin added while the manager is open is loaded beside the copy that
        /// was already there, which .NET Framework cannot unload: both watched the game, unlocked and
        /// removed the same files, and logged every game start and stop twice (a player's log,
        /// 2026-11-21). The copy loaded last stops the older ones' game watch and their retry of
        /// pending content; they keep answering the window until the manager restarts.</summary>
        public static void RetireOlderCopies(Dictionary<string, object> host)
        {
            var mine = typeof(Plugin).Assembly;
            var name = mine.GetName().Name;
            const System.Reflection.BindingFlags all = System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public;
            foreach (var other in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (ReferenceEquals(other, mine) || other.GetName().Name != name) continue;
                try
                {
                    var t = other.GetType(typeof(Plugin).FullName);
                    if (t == null) continue;
                    bool stopped = false;
                    // its tick returns at once without a host; then its timers go
                    t.GetField("gameHost", all)?.SetValue(null, null);
                    foreach (var field in new[] { "gameTimer", "pendingTimer" })
                    {
                        var f = t.GetField(field, all);
                        if (f?.GetValue(null) is IDisposable timer) { timer.Dispose(); f.SetValue(null, null); stopped = true; }
                    }
                    if (stopped) Log(Home(host), null, "an older copy of this plugin (" + other.GetName().Version + "), loaded before this one, stopped watching the game");
                }
                catch (Exception e) when (e is System.Reflection.TargetException || e is ArgumentException || e is FieldAccessException || e is MemberAccessException || e is TypeLoadException) { }
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

        /// <summary>(1.11.5) A game start, in three passes, so the plaintext is there before the
        /// mods load (2026-11-21: a mod reads its member content once, about 10 s after the game
        /// starts; a player whose requests to the issuer took 20 s and more, with the 1.11.3 retries
        /// up to a minute, got it after that and the mod stayed quiet all game):
        /// 1. every mod whose key is kept here within its grace is unlocked from that key, with no request;
        /// 2. the mods the first pass could not open ask the issuer, as before (retries and all);
        /// 3. the mods the first pass opened ask once each, with no retry, to renew the kept key and
        ///    see whether the author replaced the content (a replaced payload is fetched and unlocked again).
        /// The grace and every check are the same as before: a refused or unreachable request already
        /// fell back to the kept key, so taking it first lets nothing through that was kept out.</summary>
        public static bool OnGameStart(Dictionary<string, object> host, bool late)
        {
            bool any = false;
            string home = Home(host), appData = AppData(host);
            var opened = new HashSet<string>(StringComparer.OrdinalIgnoreCase);    // "seg|<folder>", "pay|<folder>"
            int sealedCount;
            lock (segmentsLock)
            {
                any |= UnlockSegments(host, late, opened, Pass.Kept).Any;
                any |= UnlockPayloads(host, late, opened, Pass.Kept).Any;
            }
            lock (segmentsLock)
            {
                var (segAny, segSeen) = UnlockSegments(host, late, opened, Pass.Online);
                any |= segAny;
                sealedCount = segSeen;
                any |= UnlockPayloads(host, late, opened, Pass.Online).Any;
            }
            lock (segmentsLock)
            {
                oneTry = true;
                try
                {
                    UnlockSegments(host, late, opened, Pass.Renew);
                    UnlockPayloads(host, late, opened, Pass.Renew);
                }
                finally { oneTry = false; }
                // (1.10.0) the payloads: a mod with both is counted once
                sealedCount += LibraryOf(host).Count(m => Json.Str(m, "path") is string p && Directory.Exists(p)
                    && PayloadOf(p) is Dictionary<string, object> pay && Json.Str(pay, "error") == null && !GameForm(pay) && !Json.Bool(SegmentsOf(p), "sealed"));
            }
            // (1.9.0) every game start, so a log tells a game this program saw from one it never saw
            Log(home, null, (late ? "the game was already running at this program's start" : "game started") + ": " + sealedCount + " mod(s) with sealed member content in the library");
            return any;
        }

        /// <summary>(1.11.5) The passes of a game start (OnGameStart).</summary>
        enum Pass { Kept, Online, Renew }

        /// <summary>(1.11.5) One pass over the library's sealed segments. Kept: unlock from the key
        /// kept here, no request. Online: the mods Kept did not open, the issuer asked (else the kept
        /// key, as before 1.11.5). Renew: the mods Kept opened, asked once to renew the kept key, and
        /// decrypted again only if their plaintext went. Any: a set was decrypted; Seen: the
        /// library's sealed mods, for the game-start line.</summary>
        static (bool Any, int Seen) UnlockSegments(Dictionary<string, object> host, bool late, HashSet<string> opened, Pass pass)
        {
            bool any = false;
            string home = Home(host), appData = AppData(host);
            int seen = 0;
            foreach (var m in LibraryOf(host))
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path)) continue;
                var seg = SegmentsOf(path);
                if (seg == null || Json.Str(seg, "error") != null || !Json.Bool(seg, "sealed")) continue;
                var decl = Declaration(path);
                if (decl == null || Json.Str(decl, "error") != null) continue;
                seen++;
                bool wasOpened = opened.Contains("seg|" + path);
                if (pass == Pass.Online && wasOpened || pass == Pass.Renew && !wasOpened) continue;
                string issuer = Json.Str(decl, "issuer");
                try
                {
                    var held = HeldAccount(appData, decl, seg);
                    if (held == null)
                    {
                        // no resident ciphertext to open: said, so a log shows why the mod stayed quiet (1.9.0)
                        if (pass == Pass.Online) Log(home, issuer, SegLabel(path, seg) + ": nothing to unlock (no member content downloaded here for an account of this computer)");
                        continue;
                    }
                    byte[] fkey;
                    byte[] key = pass == Pass.Kept
                        ? CachedKey(home, appData, issuer, Json.Str(seg, "id"), Json.Str(seg, "version"), held, out fkey)
                        : SessionKey(home, appData, decl, seg, held, out fkey);
                    if (key == null)
                    {
                        if (pass == Pass.Online) { SetLastUnlock(path, "no_key"); Log(home, issuer, SegLabel(path, seg) + ": sealed (no session key: offline past grace, or another computer)"); }
                        continue;
                    }
                    // Renew: the key is renewed (SessionKey keeps it); the plaintext written in the
                    // first pass stays, unless it went
                    // (1.13.0) and the chunk key written in the first pass is not written again:
                    // the mod deletes it once read, and it must not come back during the game
                    if (pass == Pass.Renew && PlainPresent(appData, decl, seg)) { Array.Clear(key, 0, key.Length); if (fkey != null) Array.Clear(fkey, 0, fkey.Length); continue; }
                    bool done = DecryptPlain(appData, decl, seg, key);
                    if (done) WriteChunkKey(appData, decl, seg, fkey);
                    if (fkey != null) Array.Clear(fkey, 0, fkey.Length);
                    if (done)
                    {
                        any = true;
                        opened.Add("seg|" + path);
                        SetLastUnlock(path, late ? "late" : null);
                        Log(home, issuer, SegLabel(path, seg) + (late ? ": decrypted, but the game started before this program: unlocked from the next game"
                                                                       : pass == Pass.Kept ? ": decrypted for this session from the key kept here" : ": decrypted for this session") + " (account " + held + ")");
                    }
                    else if (pass != Pass.Kept) Log(home, issuer, SegLabel(path, seg) + ": the content did not decrypt to what the receipt signs (sealed)");
                    Array.Clear(key, 0, key.Length);
                }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException)
                { Log(home, issuer, SegLabel(path, seg) + ": " + e.GetType().Name); }
            }
            return (any, seen);
        }

        /// <summary>(1.11.5) Whether a sealed version's seg*.lua are all there (written this game).</summary>
        static bool PlainPresent(string appData, Dictionary<string, object> decl, Dictionary<string, object> seg)
        {
            var dir = SegmentsFolder(appData, Json.Str(decl, "issuer"), Json.Str(seg, "id"), Json.Str(seg, "version"));
            int n = (int)Json.Long(seg, "count");
            for (int i = 1; i <= n; i++) if (!File.Exists(Path.Combine(dir, "seg" + i + ".lua"))) return false;
            return true;
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
            var key = SessionKey(home, appData, decl, seg, account, out var fkey);
            if (fkey != null) Array.Clear(fkey, 0, fkey.Length);
            return key;
        }

        /// <summary>(1.13.0) K_v, and the version's chunk key K_F when the issuer has one (keyed
        /// gate: hd2_diag\mod_licensing\DESIGN_keyed_gate.zh-CN.md, X). K_F comes only from /session,
        /// to an account bound to the member, and is kept with K_v under the same signed ticket,
        /// which names it (fkey_hash). One the ticket does not name is not used.</summary>
        static byte[] SessionKey(string home, string appData, Dictionary<string, object> decl, Dictionary<string, object> seg, string account, out byte[] fkey)
        {
            fkey = null;
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
                byte[] f = TryBase64(Json.Str(body, "fkey"));
                if (f != null && f.Length != 32) f = null;
                var fields = ticket == null ? null : VerifyTicket(ticket, issuer, PinnedKey(home, issuer), id, version, account, key, f);
                if (fields == null && f != null && ticket != null
                    && VerifyTicket(ticket, issuer, PinnedKey(home, issuer), id, version, account, key) != null)
                {
                    f = null;                                    // a chunk key the signed ticket does not name: not used
                    fields = VerifyTicket(ticket, issuer, PinnedKey(home, issuer), id, version, account, key);
                }
                if (fields != null) CacheKey(appData, issuer, id, version, key, account, ticket, f);
                fkey = f;
                return key;
            }
            return CachedKey(home, appData, issuer, id, version, account, out fkey);
        }

        /// <summary>(1.13.0) The file the mod's shell reads the chunk key from, once, and deletes.</summary>
        const string ChunkKeyFile = "fkey.txt";

        /// <summary>(1.13.0) After a decrypt: the chunk key, as hex, beside the plaintext segments,
        /// written whole through a temporary name; a version with none leaves no old one behind.
        /// The mod's shell reads it at load and deletes it, and the game's stop removes it too, so
        /// it is on disk only from the game's start until the mod has loaded.</summary>
        static void WriteChunkKey(string appData, Dictionary<string, object> decl, Dictionary<string, object> seg, byte[] fkey)
        {
            var dir = SegmentsFolder(appData, Json.Str(decl, "issuer"), Json.Str(seg, "id"), Json.Str(seg, "version"));
            var path = Path.Combine(dir, ChunkKeyFile);
            if (fkey == null) { if (File.Exists(path)) File.Delete(path); return; }
            var tmp = path + ".new-" + Hex(Random(4));
            File.WriteAllText(tmp, Hex(fkey), new UTF8Encoding(false));
            if (File.Exists(path)) File.Delete(path);
            File.Move(tmp, path);
        }

        const string SessionHeader = "HD2 MOD SESSION 1\n";
        // the local clock may be this much behind the issuer's and a ticket still counts (seconds)
        const long ClockSlack = 600;

        /// <summary>The key the member signed in with pinned for this issuer (the one claims check).</summary>
        static string PinnedKey(string home, string issuer) => Json.Str(IssuerRecord(home, issuer), "key");

        /// <summary>The fields of an issuer's session ticket (POST /session) when it is signed by the
        /// pinned key and names this id, version, account and the key it came with; else null.</summary>
        static Dictionary<string, string> VerifyTicket(string text, string issuer, string pinned, string id, string version, string account, byte[] key, byte[] fkey = null)
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
            {
                if (!f.TryGetValue("key_hash", out var kh) || kh != Hex(sha.ComputeHash(key))) return null;
                // (1.13.0) a chunk key counts only as the one the ticket names
                if (fkey != null && (!f.TryGetValue("fkey_hash", out var fh) || fh != Hex(sha.ComputeHash(fkey)))) return null;
            }
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

        static void CacheKey(string appData, string issuer, string id, string version, byte[] key, string account, string ticket, byte[] fkey = null)
        {
            var dir = SegmentsFolder(appData, issuer, id, version);
            Directory.CreateDirectory(dir);
            var rec = new Dictionary<string, object> { ["k"] = Convert.ToBase64String(key), ["account"] = account, ["t"] = ticket };
            if (fkey != null) rec["f"] = Convert.ToBase64String(fkey);
            var record = Json.Write(rec);
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
            var key = CachedKey(home, appData, issuer, id, version, account, out var fkey);
            if (fkey != null) Array.Clear(fkey, 0, fkey.Length);
            return key;
        }

        static byte[] CachedKey(string home, string appData, string issuer, string id, string version, string account, out byte[] fkey)
        {
            fkey = null;
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
                if (!(now < expires && now >= issued - ClockSlack)) return null;
                // (1.13.0) the chunk key kept with it, if the same signed ticket names it
                var fk = TryBase64(Json.Str(d, "f"));
                if (fk != null && fk.Length == 32 && VerifyTicket(Json.Str(d, "t"), issuer, PinnedKey(home, issuer), id, version, account, key, fk) != null)
                    fkey = fk;
                return key;
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
                                // (1.13.0) a chunk key the mod did not read (or its half-written copy) goes in every case
                                foreach (var k in Directory.GetFiles(ver, ChunkKeyFile + "*")) File.Delete(k);
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
