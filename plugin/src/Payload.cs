using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Hd2Qd.License
{
    /// <summary>(1.10.0) A mod's payload (spec/static-resources.zh-CN.md, draft 2): data too big for
    /// the Lua segments (Super Callouts' 19 MB of recordings), fetched sealed from the issuer.
    /// A mod whose hd2_license.json has "payload": {kind: "static", id, version?, deploy} ships none
    /// of that data; this asks POST /payload with a member's renew token for a link, the content key
    /// K_c and a signed RECEIPT 2, downloads the sealed bytes, checks them against the receipt
    /// (sealed_hash before any key, plain_hash after decrypting, key_hash for the key), and keeps
    ///   licenses\&lt;issuer&gt;\payload\&lt;id&gt;\&lt;version or _&gt;\payload.seal, receipt.txt, key.dpapi
    /// The one deploy form is "licenses/&lt;file&gt;": the plaintext is written to &lt;file&gt; in that
    /// folder while the game runs, for the mod's own shell to read, and removed when it stops: the
    /// same per-session handling as a sealed (C1) version's segments (Session.cs). K_c is kept
    /// machine-bound (DPAPI) only until the receipt's signed expires.
    ///
    /// AES-256-CBC/PKCS7, sealed = IV(16) ‖ ciphertext: .NET Framework 4.8 has no AES-GCM, and the
    /// two signed hashes give what a tag would (CONTRACT_sealed_lua section 12.3).</summary>
    public static partial class Plugin
    {
        const string PayloadHeader2 = "HD2 PAYLOAD RECEIPT 2\n";
        const string SealFile = "payload.seal";
        static readonly Regex DeployLicenses = new Regex(@"^licenses/([A-Za-z0-9._-]{1,64})\z");
        static readonly HashSet<string> PayloadResident = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { SealFile, "receipt.txt", KeyCacheFile };
        // (1.11.0) a fingerprinted payload's parts, part1.seal .. partN.seal, also resident
        static readonly Regex PartFile = new Regex(@"^part\d{1,2}\.seal\z", RegexOptions.IgnoreCase);

        /// <summary>(1.11.0) N for a fingerprinted payload's receipt (parts=N: the account's variant of
        /// each of N parts), 0 for one whole package.</summary>
        static int PartsOf(Dictionary<string, string> f) =>
            f.TryGetValue("parts", out var n) && int.TryParse(n, out var k) && k >= 1 && k <= 64 ? k : 0;

        static List<string> SealNames(int parts) =>
            parts == 0 ? new List<string> { SealFile } : Enumerable.Range(1, parts).Select(i => "part" + i + ".seal").ToList();

        /// <summary>The hash a receipt signs for these pieces: of the one package, or (parts) of the
        /// pieces' SHA-256 (hex) joined in order.</summary>
        static string JoinedHash(List<byte[]> pieces, int parts) =>
            parts == 0 ? Sha256Bytes(pieces[0]) : Utf8Sha256(string.Concat(pieces.Select(Sha256Bytes)));

        /// <summary>Every piece decrypted and joined, when the plaintext is what plain_hash signs; else null.</summary>
        static byte[] OpenPieces(byte[] key, List<byte[]> pieces, int parts, string plainHash)
        {
            var plains = new List<byte[]>();
            foreach (var p in pieces)
            {
                var plain = DecryptSeal(key, p);
                if (plain == null) return null;
                plains.Add(plain);
            }
            if (JoinedHash(plains, parts) != plainHash) return null;
            var all = new byte[plains.Sum(p => p.Length)];
            int at = 0;
            foreach (var p in plains) { Buffer.BlockCopy(p, 0, all, at, p.Length); at += p.Length; Array.Clear(p, 0, p.Length); }
            return all;
        }

        /// <summary>The resident pieces the receipt names (null when one is missing).</summary>
        static List<byte[]> ReadPieces(string dir, int parts)
        {
            var list = new List<byte[]>();
            foreach (var name in SealNames(parts))
            {
                var path = Path.Combine(dir, name);
                if (!File.Exists(path)) return null;
                list.Add(File.ReadAllBytes(path));
            }
            return list;
        }
        // a separate DPAPI label from the segments' key cache: neither ever opens the other's record
        static readonly byte[] PayloadEntropy = Encoding.ASCII.GetBytes("hd2qd-license-payload-1");
        /// <summary>The largest sealed package taken (the issuer's R2 object; Super Callouts' is ~20 MB).</summary>
        const long PayloadMax = 256L * 1024 * 1024;
        static readonly HttpClient Download = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };

        /// <summary>{id, version (or null), wire (the id sent to the issuer: id, or id.version), file}
        /// for a mod that declares a payload; null for one that does not; {error}: "bad_declaration",
        /// or "update_manager" for a deploy form this plugin does not know (spec section 2: never
        /// treated as nothing to fetch).</summary>
        public static Dictionary<string, object> PayloadOf(string modFolder)
        {
            Dictionary<string, object> d;
            try
            {
                var path = Path.Combine(modFolder, FileName);
                if (!File.Exists(path)) return null;
                d = Json.Parse(File.ReadAllText(path)) as Dictionary<string, object>;
            }
            catch (Exception e) when (e is FormatException || e is IOException || e is UnauthorizedAccessException) { return null; }
            var p = Json.Obj(d, "payload");
            if (p == null) return null;
            var id = Json.Str(p, "id");
            if (Json.Str(p, "kind") != "static" || id == null || !PayloadId.IsMatch(id)) return Err("bad_declaration");
            string version = null;
            if (p.ContainsKey("version"))
            {
                version = Json.Str(p, "version");
                if (version == null || !WholeVersion.IsMatch(version)) return Err("bad_declaration");
            }
            var wire = version == null ? id : id + "." + version;
            if (!PayloadId.IsMatch(wire)) return Err("bad_declaration");
            var m = DeployLicenses.Match(Json.Str(p, "deploy") ?? "");
            if (!m.Success) return Err("update_manager");
            return new Dictionary<string, object> { ["id"] = id, ["version"] = version, ["wire"] = wire, ["file"] = m.Groups[1].Value };
        }

        static string PayloadRoot(string appData, string issuer, string id) =>
            Path.Combine(LicenseDir(appData), issuer.Replace(':', '_'), "payload", id);

        /// <summary>The folder a payload lives in, and its shell reads the plaintext from.</summary>
        public static string PayloadFolder(string appData, string issuer, Dictionary<string, object> pay) =>
            Path.Combine(PayloadRoot(appData, issuer, Json.Str(pay, "id")), Json.Str(pay, "version") ?? "_");

        /// <summary>The fields of a RECEIPT 2 signed by key for issuer, with alg A256CBC; else null.</summary>
        static Dictionary<string, string> VerifyPayloadReceipt(string text, string issuer, string key)
        {
            if (text == null || key == null) return null;
            text = text.Replace("\r", "");
            int at = text.IndexOf("\nsig=", StringComparison.Ordinal);
            if (!text.StartsWith(PayloadHeader2, StringComparison.Ordinal) || at < 0) return null;
            string signed = text.Substring(0, at + 1), sig = text.Substring(at + 5).Trim();
            var f = Fields(signed);
            if (!f.TryGetValue("issuer", out var iss) || iss != issuer) return null;
            if (!f.TryGetValue("alg", out var alg) || alg != "A256CBC") return null;
            foreach (var h in new[] { "sealed_hash", "plain_hash", "key_hash" })
                if (!f.TryGetValue(h, out var v) || !Regex.IsMatch(v, "^[0-9a-f]{64}\\z")) return null;
            if (!f.TryGetValue("issued", out var issued) || !long.TryParse(issued, out _)
                || !f.TryGetValue("expires", out var exp) || !long.TryParse(exp, out _)) return null;
            if (f.ContainsKey("parts") && PartsOf(f) == 0) return null;       // (1.11.0) a parts= line, but no count
            var modulus = Bytes(key);
            if (!Regex.IsMatch(sig, "^[0-9a-fA-F]+$") || sig.Length != modulus.Length * 2) return null;
            using (var rsa = new RSACng())
            {
                rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = new byte[] { 1, 0, 1 } });
                if (!rsa.VerifyData(Encoding.UTF8.GetBytes(signed), Bytes(sig), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return null;
            }
            return f;
        }

        static string Sha256Bytes(byte[] b)
        {
            using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(b));
        }

        /// <summary>The account a good resident package here was sent for: the receipt verifies with
        /// the mod's key, names this wire id, and payload.seal is the bytes it signs. Null otherwise.
        /// Checked offline, without the key.</summary>
        public static string PayloadHeld(string appData, Dictionary<string, object> decl, Dictionary<string, object> pay)
        {
            string issuer = Json.Str(decl, "issuer"), key = Json.Str(decl, "key");
            var dir = PayloadFolder(appData, issuer, pay);
            try
            {
                var receipt = new FileInfo(Path.Combine(dir, "receipt.txt"));
                if (!receipt.Exists) return null;
                // the rows ask on every redraw: 20 MB is hashed again only when a file changed
                // (the package, or since 1.11.0 a fingerprinted payload's parts)
                var stamp = new StringBuilder(key).Append('|').Append(receipt.LastWriteTimeUtc.Ticks).Append(':').Append(receipt.Length);
                foreach (var fi in new DirectoryInfo(dir).GetFiles().Where(x => x.Name == SealFile || PartFile.IsMatch(x.Name)).OrderBy(x => x.Name, StringComparer.Ordinal))
                    stamp.Append('|').Append(fi.Name).Append(':').Append(fi.LastWriteTimeUtc.Ticks).Append(':').Append(fi.Length);
                lock (heldCache)
                    if (heldCache.TryGetValue(dir, out var c) && c.Stamp == stamp.ToString()) return c.Account;
                var f = VerifyPayloadReceipt(File.ReadAllText(receipt.FullName), issuer, key);
                string account = null;
                var pieces = f == null ? null : ReadPieces(dir, PartsOf(f));
                if (f != null && pieces != null && f.TryGetValue("id", out var rid) && rid == Json.Str(pay, "wire")
                    && f["sealed_hash"] == JoinedHash(pieces, PartsOf(f)) && f.TryGetValue("account", out var a)) account = a;
                var stampText = stamp.ToString();
                lock (heldCache) heldCache[dir] = (stampText, account);
                return account;
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException) { return null; }
        }

        static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> lastPayload =
            new System.Collections.Concurrent.ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>"claimed", "pending", "not_signed_in", "missing", the last fetch's error, or the
        /// declaration's ("bad_declaration", "update_manager"). Null for a mod with no payload.</summary>
        public static string PayloadState(string home, string appData, string modFolder)
        {
            var pay = PayloadOf(modFolder);
            if (pay == null) return null;
            if (Json.Str(pay, "error") != null) return Json.Str(pay, "error");
            var decl = Declaration(modFolder);
            if (decl == null || Json.Str(decl, "error") != null) return null;
            if (PayloadHeld(appData, decl, pay) != null) return "claimed";
            return lastPayload.TryGetValue(modFolder, out var last) && last != "claimed" ? last : "missing";
        }

        /// <summary>Fetches one mod's payload when this computer holds no good package for it (or
        /// force): {claimed: true, account} | {claimed: false, why: "held"|"not_signed_in"} | {error}:
        /// "payload_pending", "bad_receipt", "network", the issuer's refusal, a declaration error.</summary>
        public static Dictionary<string, object> ClaimPayload(string home, string appData, string modFolder, bool force = false)
        {
            Dictionary<string, object> r;
            try { lock (segmentsLock) r = ClaimPayloadOne(home, appData, modFolder, force); }
            finally { percent.TryRemove(modFolder, out _); }
            var pay = PayloadOf(modFolder);
            string what = Json.Str(r, "error") ?? (Json.Bool(r, "claimed") ? "claimed" : Json.Str(r, "why"));
            if (what == "payload_pending") what = "pending";
            if (what != null) lastPayload[modFolder] = what == "held" ? "claimed" : what;
            if (Json.Str(r, "why") != "held")
                Log(home, IssuerOf(modFolder), PayLabel(modFolder, pay) + ": " + what + (Json.Str(r, "account") is string a ? " (account " + a + ")" : ""));
            return r;
        }

        static string PayLabel(string modFolder, Dictionary<string, object> pay) =>
            Path.GetFileName(modFolder.TrimEnd('\\', '/')) + " payload " + (Json.Str(pay, "wire") ?? Json.Str(pay, "error"));

        static Dictionary<string, object> ClaimPayloadOne(string home, string appData, string modFolder, bool force)
        {
            var decl = Declaration(modFolder);
            if (decl == null || Json.Str(decl, "error") != null) return Err("bad_declaration");
            var pay = PayloadOf(modFolder);
            if (pay == null) return Err("bad_declaration");
            if (Json.Str(pay, "error") != null) return pay;
            var bound = BoundAccounts(home, appData, decl);
            if (bound.Count == 0) return new Dictionary<string, object> { ["claimed"] = false, ["why"] = "not_signed_in" };
            var held = PayloadHeld(appData, decl, pay);
            if (!force && held != null && bound.Any(b => b.Account == held))
                return new Dictionary<string, object> { ["claimed"] = false, ["why"] = "held", ["account"] = held };

            string error = null;
            foreach (var (account, tokens) in bound)
                foreach (var token in tokens)
                {
                    var got = FetchPayload(home, decl, pay, account, token, true, f => Progress(modFolder, f));
                    if (got.Error == "payload_pending" || got.Error == "network") return Err(got.Error);
                    if (got.Error != null) { error = error ?? got.Error; continue; }
                    WritePayload(appData, Json.Str(decl, "issuer"), pay, got.Sealed, got.Receipt, PartsOf(got.Fields));
                    CachePayloadKey(appData, Json.Str(decl, "issuer"), pay, got.Key, account, got.Receipt);
                    Array.Clear(got.Key, 0, got.Key.Length);
                    return new Dictionary<string, object> { ["claimed"] = true, ["account"] = account };
                }
            return Err(error ?? "unknown");
        }

        /// <summary>(1.11.4) How far each mod's member content download is, 0-99, while it runs
        /// (the user, 2026-11-21: players took a download in progress for one that had stopped).
        /// Parts are of about one size, so a part counts as an equal share.</summary>
        static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> percent =
            new System.Collections.Concurrent.ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        /// <summary>The download's percentage for a mod folder, or null when none is running.</summary>
        public static int? PercentOf(string modFolder) => percent.TryGetValue(modFolder, out var p) ? p : (int?)null;

        static void Progress(string modFolder, double done)
        {
            int p = Math.Max(0, Math.Min(99, (int)(done * 100)));
            int old = percent.TryGetValue(modFolder, out var o) ? o : -1;
            if (p == old) return;
            percent[modFolder] = p;
            // the card's line follows by itself (Panel's live lines); the mod's row only when the
            // window is drawn, which reads the whole state: so at 25, 50 and 75 % only
            if (old >= 0 && p / 25 > old / 25) RedrawWindow();
        }

        sealed class Fetched
        {
            public string Error, Receipt;
            public Dictionary<string, string> Fields;
            public byte[] Key;
            /// <summary>The sealed bytes: one package, or (1.11.0) the account's parts in order.</summary>
            public List<byte[]> Sealed;
        }

        /// <summary>POST /payload for one account and token; with download, also the sealed bytes,
        /// checked against the receipt and decrypted once to prove key and plaintext. Error: the
        /// issuer's refusal, "payload_pending", "network", "bad_receipt". (1.11.0) The request says
        /// parts=1: this plugin puts a fingerprinted payload's parts together (an older one is told
        /// to update); the answer then lists the parts, {url, hash} each, instead of one url.</summary>
        static Fetched FetchPayload(string home, Dictionary<string, object> decl, Dictionary<string, object> pay, string account, string token, bool download,
                                    Action<double> progress = null)
        {
            string issuer = Json.Str(decl, "issuer"), wire = Json.Str(pay, "wire");
            var (status, body) = Post(home, issuer, "/payload", new Dictionary<string, object> { ["id"] = wire, ["account"] = account, ["renew"] = token, ["parts"] = 1 });
            if (status == 409) return new Fetched { Error = Json.Str(body, "error") ?? "payload_pending" };
            if (status == 403 || status == 404) return new Fetched { Error = Json.Str(body, "error") ?? "unknown" };
            if (status != 200) return new Fetched { Error = "network" };
            var receipt = Json.Str(body, "receipt");
            var f = VerifyPayloadReceipt(receipt, issuer, Json.Str(decl, "key"));
            var keyHex = Json.Str(body, "key") ?? "";
            if (f == null || !f.TryGetValue("id", out var rid) || rid != wire || !f.TryGetValue("account", out var ra) || ra != account
                || !Regex.IsMatch(keyHex, "^[0-9a-f]{64}\\z"))
                return new Fetched { Error = "bad_receipt" };
            // what to download: one url and its hash, or the parts the receipt counts, whose hashes
            // joined in order are the signed sealed_hash
            int parts = PartsOf(f);
            var links = new List<(string Url, string Hash)>();
            if (parts == 0)
            {
                if (Json.Str(body, "hash") != f["sealed_hash"]) return new Fetched { Error = "bad_receipt" };
                links.Add((Json.Str(body, "url") ?? "", f["sealed_hash"]));
            }
            else
            {
                var list = (Json.List(body, "parts") ?? new List<object>()).OfType<Dictionary<string, object>>().ToList();
                if (list.Count != parts) return new Fetched { Error = "bad_receipt" };
                foreach (var p in list) links.Add((Json.Str(p, "url") ?? "", Json.Str(p, "hash") ?? ""));
                if (links.Any(l => !Regex.IsMatch(l.Hash, "^[0-9a-f]{64}\\z")) || Utf8Sha256(string.Concat(links.Select(l => l.Hash))) != f["sealed_hash"])
                    return new Fetched { Error = "bad_receipt" };
            }
            var key = Bytes(keyHex);
            if (Sha256Bytes(key) != f["key_hash"]) return new Fetched { Error = "bad_receipt" };
            var got = new Fetched { Receipt = receipt.Replace("\r", ""), Fields = f, Key = key };
            if (!download) return got;

            var pieces = new List<byte[]>();
            int fresh = 0;
            for (int i = 0; i < links.Count; i++)
            {
                byte[] bytes = null;
                // (1.11.3) a download cut off or stalled is started again, twice, as Post retries a
                // request; a link that ran out (the issuer's links last 10 minutes, all handed out at
                // once, and a slow line did not get through 20 MB in that time) is asked for again
                for (int attempt = 0; ; attempt++)
                {
                    var (url, hash) = links[i];
                    // the link comes from the issuer itself (same scheme and host), never another site
                    if (!url.StartsWith(Base(issuer) + "/", StringComparison.Ordinal)) return new Fetched { Error = "bad_receipt" };
                    int at = i, of = links.Count;
                    try { bytes = GetBytes(home, issuer, url, part => progress?.Invoke((at + part) / of)); break; }
                    catch (LinkExpired)
                    {
                        if (fresh++ >= 2) return new Fetched { Error = "network" };
                        var again = FreshLinks(home, issuer, wire, account, token, parts);
                        // the same parts of the same signed receipt, only new links: else nothing
                        if (again == null || again.Count != links.Count || again.Where((l, n) => l.Hash != links[n].Hash).Any())
                            return new Fetched { Error = "network" };
                        links = again;
                        attempt--;                          // a new link is no retry
                    }
                    catch (Exception e) when (e is HttpRequestException || e is TaskCanceledException || e is IOException)
                    {
                        Log(home, issuer, "GET /payload/blob: " + e.GetType().Name + " " + e.Message);
                        if (attempt >= RetryDelaysMs.Length) return new Fetched { Error = "network" };
                        if (RetryDelaysMs[attempt] > 0) System.Threading.Thread.Sleep(RetryDelaysMs[attempt]);
                    }
                    catch (InvalidDataException e)
                    {
                        Log(home, issuer, "GET /payload/blob: " + e.GetType().Name + " " + e.Message);
                        return new Fetched { Error = "network" };
                    }
                }
                if (bytes == null) return new Fetched { Error = "network" };
                if (Sha256Bytes(bytes) != links[i].Hash) return new Fetched { Error = "bad_receipt" };
                pieces.Add(bytes);
            }
            var plain = OpenPieces(key, pieces, parts, f["plain_hash"]);
            if (plain == null) return new Fetched { Error = "bad_receipt" };
            Array.Clear(plain, 0, plain.Length);
            got.Sealed = pieces;
            return got;
        }

        /// <summary>(1.11.3) The issuer refused a download link (403): it ran out.</summary>
        sealed class LinkExpired : Exception { }

        /// <summary>(1.11.3) New links for the same payload: /payload asked again. Null when it
        /// gives none; the caller keeps them only when their hashes are the ones already checked.</summary>
        static List<(string Url, string Hash)> FreshLinks(string home, string issuer, string wire, string account, string token, int parts)
        {
            var (status, body) = Post(home, issuer, "/payload", new Dictionary<string, object> { ["id"] = wire, ["account"] = account, ["renew"] = token, ["parts"] = 1 });
            if (status != 200) return null;
            if (parts == 0) return new List<(string, string)> { (Json.Str(body, "url") ?? "", Json.Str(body, "hash") ?? "") };
            return (Json.List(body, "parts") ?? new List<object>()).OfType<Dictionary<string, object>>()
                .Select(p => (Json.Str(p, "url") ?? "", Json.Str(p, "hash") ?? "")).ToList();
        }

        /// <summary>(1.11.3) How long a download may go without a byte before it counts as cut off
        /// (2026-11-21: a player's first 2.4 MB part had not arrived in 6 minutes and the card said
        /// "downloading" until the manager was restarted). Tests set it lower.</summary>
        public static int StallMs = 30000;

        /// <summary>The sealed bytes from the issuer's short-lived link (null on a non-200 other than
        /// 403, which throws LinkExpired). No byte for StallMs, while waiting for the answer or
        /// during it, throws IOException: the caller starts it again.</summary>
        static byte[] GetBytes(string home, string issuer, string url, Action<double> progress = null)
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            using (var request = new HttpRequestMessage(HttpMethod.Get, url))
            {
                request.Headers.TryAddWithoutValidation("X-HD2QD-License", PluginVersion);
                HttpResponseMessage answer;
                using (var head = new System.Threading.CancellationTokenSource(StallMs))
                {
                    try { answer = Download.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, head.Token).GetAwaiter().GetResult(); }
                    catch (OperationCanceledException) { throw new IOException("no answer in " + StallMs / 1000.0 + " s"); }
                }
                using (var r = answer)
                {
                    if ((int)r.StatusCode == 403)
                    {
                        Log(home, issuer, "GET /payload/blob -> 403 (the link ran out)");
                        throw new LinkExpired();
                    }
                    if ((int)r.StatusCode != 200)
                    {
                        Log(home, issuer, "GET /payload/blob -> " + (int)r.StatusCode);
                        return null;
                    }
                    if (r.Content.Headers.ContentLength > PayloadMax) throw new InvalidDataException("larger than " + PayloadMax + " bytes");
                    using (var s = r.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                    using (var ms = new MemoryStream())
                    {
                        var buf = new byte[81920];
                        int n;
                        while ((n = ReadOrStall(s, buf, r, ms.Length)) > 0)
                        {
                            ms.Write(buf, 0, n);
                            // (1.11.4) how far this part is, by the length the answer gave
                            if (r.Content.Headers.ContentLength is long whole && whole > 0) progress?.Invoke(Math.Min(1.0, ms.Length / (double)whole));
                            if (ms.Length > PayloadMax) throw new InvalidDataException("larger than " + PayloadMax + " bytes");
                        }
                        Log(home, issuer, "GET /payload/blob -> 200, " + ms.Length + " bytes in " + clock.ElapsedMilliseconds + " ms");
                        return ms.ToArray();
                    }
                }
            }
        }

        /// <summary>(1.11.3) One read of a download, given StallMs: none in that time closes the
        /// connection and throws IOException (a stalled read would otherwise wait forever, since
        /// HttpClient's own timeout ends when the answer's headers arrive).</summary>
        static int ReadOrStall(Stream s, byte[] buf, HttpResponseMessage r, long have)
        {
            var read = s.ReadAsync(buf, 0, buf.Length);
            try { if (read.Wait(StallMs)) return read.Result; }
            catch (AggregateException e)
            {
                var inner = e.InnerException;
                throw inner as IOException ?? new IOException(inner?.Message ?? "read failed", inner);
            }
            read.ContinueWith(t => { var _ = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);   // its error, once the close ends it
            try { s.Dispose(); r.Dispose(); } catch (Exception) { }
            throw new IOException("no data for " + StallMs / 1000.0 + " s after " + have + " bytes");
        }

        /// <summary>AES-256-CBC/PKCS7 of sealed = IV(16) ‖ ciphertext; null when it is no package or
        /// the padding is wrong (most wrong keys; plain_hash catches the rest).</summary>
        static byte[] DecryptSeal(byte[] key, byte[] sealedBytes)
        {
            if (sealedBytes.Length <= 16 || (sealedBytes.Length - 16) % 16 != 0) return null;
            try { return AesCbcDecrypt(key, sealedBytes); }
            catch (CryptographicException) { return null; }
        }

        /// <summary>The package and its receipt, written whole into a new folder beside the version's,
        /// then moved into place (an older package and its key cache go with the old folder).</summary>
        static void WritePayload(string appData, string issuer, Dictionary<string, object> pay, List<byte[]> pieces, string receipt, int parts)
        {
            var dir = PayloadFolder(appData, issuer, pay);
            var root = Path.GetDirectoryName(dir);
            var name = Path.GetFileName(dir);
            Directory.CreateDirectory(root);
            var tmp = Path.Combine(root, "." + name + ".new-" + Hex(Random(4)));
            Directory.CreateDirectory(tmp);
            var names = SealNames(parts);
            for (int i = 0; i < pieces.Count; i++) File.WriteAllBytes(Path.Combine(tmp, names[i]), pieces[i]);
            File.WriteAllText(Path.Combine(tmp, "receipt.txt"), receipt, new UTF8Encoding(false));
            string old = null;
            if (Directory.Exists(dir))
            {
                old = Path.Combine(root, "." + name + ".old-" + Hex(Random(4)));
                Directory.Move(dir, old);
            }
            Directory.Move(tmp, dir);
            if (old != null) TryDelete(old);
        }

        static void CachePayloadKey(string appData, string issuer, Dictionary<string, object> pay, byte[] key, string account, string receipt)
        {
            var dir = PayloadFolder(appData, issuer, pay);
            Directory.CreateDirectory(dir);
            var record = Json.Write(new Dictionary<string, object> { ["k"] = Convert.ToBase64String(key), ["account"] = account, ["t"] = receipt });
            var prot = ProtectedData.Protect(Encoding.UTF8.GetBytes(record), PayloadEntropy, DataProtectionScope.CurrentUser);
            var path = Path.Combine(dir, KeyCacheFile);
            var tmp = path + ".tmp";
            File.WriteAllBytes(tmp, prot);
            if (File.Exists(path)) File.Delete(path);
            File.Move(tmp, path);
        }

        /// <summary>The cached K_c while the receipt cached with it holds: signed by the key pinned
        /// at sign-in, for this wire id, account and resident package (sealed_hash), naming this key,
        /// and the clock between issued (less the slack) and expires. Null otherwise.</summary>
        static byte[] CachedPayloadKey(string home, string appData, string issuer, Dictionary<string, object> pay, string account, string sealedHash)
        {
            var path = Path.Combine(PayloadFolder(appData, issuer, pay), KeyCacheFile);
            if (!File.Exists(path)) return null;
            try
            {
                var bytes = ProtectedData.Unprotect(File.ReadAllBytes(path), PayloadEntropy, DataProtectionScope.CurrentUser);
                var d = Json.Parse(Encoding.UTF8.GetString(bytes)) as Dictionary<string, object>;
                if (Json.Str(d, "account") != account) return null;
                var key = TryBase64(Json.Str(d, "k"));
                if (key == null || key.Length != 32) return null;
                var f = VerifyPayloadReceipt(Json.Str(d, "t"), issuer, PinnedKey(home, issuer));
                if (f == null || f["id"] != Json.Str(pay, "wire") || !f.TryGetValue("account", out var a) || a != account
                    || f["sealed_hash"] != sealedHash || f["key_hash"] != Sha256Bytes(key)) return null;
                long now = Now(), issued = long.Parse(f["issued"]), expires = long.Parse(f["expires"]);
                return now < expires && now >= issued - ClockSlack ? key : null;
            }
            catch (Exception e) when (e is CryptographicException || e is FormatException || e is IOException || e is UnauthorizedAccessException || e is KeyNotFoundException) { return null; }
        }

        /// <summary>Every library mod with a payload: fetched where this computer lacks a good
        /// package; then the versions no mod uses any more are removed. True when one was fetched.</summary>
        static bool ClaimAllPayloads(Dictionary<string, object> host, bool force)
        {
            bool any = false;
            string home = Home(host), appData = AppData(host);
            var library = LibraryOf(host);
            foreach (var m in library)
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path) || PayloadOf(path) == null) continue;
                try { any |= Json.Bool(ClaimPayload(home, appData, path, force), "claimed"); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException)
                {
                    lastPayload[path] = "other";
                    Log(home, IssuerOf(path), Path.GetFileName(path.TrimEnd('\\', '/')) + " payload: " + e.GetType().Name + " " + e.Message);
                }
            }
            try
            {
                List<string> removed;
                lock (segmentsLock) removed = CleanPayloads(appData, library);
                foreach (var gone in removed)
                {
                    var rel = gone.Substring(LicenseDir(appData).Length).TrimStart('\\');
                    Log(home, rel.Split('\\')[0], "removed " + rel);
                }
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
            return any;
        }

        static readonly Regex OwnPayloadFolder = new Regex(@"^(?:_|v\d+(?:\.\d+)+|\.(?:_|v\d+(?:\.\d+)+)\.(?:new|old)-[0-9a-f]{8})$");

        /// <summary>As CleanSegments: the version folders of the payload ids the library declares that
        /// no library mod is at, and what an interrupted write left. An id no mod declares any more is
        /// left alone. The removed folders.</summary>
        public static List<string> CleanPayloads(string appData, IEnumerable<Dictionary<string, object>> library)
        {
            var inUse = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in library)
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path)) continue;
                var decl = Declaration(path);
                var pay = decl == null || Json.Str(decl, "error") != null ? null : PayloadOf(path);
                if (pay == null || Json.Str(pay, "error") != null) continue;
                var root = PayloadRoot(appData, Json.Str(decl, "issuer"), Json.Str(pay, "id"));
                if (!inUse.TryGetValue(root, out var set)) inUse[root] = set = new HashSet<string>(StringComparer.Ordinal);
                set.Add(Json.Str(pay, "version") ?? "_");
            }
            var removed = new List<string>();
            foreach (var kv in inUse)
            {
                if (!Directory.Exists(kv.Key)) continue;
                foreach (var dir in Directory.GetDirectories(kv.Key))
                {
                    var name = Path.GetFileName(dir);
                    if (kv.Value.Contains(name) || !OwnPayloadFolder.IsMatch(name)) continue;
                    TryDelete(dir);
                    if (!Directory.Exists(dir)) removed.Add(dir);
                }
            }
            return removed;
        }

        /// <summary>The game start for payloads: each held package is decrypted into its deploy file,
        /// with K_c from the issuer now (a fresh receipt; a package the author replaced is downloaded
        /// again first) or from the cache within the receipt's expires. Called from OnGameStart, under
        /// segmentsLock. Returns (decrypted any, how many payload mods there are).</summary>
        /// <summary>One pass over the library's payloads at a game start (1.11.5: see OnGameStart).
        /// Kept: unlock from the key kept here, no request. Online: the ones Kept did not open, the
        /// issuer asked (else the kept key). Renew: the ones Kept opened, asked once; a package the
        /// author replaced is fetched and unlocked again.</summary>
        static (bool Any, int Count) UnlockPayloads(Dictionary<string, object> host, bool late, HashSet<string> opened, Pass pass)
        {
            bool any = false;
            int count = 0;
            string home = Home(host), appData = AppData(host);
            foreach (var m in LibraryOf(host))
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path)) continue;
                var pay = PayloadOf(path);
                if (pay == null || Json.Str(pay, "error") != null) continue;
                var decl = Declaration(path);
                if (decl == null || Json.Str(decl, "error") != null) continue;
                count++;
                bool wasOpened = opened.Contains("pay|" + path);
                if (pass == Pass.Online && wasOpened || pass == Pass.Renew && !wasOpened) continue;
                bool alsoSegments = Json.Bool(SegmentsOf(path), "sealed");
                string issuer = Json.Str(decl, "issuer");
                try
                {
                    var held = PayloadHeld(appData, decl, pay);
                    if (held == null)
                    {
                        if (pass == Pass.Online) Log(home, issuer, PayLabel(path, pay) + ": nothing to unlock (no member content downloaded here for an account of this computer)");
                        continue;
                    }
                    byte[] key;
                    if (pass == Pass.Kept)
                    {
                        var dir = PayloadFolder(appData, issuer, pay);
                        var resident = VerifyPayloadReceipt(File.ReadAllText(Path.Combine(dir, "receipt.txt")), issuer, Json.Str(decl, "key"));
                        key = resident == null ? null : CachedPayloadKey(home, appData, issuer, pay, held, resident["sealed_hash"]);
                    }
                    else key = PayloadSessionKey(home, appData, decl, pay, held);
                    if (key == null)
                    {
                        if (pass == Pass.Online)
                        {
                            SetLastUnlock(path, "no_key");
                            Log(home, issuer, PayLabel(path, pay) + ": sealed (no key: offline past grace, or another computer)");
                        }
                        continue;
                    }
                    // Renew: the plaintext written in the first pass stays, unless a replaced package took it
                    if (pass == Pass.Renew && File.Exists(Path.Combine(PayloadFolder(appData, issuer, pay), Json.Str(pay, "file"))))
                    { Array.Clear(key, 0, key.Length); continue; }
                    held = PayloadHeld(appData, decl, pay) ?? held;     // a fresh download may have replaced it
                    if (DecryptPayload(appData, decl, pay, key))
                    {
                        any = true;
                        opened.Add("pay|" + path);
                        if (late || !alsoSegments) SetLastUnlock(path, late ? "late" : null);
                        Log(home, issuer, PayLabel(path, pay) + (late ? ": decrypted, but the game started before this program: unlocked from the next game"
                                                                     : pass == Pass.Kept ? ": decrypted for this session from the key kept here" : ": decrypted for this session") + " (account " + held + ")");
                    }
                    else if (pass != Pass.Kept) Log(home, issuer, PayLabel(path, pay) + ": the content did not decrypt to what the receipt signs (sealed)");
                    Array.Clear(key, 0, key.Length);
                }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException)
                { Log(home, issuer, PayLabel(path, pay) + ": " + e.GetType().Name); }
            }
            return (any, count);
        }

        /// <summary>K_c for a held package: from the issuer now (its fresh receipt replaces the
        /// resident one and goes into the cache; when the receipt signs other sealed bytes, the
        /// author replaced the package and it is downloaded again here), else from the cache.</summary>
        static byte[] PayloadSessionKey(string home, string appData, Dictionary<string, object> decl, Dictionary<string, object> pay, string account)
        {
            string issuer = Json.Str(decl, "issuer");
            var dir = PayloadFolder(appData, issuer, pay);
            var resident = VerifyPayloadReceipt(File.ReadAllText(Path.Combine(dir, "receipt.txt")), issuer, Json.Str(decl, "key"));
            if (resident == null) return null;
            var tokens = BoundAccounts(home, appData, decl).FirstOrDefault(b => b.Account == account).Tokens ?? new List<string>();
            foreach (var token in tokens)
            {
                var got = FetchPayload(home, decl, pay, account, token, false);
                if (got.Error != null) continue;              // refused or unreachable: the cache, within its grace
                if (got.Fields["sealed_hash"] != resident["sealed_hash"])
                {
                    got = FetchPayload(home, decl, pay, account, token, true);
                    if (got.Error != null) continue;
                    WritePayload(appData, issuer, pay, got.Sealed, got.Receipt, PartsOf(got.Fields));
                    Log(home, issuer, "payload " + Json.Str(pay, "wire") + ": the author replaced the package; downloaded again");
                }
                else File.WriteAllText(Path.Combine(dir, "receipt.txt"), got.Receipt, new UTF8Encoding(false));
                // kept to the receipt's expires only when it verifies with the key pinned at sign-in
                if (VerifyPayloadReceipt(got.Receipt, issuer, PinnedKey(home, issuer)) != null)
                    CachePayloadKey(appData, issuer, pay, got.Key, account, got.Receipt);
                return got.Key;
            }
            return CachedPayloadKey(home, appData, issuer, pay, account, resident["sealed_hash"]);
        }

        /// <summary>Decrypts payload.seal with K_c and, when the plaintext matches the resident
        /// receipt's plain_hash, writes the deploy file whole (through a temporary name). False when
        /// the key is wrong or the content does not check out: nothing is written.</summary>
        static bool DecryptPayload(string appData, Dictionary<string, object> decl, Dictionary<string, object> pay, byte[] key)
        {
            string issuer = Json.Str(decl, "issuer");
            var dir = PayloadFolder(appData, issuer, pay);
            var f = VerifyPayloadReceipt(File.ReadAllText(Path.Combine(dir, "receipt.txt")), issuer, Json.Str(decl, "key"));
            if (f == null) return false;
            int parts = PartsOf(f);
            var pieces = ReadPieces(dir, parts);
            if (pieces == null || JoinedHash(pieces, parts) != f["sealed_hash"]) return false;
            var plain = OpenPieces(key, pieces, parts, f["plain_hash"]);
            if (plain == null) return false;     // wrong key or tampered: fail closed
            var target = Path.Combine(dir, Json.Str(pay, "file"));
            var tmp = target + ".new-" + Hex(Random(4));
            File.WriteAllBytes(tmp, plain);
            Array.Clear(plain, 0, plain.Length);
            if (File.Exists(target)) File.Delete(target);
            File.Move(tmp, target);
            return true;
        }

        /// <summary>The game stop: every payload folder here keeps only its package, receipt and key
        /// cache; the plaintext (and anything a crash left half written) goes.</summary>
        static void ClearPayloadPlain(string appData)
        {
            var root = LicenseDir(appData);
            if (!Directory.Exists(root)) return;
            // licenses\<issuer>\payload\<id>\<version or _>\
            foreach (var iss in SafeDirs(root))
                foreach (var payRoot in SafeDirs(iss).Where(d => string.Equals(Path.GetFileName(d), "payload", StringComparison.Ordinal)))
                    foreach (var idDir in SafeDirs(payRoot))
                        foreach (var ver in SafeDirs(idDir))
                        {
                            try
                            {
                                foreach (var file in Directory.GetFiles(ver))
                                    if (!PayloadResident.Contains(Path.GetFileName(file)) && !PartFile.IsMatch(Path.GetFileName(file))) File.Delete(file);
                            }
                            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
                        }
        }
    }
}
