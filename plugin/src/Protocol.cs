using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Hd2Qd.License
{
    /// <summary>HD2 Mod License, the manager's side (spec: utilities\hd2-mod-license,
    /// spec/protocol.zh-CN.md). A mod that declares an issuer in hd2_license.json checks a
    /// license at load; this signs the player in to that issuer, writes the license where the
    /// mod reads it, and renews it. The manager calls these by reflection (core\Plugins.cs), so
    /// every method takes and gives strings, numbers, bools and the Json shapes only.
    ///
    /// home: the manager's settings folder (licenses.json: per issuer the pinned key and the
    /// renew token, encrypted for this Windows user). appData: the player's roaming AppData,
    /// where the game keeps saves\ and the mods read licenses\.</summary>
    public static partial class Plugin
    {
        /// <summary>Raised when the calls change shape; the manager refuses a plugin of another Api.</summary>
        public const int Api = 2;
        /// <summary>"panel": drawn in the manager's own window (its plugins page).</summary>
        public const string Kind = "panel";

        /// <summary>The plugin's name in the language lang (a language tag: en, zh-CN, ...).</summary>
        public static string Title(string lang) => Words.Get(lang, "lic_title");

        /// <summary>One sentence on what it does, in lang.</summary>
        public static string Summary(string lang) => Words.Get(lang, "lic_summary");

        const string FileName = "hd2_license.json", Header = "HD2 MOD LICENSE 1\n", StoreName = "licenses.json";
        static readonly Regex Issuer = new Regex(@"^(?:[a-z0-9][a-z0-9.-]*|(?:localhost|127\.0\.0\.1):\d{1,5})$");
        // 16 hex digits, at least 8 of them significant: a placeholder id (0, ...) is no account
        static readonly Regex Account = new Regex("^(?!0{8})[0-9a-f]{16}$");
        // names reserved for tests and examples (RFC 2606, RFC 6761): no members' site can ever
        // answer there. localhost:port is not one of them: an author tries their own issuer there.
        static readonly Regex Reserved = new Regex(@"(?:^|\.)(?:test|example|invalid|localhost|example\.(?:com|net|org))$");

        /// <summary>True when the issuer is a name reserved for tests (issuer.test, ...): a test
        /// build's declaration. Nobody can sign in there, so the manager offers no sign-in.</summary>
        public static bool TestIssuer(string issuer) => issuer != null && Reserved.IsMatch(issuer);
        static readonly byte[] Salt = Encoding.UTF8.GetBytes("hd2qd license renew");
        static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };

        // -- what a mod declares ---------------------------------------------------------

        /// <summary>The mod's hd2_license.json as {issuer, name, key}, or null when it has none.
        /// A declaration that is there but wrong is {error}, so the manager can say so.</summary>
        public static Dictionary<string, object> Declaration(string modFolder)
        {
            var path = Path.Combine(modFolder, FileName);
            if (!File.Exists(path)) return null;
            Dictionary<string, object> d;
            try { d = Json.Parse(File.ReadAllText(path)) as Dictionary<string, object>; }
            catch (Exception e) when (e is FormatException || e is IOException) { return Err("bad_declaration"); }
            if (d == null) return Err("bad_declaration");
            var issuer = Json.Str(d, "issuer")?.Trim().ToLowerInvariant();
            var key = Json.Str(d, "key")?.Trim().ToLowerInvariant().TrimStart('0');
            if (Json.Long(d, "protocol") != 1 || issuer == null || !Issuer.IsMatch(issuer)
                || key == null || !Regex.IsMatch(key, "^[89a-f][0-9a-f]{511}$"))   // RSA-2048, as the mod's check takes
                return Err("bad_declaration");
            var name = Json.Str(d, "name")?.Trim();
            var r = new Dictionary<string, object> { ["issuer"] = issuer, ["name"] = string.IsNullOrEmpty(name) ? issuer : name, ["key"] = key };
            if (ViaOf(modFolder) is string via) r["via"] = via;
            return r;
        }

        /// <summary>(1.9.0) Where this package's player pays, from the mod's .hd2_license_via
        /// ("patreon" or "afdian"): the creator ships one package per members' site, the same
        /// mod but for this file, and the sign-in goes straight to that site. Null when the
        /// package has none (the issuer then asks as before). A dot file, so Quick Deploy's
        /// integrity check (0.22.0 and later) leaves it out: one signed manifest fits both
        /// packages, and the file decides nothing but which site's sign-in opens.</summary>
        static string ViaOf(string modFolder)
        {
            try
            {
                var path = Path.Combine(modFolder, ".hd2_license_via");
                if (!File.Exists(path) || new FileInfo(path).Length > 64) return null;
                var v = File.ReadAllText(path).Trim().ToLowerInvariant();
                return v == "patreon" || v == "afdian" ? v : null;
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return null; }
        }

        /// <summary>The game accounts on this computer: the ids the game names its settings
        /// files after (saves\&lt;id&gt;_user_settings.config), which Network.peer_id() returns in
        /// game. Most played first.</summary>
        public static List<string> Accounts(string appData)
        {
            var saves = Path.Combine(appData, "Arrowhead", "Helldivers2", "saves");
            if (!Directory.Exists(saves)) return new List<string>();
            return new DirectoryInfo(saves).GetFiles("*_user_settings.config")
                .Select(f => (Id: AccountOfName(f.Name), f.LastWriteTimeUtc))
                .Where(a => Account.IsMatch(a.Id))
                .OrderByDescending(a => a.LastWriteTimeUtc)
                .Select(a => a.Id).Distinct().ToList();
        }

        /// <summary>(1.9.0) The account a settings file is named after, as 16 hex digits. The game
        /// writes the id without its leading zeros (0a1b2c3d4e5f6071 -> a1b2c3d4e5f6071_user_
        /// settings.config: a player's saves, 2026-11-19; a Steam id, 0110000100..., is always
        /// saved so by HellForge); Network.peer_id() is padded back to 16 by the mods' own check
        /// (license_check.lua), so the license must name the padded id. One player in 16 has a
        /// leading zero and was told there was no game account.</summary>
        static string AccountOfName(string fileName)
        {
            int at = fileName.IndexOf('_');
            var id = at > 0 ? fileName.Substring(0, at).ToLowerInvariant() : "";
            return Regex.IsMatch(id, "^[0-9a-f]{1,16}$") ? id.PadLeft(16, '0') : id;
        }

        // -- state -------------------------------------------------------------------------

        /// <summary>Where the issuer's license stands on this computer:
        /// {state, issuer, name, expires?, accounts?, renew_due?, members}. The file holds one
        /// license per member who signed in here (two players sharing a computer); the one for
        /// an account here that runs longest speaks. state is "licensed", "expired", "none" (no
        /// license yet), "other_account" (the licenses name no account here), "invalid" (none is
        /// signed by the declared key), "key_changed" (the declared key is not the one signed in
        /// with: ask the player), or "no_account" (no game account here yet: start the game
        /// once). members: how many members' licenses the file holds. A test issuer (TestIssuer)
        /// that has no license good here is "test_issuer" instead: there is no site to sign in to.</summary>
        public static Dictionary<string, object> Status(string home, string appData, Dictionary<string, object> decl)
        {
            var r = StatusOf(home, appData, decl);
            r = TestIssuer(Json.Str(decl, "issuer")) && Json.Str(r, "state") != "licensed" ? With(r, "test_issuer") : r;
            LogState(home, appData, r);
            return r;
        }

        static Dictionary<string, object> StatusOf(string home, string appData, Dictionary<string, object> decl)
        {
            string issuer = Json.Str(decl, "issuer"), key = Json.Str(decl, "key");
            var r = new Dictionary<string, object> { ["issuer"] = issuer, ["name"] = Json.Str(decl, "name") };
            var pinned = Json.Str(IssuerRecord(home, issuer), "key");
            if (pinned != null && pinned != key) return With(r, "key_changed");
            var mine = Accounts(appData);
            var text = ReadLicense(appData, issuer);
            if (text == null) return With(r, mine.Count == 0 ? "no_account" : "none");
            var all = Licenses(text, issuer, key);
            if (all.Count == 0) return With(r, "invalid");
            r["members"] = (long)all.Count;
            var ours = all.Where(f => Named(f).Intersect(mine).Any()).OrderByDescending(Expires).ToList();
            if (ours.Count == 0) return With(r, mine.Count == 0 ? "no_account" : "other_account");
            var best = ours[0];
            long expires = Expires(best);
            long issued = best.TryGetValue("issued", out var iv) && long.TryParse(iv, out var i) ? i : expires;
            r["expires"] = expires;
            r["accounts"] = Named(best).Cast<object>().ToList();
            long now = Now();
            if (now >= expires) return With(r, "expired");
            r["renew_due"] = now >= issued + (expires - issued) / 2;
            return With(r, "licensed");
        }

        // -- signing in --------------------------------------------------------------------

        /// <summary>A sign-in under way, between BeginSignIn and FinishSignIn: where the browser
        /// comes back, and the secrets only this computer knows.</summary>
        sealed class SignInSession
        {
            public Loopback Loopback;
            public string Verifier, State;
        }

        static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SignInSession> Sessions =
            new System.Collections.Concurrent.ConcurrentDictionary<string, SignInSession>();

        /// <summary>Step one: {url, session}. It listens on 127.0.0.1 for the browser's return
        /// and makes the address the manager opens in the browser, where the player signs in to
        /// the issuer's members' site (OAuth for native apps, RFC 8252: a loopback redirect with
        /// PKCE). {error: "no_account"} when the game has not made a settings file here yet;
        /// {error: "test_issuer"} for a test build's issuer; {error: "other", detail} when it
        /// cannot listen. FinishSignIn or AbandonSignIn ends the session.</summary>
        public static Dictionary<string, object> BeginSignIn(string appData, Dictionary<string, object> decl)
        {
            if (TestIssuer(Json.Str(decl, "issuer"))) return Err("test_issuer");
            var accounts = Accounts(appData);
            if (accounts.Count == 0) return Err("no_account");
            Loopback loopback;
            try { loopback = new Loopback(); }
            catch (System.Net.Sockets.SocketException e) { return new Dictionary<string, object> { ["error"] = "other", ["detail"] = e.Message }; }
            var s = new SignInSession { Loopback = loopback, Verifier = Hex(Random(32)), State = Hex(Random(16)) };
            var session = Hex(Random(16));
            Sessions[session] = s;
            var url = Base(Json.Str(decl, "issuer")) + "/login?c=" + Sha256Hex(s.Verifier) + "&s=" + s.State
                      + "&port=" + loopback.Port + "&acct=" + accounts[0]
                      + (Json.Str(decl, "via") is string via && (via == "patreon" || via == "afdian") ? "&via=" + via : "");
            return new Dictionary<string, object> { ["url"] = url, ["session"] = session };
        }

        /// <summary>Ends a sign-in that will not be finished (the player said no, the browser
        /// would not open): it stops listening. Nothing when it has ended already.</summary>
        public static void AbandonSignIn(string session)
        {
            if (session != null && Sessions.TryRemove(session, out var s)) s.Loopback.Dispose();
        }

        /// <summary>Step two: waits for the browser to come back (up to timeoutSeconds), collects
        /// the license with the code it brings and the verifier kept here, checks it against the
        /// declared key, writes it where the mods read it and keeps the renew token; then answers
        /// the browser with a page saying how it went, in lang. {ok: true, expires} or {error}:
        /// the issuer's own (not_member, account_limit with wait_days, denied, unknown),
        /// "timeout", "cancelled", "network", "bad_license".</summary>
        public static Dictionary<string, object> FinishSignIn(string home, string appData, Dictionary<string, object> decl,
                                                              string session, int timeoutSeconds, CancellationToken cancel, string lang = null)
        {
            if (session == null || !Sessions.TryRemove(session, out var s)) return Err("cancelled");
            using (s.Loopback)
            {
                Loopback.Return back;
                try { back = s.Loopback.Receive(s.State, DateTime.UtcNow.AddSeconds(timeoutSeconds), cancel); }
                catch (OperationCanceledException) { return Err("cancelled"); }
                if (back == null) { Log(home, Json.Str(decl, "issuer"), "sign-in: timeout (the browser did not come back)"); return Err("timeout"); }
                var r = Claim(home, appData, decl, back, s.Verifier);
                back.Reply(Page(r, lang));
                Log(home, Json.Str(decl, "issuer"), "sign-in: " + OutcomeWords(r));
                return r;
            }
        }

        /// <summary>A sign-in's, activation's or renewal's result for the log.</summary>
        static string OutcomeWords(Dictionary<string, object> r)
        {
            if (Json.Str(r, "error") is string e)
                return e + (Json.Long(r, "wait_days") > 0 ? " (wait " + Json.Long(r, "wait_days") + " days)" : "")
                         + (Json.Str(r, "detail") is string d ? " (" + d + ")" : "");
            if (r.ContainsKey("expires"))
                return "ok, until " + DateTimeOffset.FromUnixTimeSeconds(Json.Long(r, "expires")).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            return Json.Bool(r, "renewed") ? "ok" : "nothing due";
        }

        static Dictionary<string, object> Claim(string home, string appData, Dictionary<string, object> decl, Loopback.Return back, string verifier)
        {
            string issuer = Json.Str(decl, "issuer"), key = Json.Str(decl, "key");
            if (back["error"] is string refused)
                return WithWait(Err(Regex.IsMatch(refused, "^[a-z_]{1,32}$") ? refused : "other"), back["wait_days"]);
            var code = back["code"];
            if (code == null || !Regex.IsMatch(code, "^[0-9a-f]{32}$")) return Err("other");
            var (status, body) = Post(home, issuer, "/claim", new Dictionary<string, object> { ["code"] = code, ["verifier"] = verifier });
            if (status == 403) return WithWait(Err(Json.Str(body, "error") ?? "network"), Json.Long(body, "wait_days").ToString());
            if (status != 200 || body == null) return Err("network");
            return Keep(home, appData, decl, body);
        }

        /// <summary>A license the issuer gave ({license, renew}): checked against the declared key,
        /// written where the mods read it, and its renew token kept for its member.
        /// {ok: true, expires} or {error: "bad_license"}.</summary>
        static Dictionary<string, object> Keep(string home, string appData, Dictionary<string, object> decl, Dictionary<string, object> body)
        {
            string issuer = Json.Str(decl, "issuer"), key = Json.Str(decl, "key");
            var text = Json.Str(body, "license");
            var renew = Json.Str(body, "renew");
            var f = text == null ? null : Verify(text, issuer, key);
            if (f == null || renew == null) return Err("bad_license");
            WriteLicense(appData, issuer, key, text);
            var rec = IssuerRecord(home, issuer) ?? new Dictionary<string, object>();
            rec["key"] = key;
            rec["name"] = Json.Str(decl, "name");
            var members = Json.Obj(rec, "members") ?? new Dictionary<string, object>();
            members[Holder(f)] = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(renew), Salt, DataProtectionScope.CurrentUser));
            rec["members"] = members;
            SaveIssuer(home, issuer, rec);
            return new Dictionary<string, object> { ["ok"] = true, ["expires"] = long.Parse(f["expires"]) };
        }

        // -- activation codes ----------------------------------------------------------------

        const string CodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        /// <summary>An activation code as typed, in its 20 characters, or null when it is not one.
        /// A code is 19 characters of Crockford's Base32 and a check character: the first 5 bits
        /// of the SHA-256 of "hd2 license code\n" and the 19 (spec/protocol.zh-CN.md). Case,
        /// spaces and dashes are ignored, O reads as 0 and I and L as 1.</summary>
        public static string NormalizeCode(string typed)
        {
            if (typed == null) return null;
            var s = new string(typed.ToUpperInvariant().Where(c => !char.IsWhiteSpace(c) && c != '-')
                .Select(c => c == 'O' ? '0' : c == 'I' || c == 'L' ? '1' : c).ToArray());
            if (s.Length != 20 || s.Any(c => CodeAlphabet.IndexOf(c) < 0)) return null;
            using (var sha = SHA256.Create())
            {
                var d = sha.ComputeHash(Encoding.ASCII.GetBytes("hd2 license code\n" + s.Substring(0, 19)));
                return s[19] == CodeAlphabet[d[0] >> 3] ? s : null;
            }
        }

        /// <summary>Activates with a code the author gave (for example in a sponsorship platform's
        /// reply after paying), instead of signing in through the browser: the issuer finds whom the
        /// code was given to and answers as a sign-in does. {ok: true, expires} or {error}:
        /// "bad_code" (mistyped, nothing was sent), "no_account", "test_issuer", the issuer's own
        /// (unknown_code, not_member, account_limit with wait_days, banned), "no_codes" (the issuer
        /// takes no codes), "network", "bad_license".</summary>
        public static Dictionary<string, object> Redeem(string home, string appData, Dictionary<string, object> decl, string typed)
        {
            var r = RedeemOnce(home, appData, decl, typed);
            Log(home, Json.Str(decl, "issuer"), "activation code: " + OutcomeWords(r));
            return r;
        }

        static Dictionary<string, object> RedeemOnce(string home, string appData, Dictionary<string, object> decl, string typed)
        {
            if (TestIssuer(Json.Str(decl, "issuer"))) return Err("test_issuer");
            var code = NormalizeCode(typed);
            if (code == null) return Err("bad_code");
            var accounts = Accounts(appData);
            if (accounts.Count == 0) return Err("no_account");
            var (status, body) = Post(home, Json.Str(decl, "issuer"), "/redeem", new Dictionary<string, object> { ["code"] = code, ["acct"] = accounts[0] });
            string error = Json.Str(body, "error");
            if (status == 404) return Err("no_codes");                  // an issuer that has no /redeem, or takes no codes
            if (status == 400) return Err(error == "bad_code" ? "bad_code" : "other");
            if (status == 403) return WithWait(Err(error != null && Regex.IsMatch(error, "^[a-z_]{1,32}$") ? error : "other"), Json.Long(body, "wait_days").ToString());
            if (status != 200 || body == null) return Err("network");
            return Keep(home, appData, decl, body);
        }

        /// <summary>account_limit's wait, in days, when the issuer gave one.</summary>
        static Dictionary<string, object> WithWait(Dictionary<string, object> r, string days)
        {
            if (Json.Str(r, "error") == "account_limit" && long.TryParse(days, out var d) && d > 0 && d < 100000) r["wait_days"] = d;
            return r;
        }

        /// <summary>The page the browser is left on: how the sign-in went, and to go back to the manager.</summary>
        static string Page(Dictionary<string, object> r, string lang)
        {
            lang = lang ?? "en";
            var error = Json.Str(r, "error");
            string text = error == null ? Words.F(lang, "lic_done", Until(Json.Long(r, "expires"))) : ErrorWords(r, lang);
            return "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>HD2 MOD</title>"
                   + "<body style='font:16px system-ui;margin:3em auto;max-width:36em;padding:0 1em'><p>"
                   + System.Net.WebUtility.HtmlEncode(text) + "</p><p>" + System.Net.WebUtility.HtmlEncode(Words.Get(lang, "lic_page_close")) + "</p>";
        }

        /// <summary>Renews each member's license here when half its time has passed (or always,
        /// with force). {renewed: false} when none was due or nobody signed in here; {renewed:
        /// true, expires} (the latest end) when one or more were; {error} when none could be and
        /// one failed: the issuer's (not_member, sign_in_again, unknown), "network",
        /// "bad_license", "key_changed". A member whose renewal fails keeps their license to its
        /// end; the others are renewed all the same.</summary>
        public static Dictionary<string, object> Renew(string home, string appData, Dictionary<string, object> decl, bool force)
        {
            var r = RenewOnce(home, appData, decl, force);
            if (Json.Bool(r, "renewed") || Json.Str(r, "error") != null) Log(home, Json.Str(decl, "issuer"), "renewal: " + OutcomeWords(r));
            return r;
        }

        static Dictionary<string, object> RenewOnce(string home, string appData, Dictionary<string, object> decl, bool force)
        {
            string issuer = Json.Str(decl, "issuer"), key = Json.Str(decl, "key");
            var rec = IssuerRecord(home, issuer);
            var tokens = RenewTokens(rec);
            if (tokens.Count == 0) return new Dictionary<string, object> { ["renewed"] = false };
            if (Json.Str(rec, "key") != key) return Err("key_changed");
            var text = ReadLicense(appData, issuer);
            var held = text == null ? new List<Dictionary<string, string>>() : Licenses(text, issuer, key);
            long now = Now(), latest = 0;
            string error = null;
            foreach (var (holder, token) in tokens)
            {
                var mine = held.Where(f => Holder(f) == holder).OrderByDescending(Expires).FirstOrDefault();
                if (!force && mine != null && !Due(mine, now)) continue;
                var (status, body) = Post(home, issuer, "/renew", new Dictionary<string, object> { ["renew"] = token });
                if (status != 200) { error = error ?? (status == 403 ? Json.Str(body, "error") ?? "network" : "network"); continue; }
                var got = Json.Str(body, "license");
                var f = got == null ? null : Verify(got, issuer, key);
                if (f == null) { error = error ?? "bad_license"; continue; }
                WriteLicense(appData, issuer, key, got);
                latest = Math.Max(latest, Expires(f));
                // a token kept before members were told apart: filed under the member it renewed
                if (holder == "")
                {
                    rec = IssuerRecord(home, issuer);
                    var members = Json.Obj(rec, "members") ?? new Dictionary<string, object>();
                    if (!members.ContainsKey(Holder(f))) members[Holder(f)] = rec["renew"];
                    rec["members"] = members;
                    rec.Remove("renew");
                    SaveIssuer(home, issuer, rec);
                }
            }
            if (latest > 0) return new Dictionary<string, object> { ["renewed"] = true, ["expires"] = latest };
            return error != null ? Err(error) : new Dictionary<string, object> { ["renewed"] = false };
        }

        /// <summary>Signs out here: the license file, the renew token and the pinned key go.</summary>
        public static void Forget(string home, string appData, string issuer)
        {
            var path = LicensePath(appData, issuer);
            if (File.Exists(path)) File.Delete(path);
            SaveIssuer(home, issuer, null);
            Log(home, issuer, "signed out on this computer");
        }

        /// <summary>The issuers signed in on this computer, each as {issuer, name, key}: so the
        /// manager can show a sign-in (and sign it out) when no mod in the library names it.</summary>
        public static List<Dictionary<string, object>> SignedIn(string home)
        {
            var list = new List<Dictionary<string, object>>();
            var all = Json.Obj(LoadStore(home), "issuers");
            if (all == null) return list;
            foreach (var kv in all)
                if (kv.Value is Dictionary<string, object> rec && Json.Str(rec, "key") != null)
                    list.Add(new Dictionary<string, object> { ["issuer"] = kv.Key, ["name"] = Json.Str(rec, "name") ?? kv.Key, ["key"] = Json.Str(rec, "key") });
            return list;
        }

        // -- the license -------------------------------------------------------------------

        /// <summary>Every license in a file signed by key for issuer: the file holds one per
        /// member, each starting with the header at the start of a line.</summary>
        static List<Dictionary<string, string>> Licenses(string text, string issuer, string key)
        {
            var found = new List<Dictionary<string, string>>();
            foreach (var block in Blocks(text))
            {
                var f = Verify(block, issuer, key);
                if (f != null) found.Add(f);
            }
            return found;
        }

        static List<string> Blocks(string text)
        {
            text = text.Replace("\r", "");
            var blocks = new List<string>();
            int at = text.StartsWith(Header, StringComparison.Ordinal) ? 0 : text.IndexOf("\n" + Header, StringComparison.Ordinal);
            while (at >= 0)
            {
                if (text[at] == '\n') at++;
                int next = text.IndexOf("\n" + Header, at, StringComparison.Ordinal);
                blocks.Add(next < 0 ? text.Substring(at) : text.Substring(at, next + 1 - at));
                at = next;
            }
            return blocks;
        }

        static List<string> Named(Dictionary<string, string> f) => f["accounts"].Split(',').ToList();
        static long Expires(Dictionary<string, string> f) => long.Parse(f["expires"]);
        static string Holder(Dictionary<string, string> f) => f.TryGetValue("holder", out var h) ? h : "";

        static bool Due(Dictionary<string, string> f, long now)
        {
            long expires = Expires(f);
            long issued = f.TryGetValue("issued", out var iv) && long.TryParse(iv, out var i) ? i : expires;
            return now >= issued + (expires - issued) / 2;
        }

        /// <summary>The fields of a license signed by key for issuer, else null. Same rules as
        /// license_check.lua: CR dropped, the signature over every byte before "sig=".</summary>
        static Dictionary<string, string> Verify(string text, string issuer, string key)
        {
            text = text.Replace("\r", "");
            int at = text.IndexOf("\nsig=", StringComparison.Ordinal);
            if (!text.StartsWith(Header, StringComparison.Ordinal) || at < 0) return null;
            string signed = text.Substring(0, at + 1), sig = text.Substring(at + 5).Trim();
            var f = new Dictionary<string, string>();
            foreach (var line in signed.Split('\n').Skip(1))
            {
                int eq = line.IndexOf('=');
                if (eq > 0) f[line.Substring(0, eq)] = line.Substring(eq + 1);
            }
            if (!f.TryGetValue("issuer", out var iss) || iss != issuer) return null;
            if (!f.ContainsKey("accounts") || !f.TryGetValue("expires", out var exp) || !long.TryParse(exp, out _)
                || !f.TryGetValue("issued", out var iss2) || !long.TryParse(iss2, out _)) return null;
            var modulus = Bytes(key);
            if (!Regex.IsMatch(sig, "^[0-9a-fA-F]+$") || sig.Length != modulus.Length * 2) return null;
            using (var rsa = new RSACng())
            {
                rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = new byte[] { 1, 0, 1 } });
                if (!rsa.VerifyData(Encoding.UTF8.GetBytes(signed), Bytes(sig), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return null;
            }
            return f;
        }

        static string LicensePath(string appData, string issuer) =>
            Path.Combine(appData, "Arrowhead", "Helldivers2", "licenses", issuer.Replace(':', '_') + ".txt");

        static string ReadLicense(string appData, string issuer)
        {
            var path = LicensePath(appData, issuer);
            try { return File.Exists(path) ? File.ReadAllText(path) : null; }
            catch (IOException) { return null; }
        }

        /// <summary>A member's new license, in place of their old one: the other members'
        /// licenses that are still good stay (two players sharing a computer). Through a
        /// temporary file, so the game never reads half a license.</summary>
        static void WriteLicense(string appData, string issuer, string key, string text)
        {
            var path = LicensePath(appData, issuer);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            var holder = Holder(Verify(text, issuer, key));
            var keep = new StringBuilder(text.Replace("\r", "").TrimEnd('\n') + "\n");
            var old = ReadLicense(appData, issuer);
            if (old != null)
                foreach (var block in Blocks(old))
                {
                    var f = Verify(block, issuer, key);
                    if (f != null && Holder(f) != holder && Expires(f) > Now()) keep.Append(block.TrimEnd('\n') + "\n");
                }
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, keep.ToString(), new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(tmp, path, null);
            else File.Move(tmp, path);
        }

        // -- licenses.json -----------------------------------------------------------------

        static Dictionary<string, object> LoadStore(string home)
        {
            var path = Path.Combine(home, StoreName);
            try { return File.Exists(path) ? Json.Parse(File.ReadAllText(path)) as Dictionary<string, object> ?? new Dictionary<string, object>() : new Dictionary<string, object>(); }
            catch (FormatException) { return new Dictionary<string, object>(); }
        }

        static Dictionary<string, object> IssuerRecord(string home, string issuer) => Json.Obj(Json.Obj(LoadStore(home), "issuers"), issuer);

        static void SaveIssuer(string home, string issuer, Dictionary<string, object> rec)
        {
            var store = LoadStore(home);
            var all = Json.Obj(store, "issuers") ?? new Dictionary<string, object>();
            if (rec == null) all.Remove(issuer);
            else all[issuer] = rec;
            store["issuers"] = all;
            Directory.CreateDirectory(home);
            var path = Path.Combine(home, StoreName);
            File.WriteAllText(path + ".tmp", Json.Write(store, true), new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(path + ".tmp", path, null);
            else File.Move(path + ".tmp", path);
        }

        /// <summary>(holder, token) for each member signed in here; holder "" for the one token
        /// a sign-in before 2026-11-02 kept for the whole issuer.</summary>
        static List<(string Holder, string Token)> RenewTokens(Dictionary<string, object> rec)
        {
            var list = new List<(string, string)>();
            var members = Json.Obj(rec, "members");
            if (members != null)
                foreach (var kv in members)
                    if (Unprotect(kv.Value as string) is string t) list.Add((kv.Key, t));
            if (Unprotect(Json.Str(rec, "renew")) is string legacy) list.Add(("", legacy));
            return list;
        }

        static string Unprotect(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(s), Salt, DataProtectionScope.CurrentUser)); }
            catch (Exception e) when (e is CryptographicException || e is FormatException) { return null; }
        }

        // -- helpers -----------------------------------------------------------------------

        /// <summary>https, except for a test issuer on this computer.</summary>
        static string Base(string issuer) =>
            (issuer.StartsWith("localhost:") || issuer.StartsWith("127.0.0.1:") ? "http://" : "https://") + issuer;

        /// <summary>(status, body); status 0 when the issuer could not be reached. (1.8.0) Each
        /// request and its answer is a line of the plugin's log (Log.cs), and says the plugin's
        /// version to the issuer (header X-HD2QD-License), whose own request log shows it.</summary>
        static (int, Dictionary<string, object>) Post(string home, string issuer, string path, Dictionary<string, object> body)
        {
            // (1.11.3) a request that does not get through is sent again, twice, after a pause: a
            // network that drops some connections (mainland China to Cloudflare, 2026-11-21: three
            // sign-ins lost at 20 s, the fourth answered in 3.8 s) then needs no click. Only an
            // unreachable issuer or an edge error (502-504, Cloudflare's 520-524) is retried, never a
            // refusal. Safe for every path: /renew, /segments, /payload, /session and /attest change
            // nothing; /redeem with the same code signs again; a /claim whose first answer was lost
            // finds its one-use code spent and says "sign in again", as a new sign-in would need anyway.
            var (status, d) = PostOnce(home, issuer, path, body);
            for (int i = 0; i < RetryDelaysMs.Length && Retryable(status); i++)
            {
                if (RetryDelaysMs[i] > 0) System.Threading.Thread.Sleep(RetryDelaysMs[i]);
                (status, d) = PostOnce(home, issuer, path, body);
            }
            return (status, d);
        }

        /// <summary>(1.11.3) The pauses before each retry, in milliseconds; tests set them to 0.</summary>
        public static int[] RetryDelaysMs = { 2000, 5000 };

        static bool Retryable(int status) => status == 0 || status == 502 || status == 503 || status == 504 || (status >= 520 && status <= 524);

        static (int, Dictionary<string, object>) PostOnce(string home, string issuer, string path, Dictionary<string, object> body)
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            int status = 0;
            Dictionary<string, object> d = null;
            Exception failed = null;
            try
            {
                using (var content = new StringContent(Json.Write(body), Encoding.UTF8, "application/json"))
                using (var request = new HttpRequestMessage(HttpMethod.Post, Base(issuer) + path) { Content = content })
                {
                    request.Headers.TryAddWithoutValidation("X-HD2QD-License", PluginVersion);
                    using (var r = Http.SendAsync(request).GetAwaiter().GetResult())
                    {
                        var text = r.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        try { d = Json.Parse(text) as Dictionary<string, object>; } catch (FormatException) { }
                        status = (int)r.StatusCode;
                    }
                }
            }
            catch (Exception e) when (e is HttpRequestException || e is TaskCanceledException || e is IOException) { failed = e; status = 0; d = null; }
            if (path != "/diag" || status != 200) Log(home, issuer, RequestWords(path, body, status, d, clock.ElapsedMilliseconds, failed));
            return (status, d);
        }

        /// <summary>Set by tests.</summary>
        public static Func<long> Clock = () => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        static long Now() => Clock();

        static Dictionary<string, object> Err(string error) => new Dictionary<string, object> { ["error"] = error };

        static Dictionary<string, object> With(Dictionary<string, object> r, string state)
        {
            r["state"] = state;
            return r;
        }

        static byte[] Random(int n)
        {
            var b = new byte[n];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return b;
        }

        static string Hex(byte[] b) => string.Concat(b.Select(x => x.ToString("x2")));

        static string Sha256Hex(string text)
        {
            using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(Encoding.ASCII.GetBytes(text)));
        }

        static byte[] Bytes(string hex)
        {
            if (hex.Length % 2 == 1) hex = "0" + hex;
            var b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }
    }
}
