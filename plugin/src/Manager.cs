using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace Hd2Qd.License
{
    // What the plugin adds to HD2 Mod Quick Deploy besides its card (Panel.cs): a word on the
    // rows of mods that need a license, the renewal at the manager's start, and the commands
    // license, license-login, license-renew and license-logout. The manager hands every call
    // its host: home (its settings folder), appdata (the player's roaming AppData), lang (the
    // language the manager shows, a language tag: Words.cs), and library (a Func of every mod
    // in its library: {name, path, enabled}).
    public static partial class Plugin
    {
        static string Home(Dictionary<string, object> host) => (string)host["home"];

        static string AppData(Dictionary<string, object> host) =>
            host.TryGetValue("appdata", out var a) && a is string s && s.Length > 0 ? s
            : Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        static List<Dictionary<string, object>> LibraryOf(Dictionary<string, object> host) =>
            host.TryGetValue("library", out var f) && f is Func<List<Dictionary<string, object>>> read ? read() ?? new List<Dictionary<string, object>>()
            : new List<Dictionary<string, object>>();

        /// <summary>Where a mod's license stands: null when it needs none; {state:
        /// "bad_declaration"} when its hd2_license.json cannot be read; else Status.</summary>
        public static Dictionary<string, object> StateOf(string home, string appData, string modFolder)
        {
            var d = Declaration(modFolder);
            if (d == null) return null;
            if (Json.Str(d, "error") != null) return new Dictionary<string, object> { ["state"] = "bad_declaration" };
            return Status(home, appData, d);
        }

        /// <summary>Every issuer the library's mods declare, each with its declaration, the names
        /// of the mods that use it and the folder of the first, in the library's order.</summary>
        public static List<(Dictionary<string, object> Decl, List<string> Mods, string Folder)> Issuers(IEnumerable<Dictionary<string, object>> library)
        {
            var found = new List<(Dictionary<string, object>, List<string>, string)>();
            foreach (var m in library)
            {
                var path = Json.Str(m, "path");
                if (path == null || !Directory.Exists(path)) continue;
                var d = Declaration(path);
                if (d == null || Json.Str(d, "error") != null) continue;
                var at = found.FindIndex(x => Json.Str(x.Item1, "issuer") == Json.Str(d, "issuer") && Json.Str(x.Item1, "key") == Json.Str(d, "key"));
                if (at < 0) found.Add((d, new List<string> { Json.Str(m, "name") }, path));
                else
                {
                    found[at].Item2.Add(Json.Str(m, "name"));
                    // (1.9.0) packages from both members' sites: the issuer asks which, as before
                    if (Json.Str(found[at].Item1, "via") != Json.Str(d, "via")) found[at].Item1["via"] = "mixed";
                }
            }
            return found;
        }

        /// <summary>Issuers(library), then every issuer signed in here that no mod in the library
        /// names, with no mods: a sign-in stays in sight (and can be signed out) after its mods
        /// leave the library.</summary>
        public static List<(Dictionary<string, object> Decl, List<string> Mods, string Folder)> Known(string home, IEnumerable<Dictionary<string, object>> library)
        {
            var found = Issuers(library);
            foreach (var d in SignedIn(home))
                if (!found.Any(x => Json.Str(x.Decl, "issuer") == Json.Str(d, "issuer")))
                    found.Add((d, new List<string>(), null));
            return found;
        }

        // ------------------------------------------------------------ the manager's calls

        /// <summary>The word on a mod's row: none when it needs no license or has one; else that
        /// it needs one, or that it ran out, or that its declaration cannot be read.</summary>
        public static Dictionary<string, object> ModNote(string modFolder, Dictionary<string, object> host)
        {
            var st = StateOf(Home(host), AppData(host), modFolder);
            var state = Json.Str(st, "state");
            if (state == "licensed") return SegmentsNote(modFolder, host);
            if (state == null) return null;
            string key = state == "expired" ? "row_license_expired" : state == "bad_declaration" ? "lic_bad_declaration"
                : state == "test_issuer" ? "row_license_test" : "row_license";
            string tip = state == "test_issuer" ? "row_license_test_tip" : "row_license_tip";
            string lang = Words.Lang(host);
            return new Dictionary<string, object>
            {
                ["text"] = Words.Get(lang, key),
                ["tip"] = Words.Get(lang, tip),
                ["colour"] = "Yellow",
            };
        }

        /// <summary>(1.6.0) A licensed mod that ships its Lua as per-account segments: nothing
        /// when this computer holds its version's set; else what is missing, and (once per version
        /// per run) a claim in the background, so a new version in the library is fetched without
        /// a restart.</summary>
        static Dictionary<string, object> SegmentsNote(string modFolder, Dictionary<string, object> host)
        {
            string seg;
            try { seg = SegmentsState(Home(host), AppData(host), modFolder); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return null; }
            string lang = Words.Lang(host);
            if (seg == "claimed")
            {
                // a sealed (C1) mod held here: a word only when its content was, or will be, left
                // locked in a game (the user, 2026-11-19: "log and manager only", nothing in game)
                if (!UnlockedPerSession(modFolder)) return null;       // (1.10.0) a payload is unlocked per game too
                string why = !RunsOnInTray(host) ? "row_needs_window"
                    : LastUnlock(modFolder) == "late" ? "row_unlock_late"
                    : LastUnlock(modFolder) == "no_key" ? "row_unlock_no_key" : null;
                if (why == null) return null;
                return new Dictionary<string, object>
                {
                    ["text"] = Words.Get(lang, why), ["tip"] = Words.Get(lang, why == "row_needs_window" ? "seg_needs_tray" : why + "_tip"), ["colour"] = "Yellow",
                };
            }
            if (seg == null) return null;
            if (seg == "missing") ClaimLater(host, modFolder, SegmentsOf(modFolder));
            return new Dictionary<string, object>
            {
                ["text"] = Words.Get(lang, seg == "pending" || seg == "payload_pending" ? "row_segments_pending"
                                           : seg == "downloading" ? "row_segments_downloading" : "row_segments"),
                ["tip"] = Words.Get(lang, "row_segments_tip"),
                ["colour"] = "Yellow",
            };
        }

        /// <summary>At the manager's start, in the background: each license that is half way to its
        /// end is renewed. A failure says nothing (the card shows the state, and the old license
        /// runs to its end); the next start tries again. True when one was renewed.</summary>
        public static bool Start(Dictionary<string, object> host)
        {
            Interlocked.Exchange(ref startedOnce, 1);
            // (1.5.0) the mods' questions answered from now on (Attest.cs)
            try { Watch(host); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException) { }
            // (1.7.0, C1) from now on a sealed version is decrypted for the game while it runs and
            // its plaintext cleared when it stops (Session.cs)
            try { WatchGame(host); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException) { }
            bool any = false;
            foreach (var (decl, _, _) in Issuers(LibraryOf(host)))
                try { any |= Json.Bool(Renew(Home(host), AppData(host), decl, false), "renewed"); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is System.Security.Cryptography.CryptographicException) { }
            // (1.6.0) the segments of the library's versions, after the licenses are fresh
            try { any |= ClaimAll(host); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is System.Security.Cryptography.CryptographicException) { }
            return any;
        }

        static int startedOnce;

        /// <summary>(1.9.0) What Start sets going, for a plugin added while the window was open:
        /// the manager calls Start only when its window opens, so a plugin added from the Plugins
        /// page watched no game until the manager was restarted, and a sealed mod stayed locked
        /// with no word why (a player's log, 2026-11-19). The card's first drawing starts the
        /// answers to the mods' questions and the game watch here instead; both are made once.</summary>
        static void EnsureStarted(Dictionary<string, object> host)
        {
            if (host == null || Interlocked.Exchange(ref startedOnce, 1) == 1) return;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                Log(Home(host), null, "started on the Plugins page (added while the manager was open)");
                try { Watch(host); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException) { }
                try { WatchGame(host); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException) { }
            });
        }

        /// <summary>The commands it adds to the manager's command line.</summary>
        public static readonly string[][] Commands =
        {
            new[] { "license", "the licenses the library's mods need (a mod with hd2_license.json is for its author's members): each issuer, whether this computer has its license and until when, and the mods that use it" },
            new[] { "license-login", "sign in to a mod author's issuer (license-login ISSUER, its name or a mod that uses it): your browser opens the author's members' site, and the license goes where the mods read it" },
            new[] { "license-redeem", "activate with the code a mod author gave you (license-redeem ISSUER CODE, the issuer's name or a mod that uses it), instead of signing in through the browser" },
            new[] { "license-renew", "renew the licenses that are half way to their end (--force: every one now)" },
            new[] { "license-segments", "download the member content of the library's mods that ship it per game account (the manager does this by itself at its start; --force: download again)" },
            new[] { "license-answer", "answer the question a licensed mod asked at its start (the manager does this by itself while it runs)" },
            new[] { "license-log-send", "send this computer's license log (sign-ins, renewals, checks, member content) to a mod author's issuer (license-log-send ISSUER; with one author in the library, ISSUER may be left out): it prints the code to give the author" },
            new[] { "license-logout", "remove an issuer's license and sign-in from this computer (license-logout ISSUER)" },
        };

        /// <summary>One of its commands: 0 done, 2 a wrong command line; a refusal is thrown.</summary>
        public static int Run(string command, string[] args, TextWriter o, Dictionary<string, object> host)
        {
            string home = Home(host), appData = AppData(host);
            var library = LibraryOf(host);
            switch (command)
            {
                case "license":
                    var known = Known(home, library);
                    if (known.Count == 0) { o.WriteLine("no mod in the library needs a license, and no author is signed in here"); return 0; }
                    foreach (var (decl, mods, folder) in known)
                    {
                        var st = folder != null ? StateOf(home, appData, folder) : Status(home, appData, decl);
                        o.WriteLine(Json.Str(decl, "name") + " (" + Json.Str(decl, "issuer") + "): " + CommandWords(st));
                        o.WriteLine("  mods: " + (mods.Count > 0 ? string.Join(", ", mods) : "none in the library now"));
                    }
                    return 0;
                case "license-login":
                {
                    if (args.Length != 1) { o.WriteLine("usage: hd2qd license-login ISSUER"); return 2; }
                    var decl = IssuerArg(home, library, args[0]);
                    var begin = BeginSignIn(appData, decl);
                    if (Json.Str(begin, "error") == "no_account") throw new InvalidOperationException("no game account on this computer yet: start the game once, then sign in");
                    if (Json.Str(begin, "error") != null) throw new InvalidOperationException(CommandError(Json.Str(begin, "error")) + (Json.Str(begin, "detail") is string d ? ": " + d : ""));
                    var session = Json.Str(begin, "session");
                    Dictionary<string, object> r;
                    try
                    {
                        o.WriteLine("your browser opens " + Json.Str(decl, "issuer") + ", the issuer of " + Json.Str(decl, "name") + "; it learns your game account id (" + Accounts(appData)[0] + ")");
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Json.Str(begin, "url")) { UseShellExecute = true });
                        r = FinishSignIn(home, appData, decl, session, 600, CancellationToken.None, "en");
                    }
                    finally { AbandonSignIn(session); }
                    var error = Json.Str(r, "error");
                    if (error != null)
                        throw new InvalidOperationException(CommandError(error) + (Json.Long(r, "wait_days") > 0 ? " (" + Json.Long(r, "wait_days") + " more days before an account can be replaced)" : ""));
                    o.WriteLine("licensed until " + When(Json.Long(r, "expires")));
                    ClaimAll(host);
                    return 0;
                }
                case "license-redeem":
                {
                    if (args.Length != 2) { o.WriteLine("usage: hd2qd license-redeem ISSUER CODE"); return 2; }
                    var decl = IssuerArg(home, library, args[0]);
                    var mine = Accounts(appData);
                    if (mine.Count > 0 && NormalizeCode(args[1]) != null)
                        o.WriteLine("the code goes to " + Json.Str(decl, "issuer") + ", the issuer of " + Json.Str(decl, "name") + "; it learns your game account id (" + mine[0] + ")");
                    var r = Redeem(home, appData, decl, args[1]);
                    var error = Json.Str(r, "error");
                    if (error == "no_account") throw new InvalidOperationException("no game account on this computer yet: start the game once, then activate");
                    if (error != null)
                        throw new InvalidOperationException(CommandError(error) + (Json.Long(r, "wait_days") > 0 ? " (" + Json.Long(r, "wait_days") + " more days before an account can be replaced)" : ""));
                    o.WriteLine("licensed until " + When(Json.Long(r, "expires")));
                    ClaimAll(host);
                    return 0;
                }
                case "license-renew":
                    var issuers = Issuers(library);
                    if (issuers.Count == 0) { o.WriteLine("no mod in the library needs a license"); return 0; }
                    bool force = args.Contains("--force");
                    foreach (var (decl, _, _) in issuers)
                    {
                        var r = Renew(home, appData, decl, force);
                        var error = Json.Str(r, "error");
                        o.WriteLine(Json.Str(decl, "issuer") + ": " + (error != null ? CommandError(error)
                            : Json.Bool(r, "renewed") ? "renewed until " + When(Json.Long(r, "expires"))
                            : "not due, or not signed in here"));
                    }
                    return 0;
                case "license-segments":
                {
                    ClaimAll(host, args.Contains("--force"));
                    bool none = true;
                    foreach (var m in library)
                    {
                        var path = Json.Str(m, "path");
                        if (path == null || !Directory.Exists(path)) continue;
                        if (!HasMemberContent(path)) continue;          // (1.10.0) segments and/or a payload
                        none = false;
                        var st = SegmentsState(home, appData, path);
                        // the version comes from the Name, so the name nearly always holds it already
                        var name = Json.Str(m, "name") ?? Path.GetFileName(path);
                        var ver = Json.Str(SegmentsOf(path), "version") ?? Json.Str(PayloadOf(path), "version");
                        if (ver != null && name.IndexOf(ver, StringComparison.Ordinal) < 0) name += " " + ver;
                        o.WriteLine(name + ": " + SegmentsCommandWords(st));
                    }
                    if (none) o.WriteLine("no mod in the library ships member content per game account");
                    o.WriteLine("log: " + LogPath(home));
                    return 0;
                }
                case "license-log-send":
                {
                    if (args.Length > 1) { o.WriteLine("usage: hd2qd license-log-send [ISSUER]"); return 2; }
                    Dictionary<string, object> decl;
                    if (args.Length == 1) decl = IssuerArg(home, library, args[0]);
                    else
                    {
                        var all = Known(home, library).Select(x => x.Decl).Where(d => !TestIssuer(Json.Str(d, "issuer"))).ToList();
                        if (all.Count != 1) { o.WriteLine(all.Count == 0 ? "no mod author in the library or signed in here" : "usage: hd2qd license-log-send ISSUER (license lists them)"); return 2; }
                        decl = all[0];
                    }
                    var manager = host.TryGetValue("version", out var mv) ? mv as string : null;
                    var r = SendLog(home, appData, decl, manager);
                    var code = Json.Str(r, "code");
                    if (code == null)
                        throw new InvalidOperationException(Json.Str(r, "error") == "rate" ? "too many logs sent today: try again tomorrow"
                            : Json.Str(r, "error") == "no_diag" ? Json.Str(decl, "issuer") + " takes no license logs"
                            : Json.Str(r, "error") == "empty" ? "nothing logged about " + Json.Str(decl, "issuer") + " yet"
                            : Json.Str(r, "error") == "test_issuer" ? CommandError("test_issuer") : CommandError(Json.Str(r, "error")));
                    o.WriteLine("sent to " + Json.Str(decl, "issuer") + ": code " + code + " (give it to the author; kept " + Json.Long(r, "days") + " days)");
                    o.WriteLine("log: " + LogPath(home));
                    return 0;
                }
                case "license-answer":
                    foreach (var (decl, _, _) in Issuers(library))
                    {
                        var r = Answer(home, appData, decl);
                        var error = Json.Str(r, "error");
                        o.WriteLine(Json.Str(decl, "issuer") + ": " + (error != null ? CommandError(error)
                            : Json.Bool(r, "answered") ? "answered, the issuer's time " + When(Json.Long(r, "time"))
                            : "nothing to answer (" + Json.Str(r, "why") + ")"));
                    }
                    return 0;
                case "license-logout":
                {
                    if (args.Length != 1) { o.WriteLine("usage: hd2qd license-logout ISSUER"); return 2; }
                    var decl = IssuerArg(home, library, args[0]);
                    Forget(home, appData, Json.Str(decl, "issuer"));
                    o.WriteLine("removed " + Json.Str(decl, "issuer") + "'s license and sign-in from this computer");
                    return 0;
                }
                default: return 2;
            }
        }

        static string SegmentsCommandWords(string st)
        {
            switch (st)
            {
                case "claimed": return "member content ready";
                case "missing": return "not downloaded yet";
                case "downloading": return "downloading now";
                case "pending": case "payload_pending": return "the author has not published this version's member content yet";
                case "not_signed_in": return "sign in first (license-login)";
                case "no_version": return "no vX.Y.Z in the mod's manifest.json Name";
                case "bad_receipt": return "the content received is not signed by the key the mod declares";
                case "update_manager": return "this mod needs a newer Member licenses plugin";
                default: return CommandError(st);
            }
        }

        static string When(long unix) => DateTimeOffset.FromUnixTimeSeconds(unix).ToLocalTime().ToString("yyyy-MM-dd HH:mm");

        /// <summary>An issuer by its name, or the issuer a mod uses (its name in the library).</summary>
        static Dictionary<string, object> IssuerArg(string home, List<Dictionary<string, object>> library, string reference)
        {
            var byName = Known(home, library).Where(x => string.Equals(Json.Str(x.Decl, "issuer"), reference, StringComparison.OrdinalIgnoreCase)).ToList();
            if (byName.Count > 1) throw new InvalidOperationException("mods declare " + reference + " with different keys: run `license` to see which");
            if (byName.Count == 1) return byName[0].Decl;
            var mod = library.FirstOrDefault(m => string.Equals(Json.Str(m, "name"), reference, StringComparison.OrdinalIgnoreCase))
                      ?? throw new InvalidOperationException("no issuer or mod " + reference + " (license lists them)");
            var d = Declaration(Json.Str(mod, "path"));
            if (d == null) throw new InvalidOperationException(Json.Str(mod, "name") + " needs no license");
            if (Json.Str(d, "error") != null) throw new InvalidOperationException(Json.Str(mod, "name") + "'s hd2_license.json cannot be read");
            return d;
        }

        static string CommandWords(Dictionary<string, object> st)
        {
            var until = st.ContainsKey("expires") ? When(Json.Long(st, "expires")) : null;
            switch (Json.Str(st, "state"))
            {
                case "licensed": return "licensed until " + until + (Json.Bool(st, "renew_due") ? " (due for renewal)" : "");
                case "expired": return "expired on " + until;
                case "none": return "not signed in here";
                case "other_account": return "the license here is for another game account";
                case "invalid": return "the license here is not signed by this issuer's key";
                case "key_changed": return "a mod declares another key than the one signed in with: check where it came from";
                case "no_account": return "no game account here yet: start the game once";
                case "test_issuer": return "a test build's issuer: there is no site to sign in to; use the author's released build";
                default: return Json.Str(st, "state");
            }
        }

        static string CommandError(string error)
        {
            switch (error)
            {
                case "not_member": return "the issuer says this account is not an active member (or its tier is too low)";
                case "account_limit": return "the membership has as many game accounts as the issuer allows: another can replace one some time after the last was added (the sign-in page says when), or ask the author to free one";
                case "banned": return "the creator has stopped licensing this membership or game account: contact the creator if this is a mistake";
                case "denied": return "access was not granted on the members' site";
                case "sign_in_again": case "unknown": return "the issuer asks to sign in again (license-login)";
                case "timeout": return "no answer from the sign-in within 10 minutes";
                case "network": return "the issuer cannot be reached";
                case "bad_license": return "the issuer's license is not signed by the key the mod declares";
                case "key_changed": return "a mod declares another key than the one signed in with: check where it came from";
                case "test_issuer": return "this is a test build's issuer: nobody can sign in there; use the author's released build";
                case "bad_code": return "not a valid activation code: check that it is complete and typed correctly (nothing was sent)";
                case "unknown_code": return "the issuer does not recognise this activation code (if you have just paid, try again in a minute)";
                case "no_codes": return "this issuer takes no activation codes: use license-login";
                case "account": return "this game account is not bound to the membership signed in here (license-login with it)";
                case "bad_answer": return "the issuer's answer is not signed by the key the mod declares";
                default: return "the sign-in failed: " + error;
            }
        }
    }
}
