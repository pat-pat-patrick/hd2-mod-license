using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Hd2Qd.License;
using Xunit;

namespace Hd2Qd.License.Tests
{
    /// <summary>The license plugin, called as the manager calls it, against an issuer on this
    /// computer that answers as the protocol says.</summary>
    public class LicensePlugin : IDisposable
    {
        const string A = "9ba626afa44a3aa3", B = "20bdec2a51065e1f";
        readonly string Root = Path.Combine(Path.GetTempPath(), "hd2lic_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        readonly string Home;
        readonly string appData;
        readonly Issuer issuer;
        readonly Dictionary<string, object> keys;

        public LicensePlugin()
        {
            Home = Path.Combine(Root, "home");
            Directory.CreateDirectory(Home);
            appData = Path.Combine(Root, "roaming");
            keys = (Dictionary<string, object>)Json.Parse(File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test_keys.json")));
            issuer = new Issuer(this);
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        }

        public void Dispose()
        {
            issuer.Dispose();
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            try { Directory.Delete(Root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }

        static void SetClock(Func<long> clock) => Plugin.Clock = clock;

        // the plugin's calls with this test's settings folder and AppData, as the manager makes them
        Dictionary<string, object> StateOf(string folder) => Plugin.StateOf(Home, appData, folder);
        Dictionary<string, object> Status(Dictionary<string, object> decl) => Plugin.Status(Home, appData, decl);
        List<string> Accounts() => Plugin.Accounts(appData);
        Dictionary<string, object> BeginSignIn(Dictionary<string, object> decl) => Plugin.BeginSignIn(appData, decl);
        Dictionary<string, object> FinishSignIn(Dictionary<string, object> decl, string session, TimeSpan wait, CancellationToken cancel) =>
            Plugin.FinishSignIn(Home, appData, decl, session, (int)wait.TotalSeconds, cancel, "en");
        Dictionary<string, object> Renew(Dictionary<string, object> decl, bool force) => Plugin.Renew(Home, appData, decl, force);
        void Forget(string issuerName) => Plugin.Forget(Home, appData, issuerName);

        /// <summary>The manager's library as the plugin is handed it: {name, path, enabled}.</summary>
        readonly List<Dictionary<string, object>> library = new List<Dictionary<string, object>>();
        void InLibrary(string name, string folder) => library.Add(new Dictionary<string, object> { ["name"] = name, ["path"] = folder, ["enabled"] = true });
        Dictionary<string, object> Host(string lang = "en") => new Dictionary<string, object>
        {
            ["home"] = Home, ["appdata"] = appData, ["lang"] = lang,
            ["library"] = (Func<List<Dictionary<string, object>>>)(() => library),
        };

        string KeyN(string name) => Json.Str(Json.Obj(keys, name), "n");

        /// <summary>A mod folder in the library with an hd2_license.json for our issuer.</summary>
        string LicensedMod(string name = "Licensed", string key = "a", string issuerName = null, string text = null)
        {
            var folder = Path.Combine(Root, "library", name);
            Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(folder, "hd2_license.json"), text ?? Json.Write(new Dictionary<string, object>
            {
                ["protocol"] = 1L, ["issuer"] = issuerName ?? issuer.Name, ["name"] = "Test Author", ["key"] = KeyN(key),
            }));
            return folder;
        }

        void Account(string id, int minutesAgo = 0)
        {
            var saves = Path.Combine(appData, "Arrowhead", "Helldivers2", "saves");
            Directory.CreateDirectory(saves);
            var f = Path.Combine(saves, id + "_user_settings.config");
            File.WriteAllText(f, "language = \"us\"");
            File.SetLastWriteTimeUtc(f, DateTime.UtcNow.AddMinutes(-minutesAgo));
        }

        string LicenseFile => Path.Combine(appData, "Arrowhead", "Helldivers2", "licenses", issuer.Name.Replace(':', '_') + ".txt");

        Dictionary<string, object> Decl(string folder) => Plugin.Declaration(folder);

        Dictionary<string, object> last;

        string SignIn(string folder)
        {
            var begin = BeginSignIn(Decl(folder));
            Assert.Null(Json.Str(begin, "error"));
            issuer.Opened(Json.Str(begin, "url"));
            var r = FinishSignIn(Decl(folder), Json.Str(begin, "session"), TimeSpan.FromSeconds(10), CancellationToken.None);
            issuer.BrowserDone();
            last = r;
            return Json.Str(r, "error") ?? "ok";
        }

        // -- loading -----------------------------------------------------------------------

        // -- declarations and accounts -----------------------------------------------------

        [Fact]
        public void A_declaration_is_read_and_a_wrong_one_is_said_as_wrong()
        {
            var d = Decl(LicensedMod());
            Assert.Equal(issuer.Name, Json.Str(d, "issuer"));
            Assert.Equal("Test Author", Json.Str(d, "name"));
            Assert.Equal(KeyN("a"), Json.Str(d, "key"));
            Assert.Equal("bad_declaration", Json.Str(Decl(LicensedMod("Short", text: "{\"protocol\":1,\"issuer\":\"x.test\",\"key\":\"abcd\"}")), "error"));
            Assert.Equal("bad_declaration", Json.Str(Decl(LicensedMod("Key1024", text: "{\"protocol\":1,\"issuer\":\"x.test\",\"key\":\"" + KeyN("a").Substring(0, 256) + "\"}")), "error"));
            Assert.Equal("bad_declaration", Json.Str(Decl(LicensedMod("V2", text: "{\"protocol\":2,\"issuer\":\"x.test\",\"key\":\"" + KeyN("a") + "\"}")), "error"));
            Assert.Equal("bad_declaration", Json.Str(Decl(LicensedMod("Path", issuerName: "..\\x")), "error"));
            Assert.Equal("bad_declaration", Json.Str(Decl(LicensedMod("Port", issuerName: "evil.test:8080")), "error"));
            Assert.Equal("bad_declaration", Json.Str(Decl(LicensedMod("Broken", text: "{")), "error"));
            Assert.Equal("bad_declaration", StateOf(Path.Combine(Root, "library", "Broken"))["state"]);
        }

        [Fact]
        public void Game_accounts_come_from_the_save_names_most_recent_first()
        {
            Assert.Empty(Accounts());
            Account(A, 60);
            Account(B, 1);
            var saves = Path.Combine(appData, "Arrowhead", "Helldivers2", "saves");
            File.WriteAllText(Path.Combine(saves, "user_settings.config"), "");
            File.WriteAllText(Path.Combine(saves, "nothex0000000000_user_settings.config"), "");
            File.WriteAllText(Path.Combine(saves, "0000000000000001_user_settings.config"), "");
            File.WriteAllText(Path.Combine(saves, A + "_user_settings.config.old"), "");
            Assert.Equal(new[] { B, A }, Accounts());
        }

        // -- signing in ----------------------------------------------------------------------

        [Fact]
        public void Signing_in_writes_the_license_where_the_mod_reads_it()
        {
            var mod = LicensedMod();
            Assert.Equal("no_account", Json.Str(StateOf(mod), "state"));
            Assert.Equal("no_account", Json.Str(BeginSignIn(Decl(mod)), "error"));
            Account(A);
            Assert.Equal("none", Json.Str(StateOf(mod), "state"));

            Assert.Equal("ok", SignIn(mod));
            Assert.Matches("^/login\\?c=[0-9a-f]{64}&s=[0-9a-f]{32}&port=[0-9]+&acct=" + A + "$", issuer.OpenedPath);
            Assert.Contains("You can close this page", issuer.BrowserPage);
            Assert.True(File.Exists(LicenseFile));
            Assert.StartsWith("HD2 MOD LICENSE 1\nissuer=" + issuer.Name + "\n", File.ReadAllText(LicenseFile));
            var st = StateOf(mod);
            Assert.Equal("licensed", Json.Str(st, "state"));
            Assert.False(Json.Bool(st, "renew_due"));
            Assert.Equal(new object[] { A }, Json.List(st, "accounts"));

            var store = File.ReadAllText(Path.Combine(Home, "licenses.json"));
            Assert.DoesNotContain(issuer.RenewToken, store);
            Assert.Contains(KeyN("a"), store);
        }

        [Fact]
        public void The_issuers_refusals_come_back_by_name()
        {
            var mod = LicensedMod();
            Account(A);
            foreach (var why in new[] { "not_member", "account_limit", "denied" })
            {
                issuer.ClaimError = why;
                Assert.Equal(why, SignIn(mod));
            }
            Assert.False(File.Exists(LicenseFile));
            issuer.ClaimError = "account_limit";
            issuer.WaitDays = 3;
            Assert.Equal("account_limit", SignIn(mod));
            Assert.Equal(3L, Json.Long(last, "wait_days"));
            Assert.Contains("in 3 days", issuer.BrowserPage);
        }

        // -- activation codes ----------------------------------------------------------------

        /// <summary>The code is checked here as the issuer's codes.js checks it: its codes pass,
        /// in any case, with spaces, and with O for 0 and I or L for 1; a typo does not.</summary>
        [Fact]
        public void An_activation_code_is_checked_here_as_the_issuer_checks_it()
        {
            // made by the issuer's codes.js make()
            foreach (var code in new[] { "G94PE-RCH4P-THXB5-21DB9", "B63BK-BQSN7-G7E3G-1MF3W", "RHJFT-FBB5Z-9005M-K49QB", "S9Z57-X4YM2-5CJPH-2FNJ2", "82QKS-Q2BMF-FEJ0V-B4TM0" })
                Assert.Equal(code.Replace("-", ""), Plugin.NormalizeCode(code));
            Assert.Equal("G94PERCH4PTHXB521DB9", Plugin.NormalizeCode(" g94pe rch4p thxb5 21db9 "));
            Assert.Equal("RHJFTFBB5Z9005MK49QB", Plugin.NormalizeCode("RHJFT-FBB5Z-9OO5M-K49QB"));
            Assert.Equal("B63BKBQSN7G7E3G1MF3W", Plugin.NormalizeCode("B63BK-BQSN7-G7E3G-LMF3W"));
            Assert.Null(Plugin.NormalizeCode("G94PE-RCH4P-THXB5-21DB8"));      // the check character
            Assert.Null(Plugin.NormalizeCode("G94PE-RCH4P-THXB6-21DB9"));      // one character
            Assert.Null(Plugin.NormalizeCode("G94PE-RCH4P-THXB5-21DB"));       // short
            Assert.Null(Plugin.NormalizeCode("G94PE-RCH4P-THXB5-21DBU"));      // U is not in the alphabet
            Assert.Null(Plugin.NormalizeCode(""));
            Assert.Null(Plugin.NormalizeCode(null));
        }

        [Fact]
        public void Activating_with_a_code_writes_the_license_as_a_sign_in_does()
        {
            var mod = LicensedMod();
            Assert.Equal("no_account", Json.Str(Plugin.Redeem(Home, appData, Decl(mod), "G94PE-RCH4P-THXB5-21DB9"), "error"));
            Account(A);
            issuer.Holder = "f:" + new string('a', 32);
            var r = Plugin.Redeem(Home, appData, Decl(mod), "g94pe rch4p thxb5 21db9");
            Assert.Null(Json.Str(r, "error"));
            Assert.Equal("G94PERCH4PTHXB521DB9", issuer.RedeemedCode);
            Assert.Equal(A, issuer.RedeemedAcct);
            Assert.Equal("licensed", Json.Str(StateOf(mod), "state"));
            Assert.Contains("holder=f:" + new string('a', 32), File.ReadAllText(LicenseFile));
            Assert.DoesNotContain(issuer.RenewToken, File.ReadAllText(Path.Combine(Home, "licenses.json")));

            // renewed later like any sign-in, with no code
            Assert.True(Json.Bool(Renew(Decl(mod), true), "renewed"));
            Assert.Equal(issuer.RenewToken, issuer.LastRenewToken);
        }

        [Fact]
        public void A_code_is_refused_by_name_and_a_mistyped_one_is_never_sent()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("bad_code", Json.Str(Plugin.Redeem(Home, appData, Decl(mod), "G94PE-RCH4P-THXB5-21DB8"), "error"));
            Assert.Equal(0, issuer.RedeemCalls);
            Assert.Equal("unknown_code", Json.Str(Plugin.Redeem(Home, appData, Decl(mod), "B63BK-BQSN7-G7E3G-1MF3W"), "error"));
            foreach (var why in new[] { "not_member", "banned" })
            {
                issuer.RedeemError = why;
                Assert.Equal(why, Json.Str(Plugin.Redeem(Home, appData, Decl(mod), issuer.KnownCode), "error"));
            }
            issuer.RedeemError = "account_limit";
            issuer.WaitDays = 4;
            var limit = Plugin.Redeem(Home, appData, Decl(mod), issuer.KnownCode);
            Assert.Equal("account_limit", Json.Str(limit, "error"));
            Assert.Equal(4L, Json.Long(limit, "wait_days"));
            issuer.RedeemError = null;
            issuer.NoRedeem = true;
            Assert.Equal("no_codes", Json.Str(Plugin.Redeem(Home, appData, Decl(mod), issuer.KnownCode), "error"));
            Assert.False(File.Exists(LicenseFile));
            issuer.NoRedeem = false;
            issuer.SignWith = "b";
            Assert.Equal("bad_license", Json.Str(Plugin.Redeem(Home, appData, Decl(mod), issuer.KnownCode), "error"));
            Assert.False(File.Exists(LicenseFile));
            Assert.Equal("test_issuer", Json.Str(Plugin.Redeem(Home, appData, Decl(LicensedMod("Test", issuerName: "issuer.test")), issuer.KnownCode), "error"));
        }

        [Fact]
        public void The_redeem_command_activates_and_says_until_when()
        {
            var mod = LicensedMod();
            InLibrary("Licensed", mod);
            Account(A);
            var o = new StringWriter();
            Assert.Equal(0, Plugin.Run("license-redeem", new[] { issuer.Name, issuer.KnownCode }, o, Host()));
            Assert.Contains("learns your game account id (" + A + ")", o.ToString());
            Assert.Contains("licensed until", o.ToString());
            var e = Assert.Throws<InvalidOperationException>(() => Plugin.Run("license-redeem", new[] { "Licensed", "G94PE-RCH4P-THXB5-21DB8" }, new StringWriter(), Host()));
            Assert.Contains("nothing was sent", e.Message);
            Assert.Equal(2, Plugin.Run("license-redeem", new[] { issuer.Name }, new StringWriter(), Host()));
        }

        /// <summary>The loopback sign-in: the browser comes back to this computer with a code,
        /// and the license is collected with the verifier only this computer has.</summary>
        [Fact]
        public void The_browser_comes_back_here_and_only_the_verifier_collects()
        {
            var mod = LicensedMod();
            Account(A);
            issuer.StrayFirst = true;                      // another page pokes the port first
            Assert.Equal("ok", SignIn(mod));
            Assert.Equal(2, issuer.StraysAnswered404);
            Assert.True(issuer.VerifierMatched);

            issuer.StrayFirst = false;
            issuer.SpoilVerifier = true;                   // what /claim does when the verifier is not the one
            Assert.Equal("unknown", SignIn(mod));
        }

        [Fact]
        public void An_abandoned_sign_in_stops_listening()
        {
            var mod = LicensedMod();
            Account(A);
            var begin = BeginSignIn(Decl(mod));
            int port = int.Parse(System.Text.RegularExpressions.Regex.Match(Json.Str(begin, "url"), "port=([0-9]+)").Groups[1].Value);
            Plugin.AbandonSignIn(Json.Str(begin, "session"));
            Assert.Throws<SocketException>(() => new TcpClient().Connect(IPAddress.Loopback, port));
            Assert.Equal("cancelled", Json.Str(FinishSignIn(Decl(mod), Json.Str(begin, "session"), TimeSpan.FromSeconds(1), CancellationToken.None), "error"));
        }

        [Fact]
        public void A_license_not_signed_by_the_declared_key_is_not_written()
        {
            var mod = LicensedMod();
            Account(A);
            issuer.SignWith = "b";
            Assert.Equal("bad_license", SignIn(mod));
            Assert.False(File.Exists(LicenseFile));
            Assert.False(File.Exists(Path.Combine(Home, "licenses.json")));
        }

        [Fact]
        public void An_issuer_that_does_not_answer_is_a_network_error()
        {
            var mod = LicensedMod();
            Account(A);
            var begin = BeginSignIn(Decl(mod));
            issuer.Opened(Json.Str(begin, "url"));         // the browser comes back with a code
            issuer.Dispose();                              // but the issuer cannot be reached to collect it
            var r = FinishSignIn(Decl(mod), Json.Str(begin, "session"), TimeSpan.FromSeconds(5), CancellationToken.None);
            Assert.Equal("network", Json.Str(r, "error"));
        }

        [Fact]
        public void Waiting_can_be_cancelled_and_runs_out()
        {
            var mod = LicensedMod();
            Account(A);
            issuer.BrowserComesBack = false;              // the player never finishes in the browser
            var begin = BeginSignIn(Decl(mod));
            issuer.Opened(Json.Str(begin, "url"));
            using (var cancel = new CancellationTokenSource(300))
                Assert.Equal("cancelled", Json.Str(FinishSignIn(Decl(mod), Json.Str(begin, "session"), TimeSpan.FromSeconds(30), cancel.Token), "error"));
            begin = BeginSignIn(Decl(mod));
            Assert.Equal("timeout", Json.Str(FinishSignIn(Decl(mod), Json.Str(begin, "session"), TimeSpan.Zero, CancellationToken.None), "error"));
        }

        // -- states --------------------------------------------------------------------------

        [Fact]
        public void Expiry_another_account_and_a_foreign_license_are_told_apart()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("ok", SignIn(mod));
            long expires = Json.Long(StateOf(mod), "expires");

            SetClock(() => expires - issuer.Days * 86400 / 2 + 1);
            Assert.True(Json.Bool(StateOf(mod), "renew_due"));
            SetClock(() => expires);
            Assert.Equal("expired", Json.Str(StateOf(mod), "state"));
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());

            File.Delete(Path.Combine(appData, "Arrowhead", "Helldivers2", "saves", A + "_user_settings.config"));
            Account(B);
            Assert.Equal("other_account", Json.Str(StateOf(mod), "state"));
            Account(A);

            File.WriteAllText(LicenseFile, issuer.License("b", new[] { A }, 30));
            Assert.Equal("invalid", Json.Str(StateOf(mod), "state"));
        }

        [Fact]
        public void A_mod_declaring_another_key_for_a_signed_in_issuer_is_flagged()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("ok", SignIn(mod));
            var other = LicensedMod("Other", key: "b");
            Assert.Equal("key_changed", Json.Str(StateOf(other), "state"));
            Assert.Equal("key_changed", Json.Str(Renew(Decl(other), true), "error"));
            Assert.Equal("licensed", Json.Str(StateOf(mod), "state"));
        }

        // -- renewing and signing out ---------------------------------------------------------

        [Fact]
        public void Renewal_waits_for_half_time_and_follows_the_issuer()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.False(Json.Bool(Renew(Decl(mod), false), "renewed"));   // never signed in
            Assert.Equal("ok", SignIn(mod));
            int calls = issuer.RenewCalls;
            Assert.False(Json.Bool(Renew(Decl(mod), false), "renewed"));
            Assert.Equal(calls, issuer.RenewCalls);

            var r = Renew(Decl(mod), true);
            Assert.True(Json.Bool(r, "renewed"));
            Assert.Equal(calls + 1, issuer.RenewCalls);
            Assert.Equal(issuer.RenewToken, issuer.LastRenewToken);

            issuer.RenewError = "not_member";
            Assert.Equal("not_member", Json.Str(Renew(Decl(mod), true), "error"));
            Assert.Equal("licensed", Json.Str(StateOf(mod), "state"));      // the old one runs out on its own
        }

        [Fact]
        public void Signing_out_removes_the_license_and_the_token()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("ok", SignIn(mod));
            Forget(issuer.Name);
            Assert.False(File.Exists(LicenseFile));
            Assert.Equal("none", Json.Str(StateOf(mod), "state"));
            Assert.False(Json.Bool(Renew(Decl(mod), true), "renewed"));
            // and another key is welcome again
            Assert.Equal("none", Json.Str(StateOf(LicensedMod("Other", key: "b")), "state"));
        }

        int LicensesInFile() =>
            System.Text.RegularExpressions.Regex.Matches(File.ReadAllText(LicenseFile), "^HD2 MOD LICENSE 1$", System.Text.RegularExpressions.RegexOptions.Multiline).Count;

        [Fact]
        public void Two_members_sharing_a_computer_each_keep_their_license()
        {
            var mod = LicensedMod();
            Account(A, 10);
            Assert.Equal("ok", SignIn(mod));                                       // member 1, game account A
            Account(B);                                                            // member 2 plays on B
            issuer.Holder = "p:2";
            issuer.Accounts = new[] { B };
            issuer.RenewToken = new string('8', 64);
            Assert.Equal("ok", SignIn(mod));
            Assert.Equal(2, LicensesInFile());
            var st = StateOf(mod);
            Assert.Equal("licensed", Json.Str(st, "state"));
            Assert.Equal(2L, Json.Long(st, "members"));

            File.Delete(Path.Combine(appData, "Arrowhead", "Helldivers2", "saves", B + "_user_settings.config"));
            Assert.Equal("licensed", Json.Str(StateOf(mod), "state"));   // A alone: member 1's still there
            Assert.Equal(new object[] { A }, Json.List(StateOf(mod), "accounts"));

            issuer.Holder = "p:1";                                                 // member 1 signs in again
            issuer.Accounts = new[] { A };
            issuer.RenewToken = new string('9', 64);
            Assert.Equal("ok", SignIn(mod));
            Assert.Equal(2, LicensesInFile());                                     // theirs replaced, not added

            int before = issuer.RenewCalls;
            Assert.True(Json.Bool(Renew(Decl(mod), true), "renewed"));
            Assert.Equal(before + 2, issuer.RenewCalls);                           // both members renewed
            Assert.Contains(new string('9', 64), issuer.Renewed);
            Assert.Contains(new string('8', 64), issuer.Renewed);
            Assert.Equal(2, LicensesInFile());
            var store = File.ReadAllText(Path.Combine(Home, "licenses.json"));
            Assert.Contains("p:1", store);
            Assert.Contains("p:2", store);
        }

        [Fact]
        public void A_renew_token_kept_before_members_were_told_apart_is_filed_under_its_member()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("ok", SignIn(mod));
            // as a sign-in before 2026-11-02 left it: one token for the whole issuer
            var path = Path.Combine(Home, "licenses.json");
            var store = (Dictionary<string, object>)Json.Parse(File.ReadAllText(path));
            var rec = Json.Obj(Json.Obj(store, "issuers"), issuer.Name);
            rec["renew"] = Json.Obj(rec, "members")["p:1"];
            rec.Remove("members");
            File.WriteAllText(path, Json.Write(store));

            int before = issuer.RenewCalls;
            Assert.True(Json.Bool(Renew(Decl(mod), false), "renewed"));  // not due, but whose it is was unknown
            Assert.Equal(before + 1, issuer.RenewCalls);
            rec = Json.Obj(Json.Obj((Dictionary<string, object>)Json.Parse(File.ReadAllText(path)), "issuers"), issuer.Name);
            Assert.Null(Json.Str(rec, "renew"));
            Assert.NotNull(Json.Str(Json.Obj(rec, "members"), "p:1"));
            Assert.False(Json.Bool(Renew(Decl(mod), false), "renewed"));  // and now waits for half time
            Assert.Equal(before + 1, issuer.RenewCalls);
        }

        [Fact]
        public void A_sign_in_stays_known_after_its_mods_leave_the_library()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Empty(Plugin.Known(Home, library));                          // no mod in the library, none signed in
            Assert.Equal("ok", SignIn(mod));
            var known = Plugin.Known(Home, library);
            Assert.Single(known);
            Assert.Empty(known[0].Mods);
            Assert.Equal(issuer.Name, Json.Str(known[0].Decl, "issuer"));
            Assert.Equal("Test Author", Json.Str(known[0].Decl, "name"));
            Assert.Equal("licensed", Json.Str(Status(known[0].Decl), "state"));

            InLibrary("Licensed", mod);
            known = Plugin.Known(Home, library);
            Assert.Single(known);                                                  // the library's, not twice
            Assert.Equal(new[] { "Licensed" }, known[0].Mods);

            Forget(issuer.Name);
            library.Clear();
            Assert.Empty(Plugin.Known(Home, library));
        }

        /// <summary>The word on a mod's row: needs a license until signed in, nothing once
        /// licensed, nothing for a mod that needs none.</summary>
        [Fact]
        public void A_mod_row_says_it_needs_a_license_until_signed_in()
        {
            Account(A);
            var mod = LicensedMod();
            var note = Plugin.ModNote(mod, Host());
            Assert.Equal("Needs a license", Json.Str(note, "text"));
            Assert.Equal("需要授权", Json.Str(Plugin.ModNote(mod, Host("zh-CN")), "text"));
            Assert.Equal("仅供创作者的会员使用：请在「插件」页登录（齿轮旁的拼图按钮）。", Json.Str(Plugin.ModNote(mod, Host("zh-CN")), "tip"));
            Assert.Equal("Needs a license", Json.Str(Plugin.ModNote(mod, Host("de-AT")), "text"));   // no German: English
            Assert.Equal("Needs a license", Json.Str(Plugin.ModNote(mod, new Dictionary<string, object> { ["home"] = Home, ["appdata"] = appData }), "text"));
            Assert.Equal("ok", SignIn(mod));
            Assert.Null(Plugin.ModNote(mod, Host()));
            Directory.CreateDirectory(Path.Combine(Root, "library", "Free"));
            Assert.Null(Plugin.ModNote(Path.Combine(Root, "library", "Free"), Host()));
        }

        /// <summary>A test build declares an issuer reserved for tests (issuer.test): there is no
        /// site to sign in to, so it says so instead of offering a sign-in that can only fail. The
        /// same author's released build (a real issuer) still signs in.</summary>
        [Fact]
        public void A_test_builds_issuer_offers_no_sign_in()
        {
            foreach (var name in new[] { "issuer.test", "x.example", "a.invalid", "dev.localhost", "example.com", "lic.example.org", "test" })
                Assert.True(Plugin.TestIssuer(name), name);
            foreach (var name in new[] { "license.patpatpatrick.com", "contest.com", "latest.net", "notexample.com", "localhost:8787", "127.0.0.1:8787", issuer.Name })
                Assert.False(Plugin.TestIssuer(name), name);

            Account(A);
            var test = LicensedMod("Gate test", issuerName: "issuer.test");
            Assert.Equal("test_issuer", Json.Str(StateOf(test), "state"));
            Assert.Equal("test_issuer", Json.Str(BeginSignIn(Decl(test)), "error"));
            var note = Plugin.ModNote(test, Host());
            Assert.Equal("Test build", Json.Str(note, "text"));
            Assert.Equal("测试版", Json.Str(Plugin.ModNote(test, Host("zh-CN")), "text"));
            InLibrary("Gate test", test);
            var ex = Assert.Throws<InvalidOperationException>(() => Plugin.Run("license-login", new[] { "issuer.test" }, new StringWriter(), Host()));
            Assert.Contains("test build", ex.Message);
            var o = new StringWriter();
            Plugin.Run("license", new string[0], o, Host());
            Assert.Contains("Test Author (issuer.test): a test build's issuer", o.ToString());

            // a license the author signed by hand for their test build still counts
            var file = Path.Combine(appData, "Arrowhead", "Helldivers2", "licenses", "issuer.test.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(file));
            File.WriteAllText(file, issuer.License("a", new[] { A }, 30, issuerName: "issuer.test"));
            Assert.Equal("licensed", Json.Str(StateOf(test), "state"));
            Assert.Null(Plugin.ModNote(test, Host()));

            // the released build of the same author signs in as before
            var released = LicensedMod("Released");
            Assert.Equal("none", Json.Str(StateOf(released), "state"));
            Assert.Equal("ok", SignIn(released));
            Assert.Equal("licensed", Json.Str(StateOf(released), "state"));
        }

        // -- the online check (1.5.0, spec section 7) ---------------------------------------

        string AskFile => Path.Combine(appData, "Arrowhead", "Helldivers2", "licenses", issuer.Name.Replace(':', '_') + ".ask");
        string AttestFile => Path.Combine(appData, "Arrowhead", "Helldivers2", "licenses", issuer.Name.Replace(':', '_') + ".attest");

        /// <summary>The question a mod writes at its start.</summary>
        void Ask(string nonce, string account, int minutesAgo = 0)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(AskFile));
            File.WriteAllText(AskFile, "HD2 MOD ASK 1\nnonce=" + nonce + "\naccount=" + account + "\n");
            File.SetLastWriteTimeUtc(AskFile, DateTime.UtcNow.AddMinutes(-minutesAgo));
        }

        Dictionary<string, object> AnswerNow(string folder) => Plugin.Answer(Home, appData, Decl(folder));

        [Fact]
        public void A_mods_question_is_answered_signed_and_only_once()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("no_question", Json.Str(AnswerNow(mod), "why"));
            Assert.Equal("ok", SignIn(mod));
            var n = new string('a', 32);
            Ask(n, A);
            var r = AnswerNow(mod);
            Assert.True(Json.Bool(r, "answered"));
            Assert.Equal(n, issuer.LastAttestNonce);
            Assert.StartsWith("HD2 MOD ATTEST 1\nissuer=" + issuer.Name + "\nnonce=" + n + "\naccount=" + A + "\n", File.ReadAllText(AttestFile));
            Assert.Contains("\nsig=", File.ReadAllText(AttestFile));
            int calls = issuer.AttestCalls;
            Assert.Equal("answered", Json.Str(AnswerNow(mod), "why"));      // the same question: not asked again
            Ask(new string('b', 32), A, minutesAgo: 11);
            Assert.Equal("old", Json.Str(AnswerNow(mod), "why"));           // from a game that ended long ago
            File.WriteAllText(AskFile, "HD2 MOD ASK 1\nnonce=xyz\naccount=" + A + "\n");
            Assert.Equal("malformed", Json.Str(AnswerNow(mod), "why"));
            Assert.Equal(calls, issuer.AttestCalls);
        }

        [Fact]
        public void An_answer_not_signed_by_the_declared_key_is_not_written()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("ok", SignIn(mod));
            issuer.SignWith = "b";
            Ask(new string('a', 32), A);
            Assert.Equal("bad_answer", Json.Str(AnswerNow(mod), "error"));
            Assert.Contains("error=bad_answer", File.ReadAllText(AttestFile));
            Assert.DoesNotContain("sig=", File.ReadAllText(AttestFile));
        }

        [Fact]
        public void A_refusal_is_written_for_the_mod_and_no_answer_leaves_the_last_one()
        {
            var mod = LicensedMod();
            Account(A);
            issuer.Accounts = new[] { A, B };                               // both places taken
            Assert.Equal("ok", SignIn(mod));
            Ask(new string('c', 32), A);
            Assert.True(Json.Bool(AnswerNow(mod), "answered"));
            var good = File.ReadAllText(AttestFile);

            issuer.AttestError = "not_member";
            Ask(new string('d', 32), A);
            Assert.Equal("not_member", Json.Str(AnswerNow(mod), "error"));
            Assert.Equal("HD2 MOD ATTEST 1\nnonce=" + new string('d', 32) + "\nerror=not_member\n", File.ReadAllText(AttestFile));
            issuer.AttestError = null;

            Ask(new string('e', 32), "1234567890abcdef");                   // a third account: no place free
            Assert.Equal("account", Json.Str(AnswerNow(mod), "error"));

            File.WriteAllText(AttestFile, good);
            Ask(new string('f', 32), A);
            issuer.Dispose();                                                // the issuer cannot be reached
            Assert.Equal("network", Json.Str(AnswerNow(mod), "error"));
            Assert.Equal(good, File.ReadAllText(AttestFile));               // the last answer stays: the mod's grace
        }

        [Fact]
        public void A_second_account_is_bound_by_its_question_and_its_license_written()
        {
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("ok", SignIn(mod));                                // bound: A alone
            Ask(new string('a', 32), B);                                     // HellForge's account: the Steam ID
            Assert.True(Json.Bool(AnswerNow(mod), "answered"));
            Assert.Contains("account=" + B, File.ReadAllText(AttestFile));
            Assert.Contains("accounts=" + A + "," + B + "\n", File.ReadAllText(LicenseFile));
            Assert.Single(Regex.Matches(File.ReadAllText(LicenseFile), "HD2 MOD LICENSE 1"));   // the member's own replaced
        }

        [Fact]
        public void The_Steam_ID_the_game_showed_goes_with_the_question_and_nothing_else_does()
        {
            // (2026-11-17) the official game shows the Steam ID before the account: the issuer
            // keeps it beside the account, so HellForge (whose account it is) takes no place
            var mod = LicensedMod();
            Account(A);
            Assert.Equal("ok", SignIn(mod));
            Directory.CreateDirectory(Path.GetDirectoryName(AskFile));
            File.WriteAllText(AskFile, "HD2 MOD ASK 1\nnonce=" + new string('a', 32) + "\naccount=" + A + "\nsteam=0110000100abcdef\n");
            Assert.True(Json.Bool(AnswerNow(mod), "answered"));
            Assert.Equal("0110000100abcdef", issuer.LastAttestSteam);
            File.WriteAllText(AskFile, "HD2 MOD ASK 1\nnonce=" + new string('b', 32) + "\naccount=" + A + "\nsteam=0220000100abcdef\n");
            Assert.True(Json.Bool(AnswerNow(mod), "answered"));               // no Steam ID: the question stands without it
            Assert.Null(issuer.LastAttestSteam);
        }

        [Fact]
        public void Nobody_signed_in_here_is_told_to_sign_in()
        {
            var mod = LicensedMod();
            Account(A);
            Ask(new string('a', 32), A);
            Assert.Equal("sign_in_again", Json.Str(AnswerNow(mod), "error"));
            Assert.Equal(0, issuer.AttestCalls);
            Assert.Contains("error=sign_in_again", File.ReadAllText(AttestFile));
        }

        [Fact]
        public void The_manager_answers_a_question_as_soon_as_a_mod_writes_it()
        {
            var mod = LicensedMod();
            InLibrary("Licensed", mod);
            Account(A);
            Assert.Equal("ok", SignIn(mod));
            Plugin.Watch(Host());
            var n = new string('9', 32);
            Ask(n, A);
            var until = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < until && !(File.Exists(AttestFile) && File.ReadAllText(AttestFile).Contains("nonce=" + n))) Thread.Sleep(50);
            Assert.Contains("nonce=" + n, File.ReadAllText(AttestFile));
        }

        /// <summary>The name and summary in the language the manager asks for (Api 2: a language
        /// tag), by the tag, then its language alone, then English.</summary>
        [Fact]
        public void The_title_and_summary_follow_the_language_tag()
        {
            Assert.Equal(2, Plugin.Api);
            Assert.Equal("Member licenses", Plugin.Title("en"));
            Assert.Equal("会员授权", Plugin.Title("zh-CN"));
            Assert.Equal("Member licenses", Plugin.Title("zh-TW"));             // no zh-TW and no zh file: English
            Assert.Equal("Member licenses", Plugin.Title("de"));
            Assert.Equal("Member licenses", Plugin.Title(null));
            Assert.Equal("部分 MOD 仅供创作者的会员使用。首次使用需在创作者的网站登录，或输入创作者提供的激活码，授权到期前将自动续期。", Plugin.Summary("zh-CN"));
            Assert.StartsWith("Some mods are available only to their author's members.", Plugin.Summary("de"));
        }

        /// <summary>Its commands, as the manager's command line runs them.</summary>
        [Fact]
        public void The_license_command_lists_each_issuer_and_its_mods()
        {
            Account(A);
            InLibrary("Licensed", LicensedMod());
            var o = new StringWriter();
            Assert.Equal(0, Plugin.Run("license", new string[0], o, Host()));
            Assert.Contains("Test Author (" + issuer.Name + "): not signed in here", o.ToString());
            Assert.Contains("mods: Licensed", o.ToString());
            Assert.Equal(new[] { "license", "license-login", "license-redeem", "license-renew", "license-answer", "license-logout" }, Plugin.Commands.Select(c => c[0]));
        }

        /// <summary>At the manager's start a license half way to its end is renewed.</summary>
        [Fact]
        public void The_start_renews_what_is_due()
        {
            Account(A);
            var mod = LicensedMod();
            InLibrary("Licensed", mod);
            Assert.False(Plugin.Start(Host()));                                    // never signed in
            Assert.Equal("ok", SignIn(mod));
            long expires = Json.Long(StateOf(mod), "expires");
            SetClock(() => expires - issuer.Days * 86400 / 2 + 1);
            Assert.True(Plugin.Start(Host()));
        }

        // -- an issuer on this computer --------------------------------------------------------

        /// <summary>Answers /claim and /renew as a Worker would, signing with a test key. The
        /// "browser" is the test: Opened() reads the nonce from the login address.</summary>
        sealed class Issuer : IDisposable
        {
            readonly LicensePlugin t;
            readonly TcpListener listener;
            readonly Thread thread;
            volatile bool stopped;
            public readonly string Name;
            public string OpenedPath, ClaimError, RenewError, SignWith = "a", LastRenewToken, BrowserPage;
            public long WaitDays;
            /// <summary>The browser: whether it comes back from the sign-in at all, whether another
            /// page pokes the port first, and what it saw.</summary>
            public bool BrowserComesBack = true, StrayFirst, SpoilVerifier, VerifierMatched;
            public int StraysAnswered404;
            Task browser = Task.CompletedTask;
            /// <summary>Codes given to the browser, with the challenge of the sign-in they end.</summary>
            readonly Dictionary<string, string> codes = new Dictionary<string, string>();
            /// <summary>Who signs in next: their holder, accounts and renew token.</summary>
            public string Holder = "p:1", RenewToken = new string('7', 64);
            public string[] Accounts = { A };
            /// <summary>Every member signed in so far, by renew token: what renewal signs for.</summary>
            public readonly Dictionary<string, (string Holder, string[] Accounts)> Members = new Dictionary<string, (string, string[])>();
            public readonly List<string> Renewed = new List<string>();
            public int RenewCalls;
            /// <summary>/redeem: the one code it knows (made by the issuer's codes.js), what came,
            /// and how it answers instead (an error, or 404 as an issuer without codes).</summary>
            public string KnownCode = "G94PERCH4PTHXB521DB9", RedeemedCode, RedeemedAcct, RedeemError;
            public bool NoRedeem;
            public int RedeemCalls;
            /// <summary>/attest: what it was asked, and the refusal it gives instead of an answer.</summary>
            public int AttestCalls;
            public string AttestError, LastAttestNonce, LastAttestSteam;
            public readonly int Days = 30;

            public Issuer(LicensePlugin t)
            {
                this.t = t;
                listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                Name = "127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
                thread = new Thread(Serve) { IsBackground = true };
                thread.Start();
            }

            /// <summary>The browser opens the sign-in address; the member signs in at once, and the
            /// issuer sends the browser back to the manager's port, in the background.</summary>
            public void Opened(string url)
            {
                var u = new Uri(url);
                OpenedPath = u.PathAndQuery;
                var q = u.Query.TrimStart('?').Split('&').Select(p => p.Split('=')).ToDictionary(p => p[0], p => p[1]);
                if (!BrowserComesBack) return;
                string back;
                if (ClaimError != null)
                    back = "error=" + ClaimError + (WaitDays > 0 ? "&wait_days=" + WaitDays : "");
                else
                {
                    var code = Guid.NewGuid().ToString("N");
                    lock (codes) codes[code] = q["c"];
                    back = "code=" + code;
                }
                int port = int.Parse(q["port"]);
                string state = q["s"];
                bool stray = StrayFirst;
                browser = Task.Run(() =>
                {
                    if (stray)
                    {
                        if (Get(port, "/favicon.ico").StartsWith("HTTP/1.1 404")) StraysAnswered404++;
                        if (Get(port, "/done?s=" + new string('0', 32) + "&code=" + new string('1', 32)).StartsWith("HTTP/1.1 404")) StraysAnswered404++;
                    }
                    BrowserPage = Get(port, "/done?s=" + state + "&" + back);
                });
            }

            public void BrowserDone() => browser.Wait(5000);

            static string Get(int port, string target)
            {
                using (var c = new TcpClient())
                {
                    c.Connect(IPAddress.Loopback, port);
                    var s = c.GetStream();
                    var req = Encoding.ASCII.GetBytes("GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nConnection: close\r\n\r\n");
                    s.Write(req, 0, req.Length);
                    using (var reader = new StreamReader(s, Encoding.UTF8)) return reader.ReadToEnd();
                }
            }

            static string Sha256Hex(string text)
            {
                using (var sha = SHA256.Create()) return string.Concat(sha.ComputeHash(Encoding.ASCII.GetBytes(text)).Select(b => b.ToString("x2")));
            }

            public string License(string key, string[] accounts, int days, string holder = "p:1", string issuerName = null)
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var text = "HD2 MOD LICENSE 1\nissuer=" + (issuerName ?? Name) + "\naccounts=" + string.Join(",", accounts) +
                           "\nissued=" + now + "\nexpires=" + (now + days * 86400L) + "\nholder=" + holder + "\n";
                var pkcs8 = Convert.FromBase64String(Json.Str(Json.Obj(t.keys, key), "pkcs8"));
                using (var rsa = new RSACng(CngKey.Import(pkcs8, CngKeyBlobFormat.Pkcs8PrivateBlob)))
                {
                    var sig = rsa.SignData(Encoding.UTF8.GetBytes(text), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    return text + "sig=" + string.Concat(sig.Select(b => b.ToString("x2"))) + "\n";
                }
            }

            public string Attest(string key, string nonce, string account, string holder, long time)
            {
                var text = "HD2 MOD ATTEST 1" + NL + "issuer=" + Name + NL + "nonce=" + nonce + NL + "account=" + account + NL +
                           "time=" + time + NL + "holder=" + holder + NL;
                var pkcs8 = Convert.FromBase64String(Json.Str(Json.Obj(t.keys, key), "pkcs8"));
                using (var rsa = new RSACng(CngKey.Import(pkcs8, CngKeyBlobFormat.Pkcs8PrivateBlob)))
                {
                    var sig = rsa.SignData(Encoding.UTF8.GetBytes(text), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    return text + "sig=" + string.Concat(sig.Select(b => b.ToString("x2"))) + NL;
                }
            }

            static readonly string NL = ((char)10).ToString();

            (int, object) Answer(string path, Dictionary<string, object> body)
            {
                if (path == "/attest")
                {
                    AttestCalls++;
                    LastAttestNonce = Json.Str(body, "nonce");
                    LastAttestSteam = Json.Str(body, "steam");
                    if (AttestError != null) return (403, new Dictionary<string, object> { ["error"] = AttestError });
                    if (!Members.TryGetValue(Json.Str(body, "renew") ?? "", out var am)) return (403, new Dictionary<string, object> { ["error"] = "unknown" });
                    var acct = Json.Str(body, "account");
                    if (!am.Accounts.Contains(acct))
                    {
                        // as the issuer: a free place binds the account, and its license comes along
                        if (am.Accounts.Length >= 2) return (403, new Dictionary<string, object> { ["error"] = "account" });
                        am = (am.Holder, am.Accounts.Concat(new[] { acct }).ToArray());
                        Members[Json.Str(body, "renew")] = am;
                        return (200, new Dictionary<string, object>
                        {
                            ["attest"] = Attest(SignWith, LastAttestNonce, acct, am.Holder, DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
                            ["license"] = License(SignWith, am.Accounts, Days, am.Holder),
                        });
                    }
                    return (200, new Dictionary<string, object> { ["attest"] = Attest(SignWith, LastAttestNonce, Json.Str(body, "account"), am.Holder, DateTimeOffset.UtcNow.ToUnixTimeSeconds()) });
                }
                if (path == "/claim")
                {
                    string code = Json.Str(body, "code"), verifier = Json.Str(body, "verifier"), challenge;
                    lock (codes)
                    {
                        if (code == null || !codes.TryGetValue(code, out challenge)) return (403, new Dictionary<string, object> { ["error"] = "unknown" });
                        codes.Remove(code);
                    }
                    VerifierMatched = verifier != null && Sha256Hex(verifier) == challenge;
                    if (!VerifierMatched || SpoilVerifier) return (403, new Dictionary<string, object> { ["error"] = "unknown" });
                    Members[RenewToken] = (Holder, Accounts);
                    return (200, new Dictionary<string, object> { ["license"] = License(SignWith, Accounts, Days, Holder), ["renew"] = RenewToken });
                }
                if (path == "/redeem")
                {
                    RedeemCalls++;
                    if (NoRedeem) return (404, new Dictionary<string, object> { ["error"] = "not_found" });
                    RedeemedCode = Json.Str(body, "code");
                    RedeemedAcct = Json.Str(body, "acct");
                    if (RedeemError != null)
                        return (403, new Dictionary<string, object> { ["error"] = RedeemError, ["wait_days"] = WaitDays });
                    if (RedeemedCode != KnownCode) return (403, new Dictionary<string, object> { ["error"] = "unknown_code" });
                    Members[RenewToken] = (Holder, Accounts);
                    return (200, new Dictionary<string, object> { ["license"] = License(SignWith, Accounts, Days, Holder), ["renew"] = RenewToken });
                }
                if (path == "/renew")
                {
                    RenewCalls++;
                    LastRenewToken = Json.Str(body, "renew");
                    Renewed.Add(LastRenewToken);
                    if (RenewError != null) return (403, new Dictionary<string, object> { ["error"] = RenewError });
                    if (!Members.TryGetValue(LastRenewToken, out var m)) return (403, new Dictionary<string, object> { ["error"] = "unknown" });
                    return (200, new Dictionary<string, object> { ["license"] = License(SignWith, m.Accounts, Days, m.Holder) });
                }
                return (404, new Dictionary<string, object> { ["error"] = "not_found" });
            }

            void Serve()
            {
                while (!stopped)
                {
                    TcpClient c;
                    try { c = listener.AcceptTcpClient(); }
                    catch (SocketException) { return; }
                    catch (ObjectDisposedException) { return; }
                    using (c)
                    using (var s = c.GetStream())
                    {
                        var head = new StringBuilder();
                        while (!head.ToString().EndsWith("\r\n\r\n"))
                        {
                            int b = s.ReadByte();
                            if (b < 0) break;
                            head.Append((char)b);
                        }
                        var lines = head.ToString().Split(new[] { "\r\n" }, StringSplitOptions.None);
                        var path = lines[0].Split(' ')[1];
                        int length = lines.Where(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                                          .Select(l => int.Parse(l.Substring(15).Trim())).FirstOrDefault();
                        var buf = new byte[length];
                        for (int got = 0; got < length;) got += s.Read(buf, got, length - got);
                        var (status, answer) = Answer(path, Json.Parse(Encoding.UTF8.GetString(buf)) as Dictionary<string, object>);
                        var bytes = Encoding.UTF8.GetBytes(Json.Write(answer));
                        var reply = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\nContent-Length: " +
                                                            bytes.Length + "\r\nConnection: close\r\n\r\n");
                        s.Write(reply, 0, reply.Length);
                        s.Write(bytes, 0, bytes.Length);
                    }
                }
            }

            public void Dispose()
            {
                stopped = true;
                listener.Stop();
            }
        }
    }
}
