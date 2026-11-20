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
            Assert.Equal(new[] { "license", "license-login", "license-redeem", "license-renew", "license-segments", "license-answer", "license-log-send", "license-logout" }, Plugin.Commands.Select(c => c[0]));
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

        // -- (1.6.0) per-account segments ------------------------------------------------------

        /// <summary>A licensed mod that ships its Lua as segments: hd2_license.json with
        /// "segments", and the version in manifest.json's Name.</summary>
        string SealedMod(string version = "v1.2.0", string name = "Sealed", string id = "sealed-mod", int count = 8, bool c1 = false)
        {
            var folder = Path.Combine(Root, "library", name);
            Directory.CreateDirectory(folder);
            var seg = new Dictionary<string, object> { ["id"] = id, ["count"] = (long)count };
            if (c1) seg["sealed"] = 1L;
            File.WriteAllText(Path.Combine(folder, "hd2_license.json"), Json.Write(new Dictionary<string, object>
            {
                ["protocol"] = 1L, ["issuer"] = issuer.Name, ["name"] = "Test Author", ["key"] = KeyN("a"),
                ["segments"] = seg, ["integrity"] = 1L,
            }));
            File.WriteAllText(Path.Combine(folder, "manifest.json"), "{\"Version\":1,\"Name\":\"" + name + " " + version + "\"}");
            if (c1) issuer.Seal(version);
            return folder;
        }

        // -- (1.10.0) payloads (spec/static-resources draft 2) ----------------------------------

        /// <summary>A mod with a payload {kind, id, version?, deploy} (and segments when given), and
        /// the issuer serving its plaintext. 200 kB, so the download crosses many reads.</summary>
        string PayloadMod(string name = "Payload", string version = "v0.12.0", string deploy = "licenses/clips.lua", Dictionary<string, object> seg = null, byte[] plain = null)
        {
            var folder = Path.Combine(Root, "library", name);
            Directory.CreateDirectory(folder);
            var pay = new Dictionary<string, object> { ["kind"] = "static", ["id"] = "callouts", ["deploy"] = deploy };
            if (version != null) pay["version"] = version;
            var decl = new Dictionary<string, object>
            {
                ["protocol"] = 1L, ["issuer"] = issuer.Name, ["name"] = "Test Author", ["key"] = KeyN("a"), ["payload"] = pay,
            };
            if (seg != null) decl["segments"] = seg;
            File.WriteAllText(Path.Combine(folder, "hd2_license.json"), Json.Write(decl));
            File.WriteAllText(Path.Combine(folder, "manifest.json"), "{\"Version\":1,\"Name\":\"" + name + "\"}");
            issuer.Publish(version == null ? "callouts" : "callouts." + version, plain ?? ClipsText("en"));
            return folder;
        }

        static byte[] ClipsText(string tag) =>
            Encoding.UTF8.GetBytes("CLIPS = { " + tag + " = { e = \"" + string.Concat(Enumerable.Range(0, 20000).Select(i => (char)('A' + i % 26))) + "\" } } -- é\n" + new string('x', 180000));

        string PayDir(string version = "v0.12.0") =>
            Path.Combine(appData, "Arrowhead", "Helldivers2", "licenses", issuer.Name.Replace(':', '_'), "payload", "callouts", version ?? "_");

        /// <summary>Signed in, the payload mod in the library, fetched.</summary>
        string ClaimedPayload(out string mod, string version = "v0.12.0")
        {
            Account(A);
            mod = PayloadMod(version: version);
            InLibrary("Payload", mod);
            Assert.Equal("ok", SignIn(mod));
            Assert.True(Plugin.ClaimAll(Host()));
            return PayDir(version);
        }

        [Fact]
        public void A_payload_is_fetched_sealed_and_no_plaintext_is_written()
        {
            var dir = ClaimedPayload(out var mod);
            Assert.Equal(1, issuer.BlobCalls);
            Assert.True(File.Exists(Path.Combine(dir, "payload.seal")) && File.Exists(Path.Combine(dir, "key.dpapi")));
            Assert.StartsWith("HD2 PAYLOAD RECEIPT 2\nissuer=" + issuer.Name + "\naccount=" + A + "\nid=callouts.v0.12.0\n", File.ReadAllText(Path.Combine(dir, "receipt.txt")));
            Assert.Equal(issuer.Payloads["callouts.v0.12.0"].Sealed, File.ReadAllBytes(Path.Combine(dir, "payload.seal")));
            Assert.False(File.Exists(Path.Combine(dir, "clips.lua")), "no plaintext at fetch time");
            Assert.Equal(A, Plugin.PayloadHeld(appData, Decl(mod), Plugin.PayloadOf(mod)));
            Assert.Equal("claimed", Plugin.SegmentsState(Home, appData, mod));
            // held: the next pass fetches nothing
            Assert.False(Plugin.ClaimAll(Host()));
            Assert.Equal(1, issuer.BlobCalls);
        }

        [Fact]
        public void A_game_session_decrypts_the_payload_and_the_exit_removes_it()
        {
            var dir = ClaimedPayload(out var mod);
            Assert.True(Plugin.OnGameStart(Host()));
            Assert.Equal(ClipsText("en"), File.ReadAllBytes(Path.Combine(dir, "clips.lua")));
            Assert.Contains("game started: 1 mod(s) with sealed member content in the library", File.ReadAllText(Plugin.LogPath(Home)));
            Assert.Empty(Directory.GetFiles(dir, "*.new-*"));
            Plugin.OnGameStop(Host());
            Assert.False(File.Exists(Path.Combine(dir, "clips.lua")));
            Assert.Equal(new[] { "key.dpapi", "payload.seal", "receipt.txt" }, Directory.GetFiles(dir).Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal));
        }

        [Theory]
        [InlineData("sealed")] [InlineData("plain")] [InlineData("keyhash")] [InlineData("id")] [InlineData("account")]
        [InlineData("url")] [InlineData("bytes")] [InlineData("unsigned")]
        public void A_payload_that_does_not_check_out_is_not_written(string spoil)
        {
            Account(A);
            var mod = PayloadMod();
            InLibrary("Payload", mod);
            Assert.Equal("ok", SignIn(mod));
            issuer.PayloadSpoil = spoil;
            Assert.False(Plugin.ClaimAll(Host()));
            Assert.Equal("bad_receipt", Plugin.SegmentsState(Home, appData, mod));
            Assert.False(Directory.Exists(PayDir()), "nothing is written for " + spoil);
            if (spoil == "url") Assert.Equal(0, issuer.BlobCalls);                  // never fetched from another host
        }

        [Fact]
        public void Offline_the_cached_payload_key_lasts_the_receipts_grace_only()
        {
            var dir = ClaimedPayload(out var mod);
            issuer.PayloadError = "network_stub";
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 5 * 86400);     // within the 20-day grace
            Assert.True(Plugin.OnGameStart(Host()), "within the grace the cached key decrypts");
            Plugin.OnGameStop(Host());
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 40 * 86400);    // past it
            Assert.False(Plugin.OnGameStart(Host()), "past the grace, offline, nothing decrypts");
            Assert.False(File.Exists(Path.Combine(dir, "clips.lua")));
            Assert.Equal("no_key", Plugin.LastUnlock(mod));
            // a cache copied from another computer opens nothing
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            File.WriteAllBytes(Path.Combine(dir, "key.dpapi"), new byte[] { 1, 2, 3, 4 });
            Assert.False(Plugin.OnGameStart(Host()));
            // a segments key cache (other DPAPI label) is no payload key cache either
            Assert.False(File.Exists(Path.Combine(dir, "clips.lua")));
        }

        [Fact]
        public void A_package_the_author_replaced_is_downloaded_again_at_the_game_start()
        {
            var dir = ClaimedPayload(out var mod);
            issuer.Publish("callouts.v0.12.0", ClipsText("zh"));
            Assert.True(Plugin.OnGameStart(Host()));
            Assert.Equal(2, issuer.BlobCalls);
            Assert.Equal(ClipsText("zh"), File.ReadAllBytes(Path.Combine(dir, "clips.lua")));
            Assert.Equal("claimed", Plugin.SegmentsState(Home, appData, mod));
        }

        [Fact]
        public void A_tampered_resident_package_is_not_held_and_does_not_decrypt()
        {
            var dir = ClaimedPayload(out var mod);
            var seal = Path.Combine(dir, "payload.seal");
            var b = File.ReadAllBytes(seal);
            b[50] ^= 1;
            File.WriteAllBytes(seal, b);
            Assert.Null(Plugin.PayloadHeld(appData, Decl(mod), Plugin.PayloadOf(mod)));
            Assert.Equal("missing", Plugin.SegmentsState(Home, appData, mod));
            issuer.PayloadError = "network_stub";
            Assert.False(Plugin.OnGameStart(Host()));
            Assert.False(File.Exists(Path.Combine(dir, "clips.lua")));
        }

        [Fact]
        public void A_payload_declaration_is_read_and_an_unknown_deploy_asks_for_an_update()
        {
            Account(A);
            var mod = PayloadMod();
            var p = Plugin.PayloadOf(mod);
            Assert.Equal("callouts.v0.12.0", Json.Str(p, "wire"));
            Assert.Equal("clips.lua", Json.Str(p, "file"));
            Assert.Equal("callouts", Json.Str(Plugin.PayloadOf(PayloadMod("NoVersion", version: null)), "wire"));
            Assert.Equal("update_manager", Json.Str(Plugin.PayloadOf(PayloadMod("Game", deploy: "patch/9ba626afa44a3aa3")), "error"));
            Assert.Equal("update_manager", Plugin.SegmentsState(Home, appData, PayloadMod("Game2", deploy: "licenses/../x.lua")));
            Assert.Equal("bad_declaration", Json.Str(Plugin.PayloadOf(PayloadMod("BadVer", version: "0.12")), "error"));
            Assert.Null(Plugin.PayloadOf(LicensedMod()));
        }

        [Fact]
        public void A_mod_with_segments_and_a_payload_is_ready_only_with_both()
        {
            Account(A);
            var seg = new Dictionary<string, object> { ["id"] = "sealed-mod", ["count"] = 8L, ["version"] = "v0.12.0", ["sealed"] = 1L };
            var mod = PayloadMod("Both", seg: seg);
            issuer.Seal("v0.12.0");
            InLibrary("Both", mod);
            Assert.Equal("ok", SignIn(mod));
            issuer.PayloadError = "payload_pending";
            Plugin.ClaimAll(Host());
            Assert.True(issuer.LastSegmentsPayload, "the segments request says this plugin fetches payloads");
            Assert.Equal("pending", Plugin.SegmentsState(Home, appData, mod));
            issuer.PayloadError = null;
            Plugin.ClaimAll(Host());
            Assert.Equal("claimed", Plugin.SegmentsState(Home, appData, mod));
            Assert.True(Plugin.OnGameStart(Host()));
            Assert.True(File.Exists(Path.Combine(SegDir("v0.12.0"), "seg1.lua")) && File.Exists(Path.Combine(PayDir(), "clips.lua")));
            Assert.Contains("game started: 1 mod(s) with sealed member content in the library", File.ReadAllText(Plugin.LogPath(Home)));
            Plugin.OnGameStop(Host());
            Assert.False(File.Exists(Path.Combine(SegDir("v0.12.0"), "seg1.lua")) || File.Exists(Path.Combine(PayDir(), "clips.lua")));
        }

        [Fact]
        public void Payload_versions_no_library_mod_uses_are_removed()
        {
            var dir = ClaimedPayload(out var mod);
            var old = PayDir("v0.11.0");
            Directory.CreateDirectory(old);
            File.WriteAllText(Path.Combine(old, "payload.seal"), "x");
            var stray = Path.Combine(Path.GetDirectoryName(dir), "notes");
            Directory.CreateDirectory(stray);
            var removed = Plugin.CleanPayloads(appData, library);
            Assert.Equal(new[] { old }, removed);
            Assert.True(Directory.Exists(dir) && Directory.Exists(stray), "the version in use and folders not this plugin's stay");
        }

        // -- (1.7.0) C1 session credential: sealed segments live as ciphertext ------------------

        /// <summary>A C1 mod in the host library, signed in, its ciphertext claimed and resident.</summary>
        string ClaimedC1(out string mod, string version = "v1.2.0")
        {
            Account(A);
            mod = SealedMod(version, "C1", c1: true);
            InLibrary("C1", mod);
            Assert.Equal("ok", SignIn(mod));
            Assert.True(Json.Bool(Claim(mod), "claimed"));
            return SegDir(version);
        }

        [Fact]
        public void A_sealed_version_is_claimed_as_ciphertext_and_no_plaintext_is_written()
        {
            var dir = ClaimedC1(out var mod);
            Assert.True(issuer.LastSegmentsEnc, "the plugin asks for ciphertext (enc=1)");
            // resident: seg*.enc and a SEGMENTS 2 receipt; no seg*.lua until the game runs
            for (int i = 1; i <= 8; i++) Assert.True(File.Exists(Path.Combine(dir, "seg" + i + ".enc")));
            Assert.False(File.Exists(Path.Combine(dir, "seg1.lua")), "no plaintext is written at claim time");
            Assert.StartsWith("HD2 MOD SEGMENTS 2\nissuer=" + issuer.Name + "\n", File.ReadAllText(Path.Combine(dir, "receipt.txt")));
            // held offline, without the content key: the card says claimed
            Assert.Equal(A, Plugin.HeldAccount(appData, Decl(mod), Plugin.SegmentsOf(mod)));
            Assert.Equal("claimed", Plugin.SegmentsState(Home, appData, mod));
        }

        [Fact]
        public void A_game_session_decrypts_the_plaintext_and_the_exit_removes_it()
        {
            var dir = ClaimedC1(out var mod);
            Assert.True(Plugin.OnGameStart(Host()), "the game start decrypts the ciphertext");
            Assert.Contains("game started: 1 mod(s) with sealed member content in the library", File.ReadAllText(Plugin.LogPath(Home)));   // (1.9.0)
            for (int i = 1; i <= 8; i++)
            {
                var lua = Path.Combine(dir, "seg" + i + ".lua");
                Assert.True(File.Exists(lua));
                // the plaintext the shell reads is the account's segment text -- the watermark survives (trace still hits)
                Assert.Equal(issuer.SegmentText("sealed-mod", "v1.2.0", A, i - 1), File.ReadAllText(lua, new UTF8Encoding(false)));
            }
            Assert.True(File.Exists(Path.Combine(dir, "key.dpapi")), "the content key is cached machine-bound for the grace");
            // the exit removes only the plaintext; ciphertext, receipt and key cache stay
            Plugin.OnGameStop(Host());
            for (int i = 1; i <= 8; i++) Assert.False(File.Exists(Path.Combine(dir, "seg" + i + ".lua")));
            Assert.True(File.Exists(Path.Combine(dir, "seg1.enc")) && File.Exists(Path.Combine(dir, "receipt.txt")) && File.Exists(Path.Combine(dir, "key.dpapi")));
        }

        [Fact]
        public void Offline_within_the_grace_still_decrypts_from_the_cached_key()
        {
            var dir = ClaimedC1(out var mod);
            Assert.True(Plugin.OnGameStart(Host()));               // a first session online, so the key is cached
            Plugin.OnGameStop(Host());
            long sessions = issuer.SessionCalls;
            issuer.SessionError = "network_stub";                  // the issuer now refuses/offline; the cache must carry it
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 5 * 86400);   // 5 days later, within the 20-day grace
            Assert.True(Plugin.OnGameStart(Host()), "within the grace the cached key still decrypts");
            Assert.True(File.Exists(Path.Combine(dir, "seg1.lua")));
        }

        [Fact]
        public void Past_the_grace_offline_the_segments_stay_sealed()
        {
            var dir = ClaimedC1(out var mod);
            Assert.True(Plugin.OnGameStart(Host()));
            Plugin.OnGameStop(Host());
            issuer.SessionError = "network_stub";
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 40 * 86400);  // past the 20-day grace
            Assert.False(Plugin.OnGameStart(Host()), "past the grace, offline, nothing decrypts");
            Assert.False(File.Exists(Path.Combine(dir, "seg1.lua")));
        }

        [Fact]
        public void A_cache_from_another_computer_does_not_open()
        {
            var dir = ClaimedC1(out var mod);
            Assert.True(Plugin.OnGameStart(Host()));
            Plugin.OnGameStop(Host());
            // a copied key.dpapi from another machine/user fails DPAPI unprotect -> no key
            File.WriteAllBytes(Path.Combine(dir, "key.dpapi"), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            issuer.SessionError = "network_stub";
            Assert.False(Plugin.OnGameStart(Host()), "a cache from another computer cannot be opened");
            Assert.False(File.Exists(Path.Combine(dir, "seg1.lua")));
        }

        [Fact]
        public void A_wrong_key_or_spoilt_sealed_receipt_decrypts_nothing()
        {
            // the sealed_hash in the receipt must cover the blobs, or the claim is not written
            Account(A);
            var mod = SealedMod("v1.2.0", "C1", c1: true);
            InLibrary("C1", mod);
            Assert.Equal("ok", SignIn(mod));
            issuer.SegmentsSpoil = "sealed";                       // a wrong sealed_hash in the receipt
            Assert.Equal("bad_receipt", Json.Str(Claim(mod), "error"));
            Assert.False(Directory.Exists(SegDir()));
            issuer.SegmentsSpoil = "text";                         // a resident blob not covered by sealed_hash
            Assert.Equal("bad_receipt", Json.Str(Claim(mod), "error"));
        }

        /// <summary>The cache's expiry is the issuer's signed ticket's, not a field of the DPAPI record
        /// the player can unprotect and rewrite (audit, 2026-11-19).</summary>
        [Fact]
        public void A_cache_with_a_rewritten_expiry_does_not_open()
        {
            var dir = ClaimedC1(out var mod);
            var key = issuer.Keys["v1.2.0"];
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            void Cache(Dictionary<string, object> record) => File.WriteAllBytes(Path.Combine(dir, "key.dpapi"),
                ProtectedData.Protect(Encoding.UTF8.GetBytes(Json.Write(record)), Encoding.ASCII.GetBytes("hd2qd-license-session-1"), DataProtectionScope.CurrentUser));
            issuer.SessionError = "network_stub";
            SetClock(() => now + 40 * 86400);                       // past the ticket's 20-day grace
            // the right key, a far expiry of the record's own, and the genuine ticket: the ticket rules
            Cache(new Dictionary<string, object> { ["k"] = Convert.ToBase64String(key), ["account"] = A, ["exp"] = now + 999 * 86400,
                                                   ["t"] = issuer.Ticket("sealed-mod", "v1.2.0", A, key, now, issuer.Grace) });
            Assert.False(Plugin.OnGameStart(Host()), "the record's own expiry is not believed");
            // a ticket whose expiry was edited no longer verifies
            var forged = issuer.Ticket("sealed-mod", "v1.2.0", A, key, now, issuer.Grace).Replace("expires=" + (now + issuer.Grace), "expires=" + (now + 999 * 86400));
            Cache(new Dictionary<string, object> { ["k"] = Convert.ToBase64String(key), ["account"] = A, ["t"] = forged });
            Assert.False(Plugin.OnGameStart(Host()), "an edited ticket does not verify");
            // a ticket signed by another key (not the pinned one) does not count either
            Cache(new Dictionary<string, object> { ["k"] = Convert.ToBase64String(key), ["account"] = A,
                                                   ["t"] = issuer.Ticket("sealed-mod", "v1.2.0", A, key, now, 999L * 86400, "b") });
            Assert.False(Plugin.OnGameStart(Host()), "a ticket not signed by the pinned key does not count");
            // must-live: the genuine ticket within its expiry opens
            SetClock(() => now + 5 * 86400);
            Cache(new Dictionary<string, object> { ["k"] = Convert.ToBase64String(key), ["account"] = A,
                                                   ["t"] = issuer.Ticket("sealed-mod", "v1.2.0", A, key, now, issuer.Grace) });
            Assert.True(Plugin.OnGameStart(Host()), "a genuine ticket within its expiry opens the cache");
            Assert.True(File.Exists(Path.Combine(dir, "seg1.lua")));
        }

        /// <summary>A clock set back before the issuer signed the ticket is not trusted (audit, 2026-11-19).</summary>
        [Fact]
        public void A_clock_set_back_before_the_ticket_opens_no_cache()
        {
            var dir = ClaimedC1(out var mod);
            Assert.True(Plugin.OnGameStart(Host()));               // online: the key and its ticket are cached
            Plugin.OnGameStop(Host());
            issuer.SessionError = "network_stub";
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 2 * 86400);
            Assert.False(Plugin.OnGameStart(Host()), "two days before the ticket was signed");
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 60);
            Assert.True(Plugin.OnGameStart(Host()), "a minute behind the issuer is ordinary clock skew");
        }

        /// <summary>An issuer that sends no ticket gives this session its key and nothing to keep.</summary>
        [Fact]
        public void Without_a_ticket_the_key_is_used_but_not_kept()
        {
            var dir = ClaimedC1(out var mod);
            issuer.SessionNoTicket = true;
            Assert.True(Plugin.OnGameStart(Host()), "online, the session still decrypts");
            Assert.False(File.Exists(Path.Combine(dir, "key.dpapi")), "but no key is kept for later");
        }

        /// <summary>Plaintext of a sealed claim is removed whatever was done to the folder or the mod:
        /// the .enc deleted and "sealed" taken out of hd2_license.json left it for good (audit, 2026-11-19).</summary>
        [Fact]
        public void Sealed_plaintext_is_cleared_and_not_held_even_with_the_ciphertext_gone()
        {
            var dir = ClaimedC1(out var mod);
            Assert.True(Plugin.OnGameStart(Host()));
            foreach (var enc in Directory.GetFiles(dir, "seg*.enc")) File.Delete(enc);
            var seg = Plugin.SegmentsOf(mod);
            seg["sealed"] = false;                                  // as if "sealed" were taken out of the mod
            Assert.Null(Plugin.HeldAccount(appData, Decl(mod), seg));
            Plugin.OnGameStop(Host());
            for (int i = 1; i <= 8; i++) Assert.False(File.Exists(Path.Combine(dir, "seg" + i + ".lua")), "seg" + i + ".lua left behind");
        }

        [Fact]
        public void A_wrong_session_key_decrypts_nothing()
        {
            // defence in depth: even with the ciphertext resident, a key that is not K_v (a stale or
            // tampered cache) decrypts to plaintext that does not match the receipt's segments_hash,
            // so no seg*.lua is written -- the session fails closed
            var dir = ClaimedC1(out var mod);
            // a well-formed DPAPI cache that holds a wrong 32-byte key for this account
            var wrong = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(wrong);
            var record = Json.Write(new Dictionary<string, object>
            { ["k"] = Convert.ToBase64String(wrong), ["account"] = A, ["exp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 86400 });
            var prot = ProtectedData.Protect(Encoding.UTF8.GetBytes(record), Encoding.ASCII.GetBytes("hd2qd-license-session-1"), DataProtectionScope.CurrentUser);
            File.WriteAllBytes(Path.Combine(dir, "key.dpapi"), prot);
            issuer.SessionError = "network_stub";                  // offline, so the wrong cached key is used
            Assert.False(Plugin.OnGameStart(Host()));
            Assert.False(File.Exists(Path.Combine(dir, "seg1.lua")));
        }

        [Fact]
        public void A_non_c1_version_is_still_claimed_as_plaintext_beside_a_c1_one()
        {
            // migration: a sealed (C1) mod and an old plaintext mod coexist; the old one keeps its
            // plaintext path (seg*.lua resident, SEGMENTS 1 receipt), C1 keeps ciphertext
            Account(A);
            var c1 = SealedMod("v1.2.0", "C1", c1: true);
            var plain = SealedMod("v0.35.0", "Plain");           // not c1
            Assert.Equal("ok", SignIn(c1));
            Assert.True(Json.Bool(Claim(c1), "claimed"));
            Assert.True(Json.Bool(Claim(plain), "claimed"));
            Assert.True(File.Exists(Path.Combine(SegDir("v1.2.0"), "seg1.enc")) && !File.Exists(Path.Combine(SegDir("v1.2.0"), "seg1.lua")));
            Assert.True(File.Exists(Path.Combine(SegDir("v0.35.0"), "seg1.lua")));
            Assert.StartsWith("HD2 MOD SEGMENTS 1\n", File.ReadAllText(Path.Combine(SegDir("v0.35.0"), "receipt.txt")));
        }

        string SegDir(string version = "v1.2.0", string id = "sealed-mod") => Plugin.SegmentsFolder(appData, issuer.Name, id, version);
        Dictionary<string, object> Claim(string folder, bool force = false) => Plugin.ClaimSegments(Home, appData, folder, force);

        [Fact]
        public void The_version_comes_from_the_manifest_name()
        {
            Assert.Equal("v0.35.0", Json.Str(Plugin.SegmentsOf(SealedMod("v0.35.0", "Super Beacon")), "version"));
            var f = SealedMod("v1.2.3", "Hf");
            File.WriteAllText(Path.Combine(f, "manifest.json"), "{\"Name\":\"Hf v1.2.3 (for HellForge)\"}");
            Assert.Equal("v1.2.3", Json.Str(Plugin.SegmentsOf(f), "version"));
            File.WriteAllText(Path.Combine(f, "manifest.json"), "{\"Name\":\"Hf\"}");
            Assert.Equal("no_version", Json.Str(Plugin.SegmentsOf(f), "error"));
            Assert.Null(Plugin.SegmentsOf(LicensedMod()));                     // a mod without segments
        }

        /// <summary>Puts "version" (any JSON value, or the raw text given) into the mod's "segments".</summary>
        static void DeclareVersion(string folder, object version)
        {
            var path = Path.Combine(folder, "hd2_license.json");
            var d = (Dictionary<string, object>)Json.Parse(File.ReadAllText(path));
            ((Dictionary<string, object>)d["segments"])["version"] = version;
            File.WriteAllText(path, Json.Write(d));
        }

        [Fact]
        public void A_declared_version_wins_over_the_manifest_name()
        {
            // a published package: the Name carries no version, the declaration does
            var pub = SealedMod("", "Pub");
            File.WriteAllText(Path.Combine(pub, "manifest.json"), "{\"Name\":\"Pub\"}");
            Assert.Equal("no_version", Json.Str(Plugin.SegmentsOf(pub), "error"));
            DeclareVersion(pub, "v0.35.0");
            Assert.Equal("v0.35.0", Json.Str(Plugin.SegmentsOf(pub), "version"));
            // the declaration wins over a version in the Name
            var both = SealedMod("v9.9.9", "Both");
            DeclareVersion(both, "v1.0.1");
            Assert.Equal("v1.0.1", Json.Str(Plugin.SegmentsOf(both), "version"));
            // a declared version names a folder: anything but a whole tag is refused, never a fallback to the Name
            foreach (var bad in new object[] { "0.35.0", "v0", "v0.35.0\n", "v0.35.0/../x", "..", "", "v0.35.0 ", 35L, null })
            {
                DeclareVersion(both, bad);
                var got = Plugin.SegmentsOf(both);
                Assert.True(Json.Str(got, "error") == "bad_declaration", "declared " + Json.Write(bad) + " gave " + Json.Write(got));
            }
        }

        [Fact]
        public void A_published_package_claims_the_declared_version()
        {
            Account(A);
            var mod = SealedMod("", "Pub");
            File.WriteAllText(Path.Combine(mod, "manifest.json"), "{\"Name\":\"Pub\"}");
            DeclareVersion(mod, "v1.2.0");
            Assert.Equal("ok", SignIn(mod));
            Assert.True(Json.Bool(Claim(mod), "claimed"));
            Assert.Equal("v1.2.0", issuer.LastSegmentsVersion);
            Assert.StartsWith("HD2 MOD SEGMENTS 1\nissuer=" + issuer.Name + "\nid=sealed-mod\nversion=v1.2.0\n", File.ReadAllText(Path.Combine(SegDir("v1.2.0"), "receipt.txt")));
            Assert.Equal("claimed", Plugin.SegmentsState(Home, appData, mod));
        }

        [Fact]
        public void Segments_are_claimed_checked_and_written_where_the_shell_reads_them()
        {
            Account(A);
            var mod = SealedMod();
            Assert.Equal("not_signed_in", Json.Str(Claim(mod), "why"));
            Assert.Equal(0, issuer.SegmentsCalls);
            Assert.Equal("ok", SignIn(mod));
            var r = Claim(mod);
            Assert.True(Json.Bool(r, "claimed"));
            Assert.Equal(A, Json.Str(r, "account"));
            Assert.Equal(A, issuer.LastSegmentsAccount);
            var dir = SegDir();
            for (int i = 1; i <= 8; i++)
                Assert.Equal(issuer.SegmentText("sealed-mod", "v1.2.0", A, i - 1), File.ReadAllText(Path.Combine(dir, "seg" + i + ".lua"), new UTF8Encoding(false)));
            Assert.StartsWith("HD2 MOD SEGMENTS 1\nissuer=" + issuer.Name + "\nid=sealed-mod\nversion=v1.2.0\naccount=" + A + "\n", File.ReadAllText(Path.Combine(dir, "receipt.txt")));
            Assert.Equal(new[] { "receipt.txt" }.Concat(Enumerable.Range(1, 8).Select(i => "seg" + i + ".lua")).OrderBy(x => x),
                         Directory.GetFiles(dir).Select(Path.GetFileName).OrderBy(x => x));
            Assert.DoesNotContain(Directory.GetDirectories(Path.GetDirectoryName(dir)), d => Path.GetFileName(d).StartsWith("."));   // no temporary folder left
            Assert.Equal("claimed", Plugin.SegmentsState(Home, appData, mod));
            int calls = issuer.SegmentsCalls;
            Assert.Equal("held", Json.Str(Claim(mod), "why"));                  // held: not asked again
            Assert.Equal(calls, issuer.SegmentsCalls);
            Assert.True(Json.Bool(Claim(mod, force: true), "claimed"));         // forced: asked, and replaced whole
            Assert.Equal(calls + 1, issuer.SegmentsCalls);
            Assert.DoesNotContain(Directory.GetDirectories(Path.GetDirectoryName(dir)), d => Path.GetFileName(d).StartsWith("."));
        }

        [Fact]
        public void A_receipt_that_does_not_check_out_writes_nothing()
        {
            Account(A);
            var mod = SealedMod();
            Assert.Equal("ok", SignIn(mod));
            foreach (var spoil in new Action[]
            {
                () => issuer.SegmentsSignWith = "b",                       // not the declared key
                () => issuer.SegmentsSpoil = "text",                       // the texts are not what it covers
                () => issuer.SegmentsSpoil = "version",                    // for another version
                () => issuer.SegmentsSpoil = "account",                    // for another account
                () => issuer.SegmentsSpoil = "count",                      // too few segments
            })
            {
                issuer.SegmentsSignWith = "a";
                issuer.SegmentsSpoil = null;
                spoil();
                Assert.Equal("bad_receipt", Json.Str(Claim(mod), "error"));
                Assert.False(Directory.Exists(SegDir()));
            }
        }

        [Fact]
        public void A_good_set_is_kept_when_a_new_claim_fails()
        {
            Account(A);
            var mod = SealedMod();
            Assert.Equal("ok", SignIn(mod));
            Assert.True(Json.Bool(Claim(mod), "claimed"));
            var before = File.ReadAllText(Path.Combine(SegDir(), "seg1.lua"));
            issuer.SegmentsSignWith = "b";
            Assert.Equal("bad_receipt", Json.Str(Claim(mod, force: true), "error"));
            Assert.Equal(before, File.ReadAllText(Path.Combine(SegDir(), "seg1.lua")));
            Assert.Equal(A, Plugin.HeldAccount(appData, Decl(mod), Plugin.SegmentsOf(mod)));
        }

        [Fact]
        public void A_segment_changed_on_disk_is_not_held_and_is_claimed_again()
        {
            Account(A);
            var mod = SealedMod();
            Assert.Equal("ok", SignIn(mod));
            Assert.True(Json.Bool(Claim(mod), "claimed"));
            var seg3 = Path.Combine(SegDir(), "seg3.lua");
            File.AppendAllText(seg3, "-- edited");
            Assert.Null(Plugin.HeldAccount(appData, Decl(mod), Plugin.SegmentsOf(mod)));
            Assert.Equal("missing", Plugin.SegmentsState(Home, appData, mod));
            Assert.True(Json.Bool(Claim(mod), "claimed"));
            Assert.Equal(issuer.SegmentText("sealed-mod", "v1.2.0", A, 2), File.ReadAllText(seg3, new UTF8Encoding(false)));
        }

        [Fact]
        public void A_version_the_author_has_not_uploaded_is_pending_and_said_so()
        {
            Account(A);
            var mod = SealedMod("v9.9.9");
            InLibrary("Sealed", mod);
            Assert.Equal("ok", SignIn(mod));
            issuer.Uploaded.Remove("v9.9.9");
            Assert.Equal("payload_pending", Json.Str(Claim(mod), "error"));
            Assert.False(Directory.Exists(SegDir("v9.9.9")));
            Assert.Equal("pending", Plugin.SegmentsState(Home, appData, mod));
            Assert.Equal("Awaiting the author", Json.Str(Plugin.ModNote(mod, Host()), "text"));
            issuer.Uploaded.Add("v9.9.9");
            Assert.True(Json.Bool(Claim(mod), "claimed"));
            Assert.Null(Plugin.ModNote(mod, Host()));                           // licensed and held: nothing on the row
        }

        [Fact]
        public void The_issuers_refusal_is_kept_and_the_next_account_tried()
        {
            Account(A, 1);
            Account(B, 60);
            var mod = SealedMod();
            issuer.Accounts = new[] { A, B };
            Assert.Equal("ok", SignIn(mod));
            issuer.SegmentsRefuse = A;                                          // the issuer refuses A (unbound since)
            var r = Claim(mod);
            Assert.True(Json.Bool(r, "claimed"));
            Assert.Equal(B, Json.Str(r, "account"));
            issuer.SegmentsRefuse = null;
            issuer.SegmentsError = "banned";
            Assert.Equal("banned", Json.Str(Claim(mod, force: true), "error"));
        }

        [Fact]
        public void Versions_no_library_mod_is_at_are_removed_and_nothing_else()
        {
            Account(A);
            var mod = SealedMod("v1.2.0");
            InLibrary("Sealed", mod);
            Assert.Equal("ok", SignIn(mod));
            var root = Path.GetDirectoryName(SegDir());
            foreach (var d in new[] { "v1.0.0", ".v1.2.0.new-0123abcd", "notes", "v1.0.0-beta" }) Directory.CreateDirectory(Path.Combine(root, d));
            var otherId = SegDir("v0.1.0", "other-mod");                         // an id no library mod declares
            Directory.CreateDirectory(otherId);
            Assert.True(Plugin.ClaimAll(Host()));
            Assert.True(Directory.Exists(SegDir("v1.2.0")));
            Assert.False(Directory.Exists(Path.Combine(root, "v1.0.0")));
            Assert.False(Directory.Exists(Path.Combine(root, ".v1.2.0.new-0123abcd")));
            Assert.True(Directory.Exists(Path.Combine(root, "notes")));
            Assert.True(Directory.Exists(Path.Combine(root, "v1.0.0-beta")));
            Assert.True(Directory.Exists(otherId));
            library.Clear();                                                     // a library read empty removes nothing
            Plugin.ClaimAll(Host());
            Assert.True(Directory.Exists(SegDir("v1.2.0")));
        }

        [Fact]
        public void Claims_go_to_the_plugins_own_log_and_never_to_the_managers_reports()
        {
            Account(A);
            var mod = SealedMod();
            InLibrary("Sealed", mod);
            Assert.Equal("ok", SignIn(mod));
            issuer.Uploaded.Remove("v1.2.0");
            Plugin.ClaimAll(Host());
            issuer.Uploaded.Add("v1.2.0");
            Plugin.ClaimAll(Host());
            Plugin.ClaimAll(Host());                                             // held: not logged again
            Assert.Equal(Path.Combine(Home, "license", "license.log"), Plugin.LogPath(Home));
            var log = File.ReadAllLines(Plugin.LogPath(Home)).Where(l => l.Contains("sealed-mod v1.2.0: ")).ToArray();
            Assert.Equal(2, log.Length);
            Assert.Contains("sealed-mod v1.2.0: pending", log[0]);
            Assert.Contains("sealed-mod v1.2.0: claimed (account " + A + ")", log[1]);
            Assert.False(Directory.Exists(Path.Combine(Home, "reports")));
            Assert.Empty(Directory.GetFiles(Home, "*.log", SearchOption.TopDirectoryOnly));
        }

        /// <summary>(1.8.0) Every request, sign-in, renewal and change of state is a line of the
        /// plugin's log, tagged with its issuer; the request says the plugin's version; no
        /// token goes into the log.</summary>
        [Fact]
        public void Requests_sign_ins_and_states_are_logged_without_tokens()
        {
            Account(A);
            var mod = LicensedMod();
            InLibrary("Licensed", mod);
            Assert.Equal("ok", SignIn(mod));
            Plugin.Status(Home, appData, Decl(mod));
            Plugin.Status(Home, appData, Decl(mod));                             // unchanged: no second line
            issuer.RenewError = "not_member";
            Plugin.Renew(Home, appData, Decl(mod), true);
            var log = File.ReadAllText(Plugin.LogPath(Home));
            var tag = "[" + issuer.Name + "] ";
            Assert.Contains(tag + "POST /claim -> 200", log);
            Assert.Contains(tag + "sign-in: ok, until ", log);
            Assert.Contains(tag + "POST /renew -> 403 not_member", log);
            Assert.Contains(tag + "renewal: not_member", log);
            Assert.Equal(1, log.Split('\n').Count(l => l.Contains(tag + "license: licensed until ")));
            Assert.Contains("license names " + A + ", accounts here " + A, log);
            Assert.DoesNotContain(issuer.RenewToken, log);
            Assert.Equal("1.10.0", Plugin.PluginVersion);
            Assert.Equal(Plugin.PluginVersion, issuer.LastClientHeader);
        }

        /// <summary>(1.8.0) The card's "Send license log": the head and the lines about that
        /// author only; the code comes back and is logged; refusals are told apart.</summary>
        [Fact]
        public void The_license_log_goes_to_one_author_with_only_their_lines()
        {
            Account(A);
            var mod = LicensedMod();
            InLibrary("Licensed", mod);
            Assert.Equal("ok", SignIn(mod));
            Plugin.Status(Home, appData, Decl(mod));
            File.AppendAllText(Plugin.LogPath(Home), "2026-11-19 12:00:00 [other.example] sign-in: ok, until x" + Environment.NewLine);
            File.AppendAllText(Plugin.LogPath(Home), "2026-11-19 12:00:01 removed nothing in particular" + Environment.NewLine);
            var r = Plugin.SendLog(Home, appData, Decl(mod), "0.22.0");
            Assert.Equal("K7Q2-M9XA", Json.Str(r, "code"));
            Assert.Equal(30L, Json.Long(r, "days"));
            var sent = issuer.LastDiagLog;
            Assert.StartsWith("HD2 MOD LICENSE LOG 1\nissuer=" + issuer.Name + "\nplugin=1.10.0\nmanager=0.22.0\n", sent);
            Assert.Contains("sign-in: ok", sent);
            Assert.Matches(@"\nwindows=Windows 1[01] .*build \d+", sent);                // not .NET Framework's 6.2.9200
            Assert.Contains("removed nothing in particular", sent);                // a line about no author goes along
            Assert.DoesNotContain("other.example", sent);
            Assert.DoesNotContain(issuer.RenewToken, sent);
            Assert.Contains("sent this log to the author: code K7Q2-M9XA", File.ReadAllText(Plugin.LogPath(Home)));
            issuer.DiagStatus = 429;
            Assert.Equal("rate", Json.Str(Plugin.SendLog(Home, appData, Decl(mod)), "error"));
            issuer.DiagStatus = 404;
            Assert.Equal("no_diag", Json.Str(Plugin.SendLog(Home, appData, Decl(mod)), "error"));
            Assert.Equal("test_issuer", Json.Str(Plugin.SendLog(Home, appData, Decl(LicensedMod("T", issuerName: "lic.test"))), "error"));
            var dead = Decl(LicensedMod("Dead", issuerName: "127.0.0.1:1"));
            Assert.Equal("network", Json.Str(Plugin.SendLog(Home, appData, dead), "error"));
            Assert.Contains("[127.0.0.1:1] POST /diag -> unreachable", File.ReadAllText(Plugin.LogPath(Home)));
        }

        /// <summary>(1.9.0) A package's .hd2_license_via says which members' site its sign-in
        /// opens; packages of one creator from both sites leave the choice to the issuer.</summary>
        [Fact]
        public void A_packages_via_file_picks_the_members_site()
        {
            Account(A);
            var afdian = LicensedMod("Afdian");
            File.WriteAllText(Path.Combine(afdian, ".hd2_license_via"), "afdian\r\n");
            Assert.Equal("afdian", Json.Str(Decl(afdian), "via"));
            string Url(Dictionary<string, object> d) { var b = BeginSignIn(d); Plugin.AbandonSignIn(Json.Str(b, "session")); return Json.Str(b, "url"); }
            Assert.EndsWith("&acct=" + A + "&via=afdian", Url(Decl(afdian)));

            var plain = LicensedMod("Plain");
            Assert.Null(Json.Str(Decl(plain), "via"));
            Assert.DoesNotContain("via=", Url(Decl(plain)));
            var odd = LicensedMod("Odd");
            File.WriteAllText(Path.Combine(odd, ".hd2_license_via"), "paypal");
            Assert.Null(Json.Str(Decl(odd), "via"));

            InLibrary("Afdian", afdian);
            Assert.Equal("afdian", Json.Str(Plugin.Issuers(library)[0].Decl, "via"));
            var patreon = LicensedMod("Patreon");
            File.WriteAllText(Path.Combine(patreon, ".hd2_license_via"), "patreon");
            InLibrary("Patreon", patreon);
            var mixed = Plugin.Issuers(library)[0].Decl;
            Assert.Equal("mixed", Json.Str(mixed, "via"));
            Assert.DoesNotContain("via=", Url(mixed));
        }

        /// <summary>(1.9.0) The game names a settings file after the id without its leading zeros
        /// (a1b2c3d4e5f6071_user_settings.config for 0a1b2c3d4e5f6071, a player's saves
        /// 2026-11-19): it is that account, padded back to 16 as the mods' check pads peer_id.</summary>
        [Fact]
        public void A_settings_file_named_without_leading_zeros_is_the_padded_account()
        {
            Account("a1b2c3d4e5f6071");
            Assert.Equal(new[] { "0a1b2c3d4e5f6071" }, Plugin.Accounts(appData));
            Account("1a2b3c4d5e6f70");                                          // two zeros dropped
            Assert.Contains("001a2b3c4d5e6f70", Plugin.Accounts(appData));
            Account("12345678");                                                // a placeholder once padded: no account
            Assert.DoesNotContain("0000000012345678", Plugin.Accounts(appData));
            var url = Json.Str(BeginSignIn(Decl(LicensedMod())), "url");
            Assert.Contains("&acct=", url);
        }

        /// <summary>(1.9.0) No account here: the log says what the saves folder holds, with the
        /// Windows user's folder left out.</summary>
        [Fact]
        public void No_account_logs_what_the_saves_folder_holds()
        {
            var mod = LicensedMod();
            Plugin.Status(Home, appData, Decl(mod));
            Assert.Contains("accounts here none (%APPDATA%\\Arrowhead\\Helldivers2\\saves: no Helldivers2 folder)", File.ReadAllText(Plugin.LogPath(Home)));
            var saves = Path.Combine(appData, "Arrowhead", "Helldivers2", "saves");
            Directory.CreateDirectory(saves);
            File.WriteAllText(Path.Combine(saves, "user_settings.config"), "x");
            Plugin.Status(Home, appData, Decl(mod));
            var log = File.ReadAllText(Plugin.LogPath(Home));
            Assert.Contains("saves: user_settings.config)", log);
            Assert.DoesNotContain(appData, log);
        }

        /// <summary>(1.8.0) The 1.6.0/1.7.0 payload.log is the start of license.log.</summary>
        [Fact]
        public void The_old_payload_log_carries_on_as_the_license_log()
        {
            var dir = Path.Combine(Home, "license");
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "payload.log"), "2026-11-18 13:59:30 Super Beacon v0.35.0: claimed" + Environment.NewLine);
            Account(A);
            Plugin.Status(Home, appData, Decl(LicensedMod()));
            Assert.False(File.Exists(Path.Combine(dir, "payload.log")));
            var log = File.ReadAllLines(Plugin.LogPath(Home));
            Assert.StartsWith("2026-11-18 13:59:30 Super Beacon", log[0]);
            Assert.Contains("license: none", log[1]);
        }

        /// <summary>The card warns on a manager that ends with its window (before 0.22.0, which
        /// first says its version to plugins): a sealed mod is unlocked only while it runs.</summary>
        [Fact]
        public void A_manager_without_the_notification_area_is_told_apart()
        {
            Dictionary<string, object> H(string v) { var h = Host(); if (v != null) h["version"] = v; return h; }
            Assert.False(Plugin.RunsOnInTray(H(null)), "0.21.0 and older say no version");
            Assert.False(Plugin.RunsOnInTray(H("0.21.0")));
            Assert.False(Plugin.RunsOnInTray(H("nonsense")));
            Assert.True(Plugin.RunsOnInTray(H("0.22.0")));
            Assert.True(Plugin.RunsOnInTray(H("0.23.4")));
            Assert.True(Plugin.RunsOnInTray(H("1.0.0")));
        }

        /// <summary>A sealed mod's row says when its content was, or will be, left locked in a game,
        /// and says nothing when all is well (the user, 2026-11-19: log and manager only).</summary>
        [Fact]
        public void A_sealed_mods_row_says_when_its_content_stays_locked()
        {
            issuer.Grace = 86400;                                                                       // a one-day key, so it lapses before the licence
            var dir = ClaimedC1(out var mod);
            Dictionary<string, object> H(string v = "0.22.0") { var h = Host("zh-CN"); if (v != null) h["version"] = v; return h; }
            Assert.Equal("游戏启动时需开着本程序", Json.Str(Plugin.ModNote(mod, H(null)), "text"));     // a manager before 0.22.0
            Assert.Null(Plugin.ModNote(mod, H()));                                                        // claimed, nothing went wrong
            Assert.True(Plugin.OnGameStart(H(), true));                                                   // the game was already running
            Assert.Equal("本局未解锁：游戏先于本程序启动", Json.Str(Plugin.ModNote(mod, H()), "text"));
            Assert.Equal("late", Plugin.LastUnlock(mod));
            Plugin.OnGameStop(H());
            Assert.True(Plugin.OnGameStart(H()));                                                         // in time: the word goes
            Assert.Null(Plugin.ModNote(mod, H()));
            Plugin.OnGameStop(H());
            issuer.SessionError = "network_stub";
            SetClock(() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 2 * 86400);                      // offline past the key's grace, licence still good
            Assert.False(Plugin.OnGameStart(H()));
            Assert.Equal("上一局未解锁：离线超过宽限期", Json.Str(Plugin.ModNote(mod, H()), "text"));
        }

        [Fact]
        public void The_start_and_the_command_claim_what_is_missing()
        {
            Account(A);
            var mod = SealedMod();
            InLibrary("Sealed", mod);
            Assert.Equal("ok", SignIn(mod));
            Assert.True(Plugin.Start(Host()));
            Assert.Equal("claimed", Plugin.SegmentsState(Home, appData, mod));
            Directory.Delete(SegDir(), true);
            var o = new StringWriter();
            Assert.Equal(0, Plugin.Run("license-segments", new string[0], o, Host()));
            Assert.Contains("Sealed v1.2.0: member content ready", o.ToString());
            Assert.True(Directory.Exists(SegDir()));
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
            /// <summary>(1.6.0) /segments: the versions uploaded, the key it signs receipts with, a
            /// spoilt receipt ("text", "version", "account", "count"), an account it refuses, and a
            /// refusal for every claim.</summary>
            public readonly HashSet<string> Uploaded = new HashSet<string> { "v1.2.0", "v9.9.9", "v0.35.0" };
            public string SegmentsSignWith = "a", SegmentsSpoil, SegmentsRefuse, SegmentsError, LastSegmentsAccount, LastSegmentsVersion;
            public int SegmentsCalls;
            public bool LastSegmentsEnc;
            /// <summary>(1.7.0, C1) sealed versions: their content key K_v (made by Seal), the grace
            /// /session hands out, and what /session answers instead (a refusal, or an account it refuses).</summary>
            public readonly Dictionary<string, byte[]> Keys = new Dictionary<string, byte[]>();
            public long Grace = 20 * 86400;
            public int SessionCalls;
            public string SessionError;
            /// <summary>(audit 2026-11-19) /session answers without its signed ticket (an older issuer).</summary>
            public bool SessionNoTicket;
            /// <summary>(1.8.0) /diag: the log sent, the plugin version the last request said, and
            /// the status it answers instead (429, 404).</summary>
            public string LastDiagLog, LastClientHeader;
            public int DiagStatus = 200;
            /// <summary>(1.10.0) /payload: each wire id's package (Publish), the grace its receipt gives,
            /// a spoilt answer ("sealed", "plain", "keyhash", "id", "account", "url", "bytes", "unsigned"),
            /// a refusal for every request, and what was asked.</summary>
            public readonly Dictionary<string, (byte[] Plain, byte[] Key, byte[] Sealed, string Mark)> Payloads =
                new Dictionary<string, (byte[], byte[], byte[], string)>();
            public string PayloadSpoil, PayloadError;
            public int PayloadCalls, BlobCalls;
            public long PayloadGrace = 20 * 86400;
            public bool LastSegmentsPayload;

            /// <summary>Seals plaintext as the offline tool does (AES-256-CBC/PKCS7, IV ‖ ciphertext)
            /// under a fresh key and mark, and serves it for the wire id from now on.</summary>
            public void Publish(string wire, byte[] plain)
            {
                var key = new byte[32];
                var mark = new byte[8];
                using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(key); rng.GetBytes(mark); }
                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = key; aes.GenerateIV();
                    using (var enc = aes.CreateEncryptor())
                        Payloads[wire] = (plain, key, aes.IV.Concat(enc.TransformFinalBlock(plain, 0, plain.Length)).ToArray(), Hex(mark));
                }
            }

            static string Hex(byte[] b) => string.Concat(b.Select(x => x.ToString("x2")));
            static string Sha(byte[] b) { using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(b)); }

            /// <summary>A RECEIPT 2 (spec/static-resources draft 2), its lines in order.</summary>
            public string PayloadReceipt(string wire, string account, string mark, string sealedHash, string plainHash, string keyHash, long issued, long grace, string signWith = "a")
            {
                var text = "HD2 PAYLOAD RECEIPT 2" + NL + "issuer=" + Name + NL + "account=" + account + NL + "id=" + wire + NL + "mark=" + mark + NL +
                           "alg=A256CBC" + NL + "sealed_hash=" + sealedHash + NL + "plain_hash=" + plainHash + NL + "key_hash=" + keyHash + NL +
                           "issued=" + issued + NL + "expires=" + (issued + grace) + NL;
                return Sign(signWith, text);
            }

            /// <summary>Marks a version sealed (C1): it gets a content key, and /segments serves it as
            /// ciphertext when the plugin asks with enc.</summary>
            public void Seal(string version)
            {
                Uploaded.Add(version);
                if (!Keys.ContainsKey(version)) { var k = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(k); Keys[version] = k; }
            }

            /// <summary>The text of one segment for an account: what a combo picks, here made up.</summary>
            public string SegmentText(string id, string version, string account, int seg) =>
                "-- " + id + " " + version + " segment " + seg + " for " + account.Substring(0, 4) + " é" + NL + "local x = " + seg + NL;

            string Receipt(string key, string id, string version, string account, string hash)
            {
                var text = "HD2 MOD SEGMENTS 1" + NL + "issuer=" + Name + NL + "id=" + id + NL + "version=" + version + NL + "account=" + account + NL +
                           "segments_hash=" + hash + NL + "issued=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() + NL;
                return Sign(key, text);
            }

            /// <summary>(1.7.0, C1) a SEGMENTS 2 receipt: the plaintext hash and the ciphertext hash.</summary>
            string Receipt2(string key, string id, string version, string account, string plainHash, string sealedHash)
            {
                var text = "HD2 MOD SEGMENTS 2" + NL + "issuer=" + Name + NL + "id=" + id + NL + "version=" + version + NL + "account=" + account + NL +
                           "alg=A256CBC" + NL + "segments_hash=" + plainHash + NL + "sealed_hash=" + sealedHash + NL + "issued=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() + NL;
                return Sign(key, text);
            }

            /// <summary>The issuer's signed session ticket (POST /session): the key's hash and its expiry.</summary>
            public string Ticket(string id, string version, string account, byte[] key, long issued, long grace, string signWith = "a")
            {
                string kh;
                using (var sha = SHA256.Create()) kh = string.Concat(sha.ComputeHash(key).Select(b => b.ToString("x2")));
                var text = "HD2 MOD SESSION 1" + NL + "issuer=" + Name + NL + "id=" + id + NL + "version=" + version + NL + "account=" + account + NL +
                           "key_hash=" + kh + NL + "issued=" + issued + NL + "expires=" + (issued + grace) + NL;
                return Sign(signWith, text);
            }

            string Sign(string key, string text)
            {
                var pkcs8 = Convert.FromBase64String(Json.Str(Json.Obj(t.keys, key), "pkcs8"));
                using (var rsa = new RSACng(CngKey.Import(pkcs8, CngKeyBlobFormat.Pkcs8PrivateBlob)))
                {
                    var sig = rsa.SignData(Encoding.UTF8.GetBytes(text), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    return text + "sig=" + string.Concat(sig.Select(b => b.ToString("x2"))) + NL;
                }
            }

            /// <summary>AES-256-CBC/PKCS7, blob = IV(16) ‖ ciphertext, base64 -- the shape the plugin decrypts.</summary>
            static string Encrypt(byte[] key, string plaintext)
            {
                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = key; aes.GenerateIV();
                    using (var enc = aes.CreateEncryptor())
                    {
                        var pt = Encoding.UTF8.GetBytes(plaintext);
                        var ct = enc.TransformFinalBlock(pt, 0, pt.Length);
                        return Convert.ToBase64String(aes.IV.Concat(ct).ToArray());
                    }
                }
            }
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
                if (path == "/diag")
                {
                    if (DiagStatus != 200) return (DiagStatus, new Dictionary<string, object> { ["error"] = DiagStatus == 429 ? "rate" : "not_found" });
                    LastDiagLog = Json.Str(body, "log");
                    return (200, new Dictionary<string, object> { ["code"] = "K7Q2-M9XA", ["days"] = 30L });
                }
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
                if (path == "/segments")
                {
                    SegmentsCalls++;
                    string id = Json.Str(body, "id"), version = Json.Str(body, "version"), acct = Json.Str(body, "account");
                    LastSegmentsAccount = acct;
                    LastSegmentsVersion = version;
                    if (SegmentsError != null) return (403, new Dictionary<string, object> { ["error"] = SegmentsError });
                    if (!Members.TryGetValue(Json.Str(body, "renew") ?? "", out var sm)) return (403, new Dictionary<string, object> { ["error"] = "unknown" });
                    if (!sm.Accounts.Contains(acct) || acct == SegmentsRefuse) return (403, new Dictionary<string, object> { ["error"] = "account" });
                    if (!Uploaded.Contains(version)) return (409, new Dictionary<string, object> { ["error"] = "payload_pending" });
                    bool enc = Json.Long(body, "enc") == 1;
                    LastSegmentsEnc = enc;
                    LastSegmentsPayload = Json.Long(body, "payload") == 1;
                    var texts = Enumerable.Range(0, SegmentsSpoil == "count" ? 7 : 8).Select(i => SegmentText(id, version, acct, i)).ToList();
                    string plainHash;
                    using (var sha = SHA256.Create()) plainHash = string.Concat(sha.ComputeHash(Encoding.UTF8.GetBytes(string.Concat(texts))).Select(b => b.ToString("x2")));
                    string ver = SegmentsSpoil == "version" ? "v0.0.1" : version, ra = SegmentsSpoil == "account" ? (acct == A ? B : A) : acct;
                    if (Keys.ContainsKey(version))
                    {
                        // C1 (section 12.4/12.5): a sealed version without enc tells an old plugin to update
                        if (!enc) return (409, new Dictionary<string, object> { ["error"] = "update_plugin" });
                        var blobs = texts.Select(x => Encrypt(Keys[version], x)).ToList();
                        string sealedHash;
                        using (var sha = SHA256.Create()) sealedHash = string.Concat(sha.ComputeHash(Encoding.UTF8.GetBytes(string.Concat(blobs))).Select(b => b.ToString("x2")));
                        // "text": a resident blob not covered by the signed sealed_hash; "sealed": a wrong sealed_hash
                        if (SegmentsSpoil == "text") blobs[3] = Encrypt(Keys[version], texts[3] + "-- added");
                        if (SegmentsSpoil == "sealed") sealedHash = new string('e', 64);
                        var rec2 = Receipt2(SegmentsSignWith, id, ver, ra, plainHash, sealedHash);
                        return (200, new Dictionary<string, object> { ["segments"] = blobs.Cast<object>().ToList(), ["receipt"] = rec2, ["enc"] = 1 });
                    }
                    if (SegmentsSpoil == "text") texts[3] += "-- added";
                    var receipt = Receipt(SegmentsSignWith, id, ver, ra, plainHash);
                    return (200, new Dictionary<string, object> { ["segments"] = texts.Cast<object>().ToList(), ["receipt"] = receipt });
                }
                if (path == "/payload")
                {
                    PayloadCalls++;
                    string wire = Json.Str(body, "id"), acct = Json.Str(body, "account");
                    if (PayloadError != null) return (403, new Dictionary<string, object> { ["error"] = PayloadError });
                    if (!Members.TryGetValue(Json.Str(body, "renew") ?? "", out var pm)) return (403, new Dictionary<string, object> { ["error"] = "unknown" });
                    if (!pm.Accounts.Contains(acct)) return (403, new Dictionary<string, object> { ["error"] = "payload_account" });
                    if (!Payloads.TryGetValue(wire ?? "", out var p)) return (409, new Dictionary<string, object> { ["error"] = "payload_pending" });
                    string sh = Sha(p.Sealed), ph = Sha(p.Plain), kh = Sha(p.Key);
                    if (PayloadSpoil == "sealed") sh = new string('e', 64);
                    if (PayloadSpoil == "plain") ph = new string('e', 64);
                    if (PayloadSpoil == "keyhash") kh = new string('e', 64);
                    var receipt = PayloadReceipt(PayloadSpoil == "id" ? wire + "x" : wire, PayloadSpoil == "account" ? (acct == A ? B : A) : acct,
                                                 p.Mark, sh, ph, kh, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), PayloadGrace, PayloadSpoil == "unsigned" ? "b" : "a");
                    var host = PayloadSpoil == "url" ? "127.0.0.2:" + Name.Split(':')[1] : Name;
                    return (200, new Dictionary<string, object>
                    {
                        ["url"] = "http://" + host + "/payload/blob?id=" + wire + "&mark=" + p.Mark + "&t=1",
                        ["key"] = Hex(p.Key), ["hash"] = sh, ["receipt"] = receipt,
                    });
                }
                if (path == "/session")
                {
                    SessionCalls++;
                    string id = Json.Str(body, "id"), version = Json.Str(body, "version"), acct = Json.Str(body, "account");
                    if (SessionError != null) return (403, new Dictionary<string, object> { ["error"] = SessionError });
                    if (!Members.TryGetValue(Json.Str(body, "renew") ?? "", out var sm)) return (403, new Dictionary<string, object> { ["error"] = "unknown" });
                    if (!sm.Accounts.Contains(acct)) return (403, new Dictionary<string, object> { ["error"] = "account" });
                    if (!Keys.ContainsKey(version)) return (409, new Dictionary<string, object> { ["error"] = "payload_pending" });
                    var answer = new Dictionary<string, object> { ["key"] = Convert.ToBase64String(Keys[version]), ["grace"] = Grace };
                    if (!SessionNoTicket) answer["ticket"] = Ticket(id, version, acct, Keys[version], DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Grace);
                    return (200, answer);
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
                        var said = lines.FirstOrDefault(l => l.StartsWith("X-HD2QD-License:", StringComparison.OrdinalIgnoreCase));
                        if (said != null) LastClientHeader = said.Substring(16).Trim();
                        int length = lines.Where(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                                          .Select(l => int.Parse(l.Substring(15).Trim())).FirstOrDefault();
                        var buf = new byte[length];
                        for (int got = 0; got < length;) got += s.Read(buf, got, length - got);
                        if (path.StartsWith("/payload/blob?"))
                        {
                            // (1.10.0) the sealed bytes, by mark, as R2 streams them
                            BlobCalls++;
                            var mark = path.Split('&').First(x => x.StartsWith("mark=")).Substring(5);
                            var pkg = Payloads.Values.FirstOrDefault(x => x.Mark == mark);
                            byte[] blob = pkg.Sealed?.ToArray() ?? new byte[0];
                            if (PayloadSpoil == "bytes" && blob.Length > 40) blob[40] ^= 1;
                            var head2 = Encoding.ASCII.GetBytes("HTTP/1.1 " + (pkg.Sealed != null ? 200 : 404) + " X\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
                                                                blob.Length + "\r\nConnection: close\r\n\r\n");
                            s.Write(head2, 0, head2.Length);
                            s.Write(blob, 0, blob.Length);
                            continue;
                        }
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
