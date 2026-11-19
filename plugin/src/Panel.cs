using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace Hd2Qd.License
{
    // The plugin's card on the manager's Plugins page: each author whose mods are in the library
    // (and each signed in here whose mods are not), where the license stands, and signing in
    // through the browser or out. Drawn with the manager's own styles and colours, which its
    // application carries (Ghost, Primary; Ink, Muted, Yellow, Blue).
    public static partial class Plugin
    {
        static CancellationTokenSource wait;
        static string signingIn;
        static string sendingLog;        // (1.8.0) the issuer a log is being sent to

        static Style Style(string key) => Application.Current?.TryFindResource(key) as Style;
        static Brush Brush(string key) => Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;

        static T Get<T>(Dictionary<string, object> host, string key) where T : class => host.TryGetValue(key, out var v) ? v as T : null;

        static string Until(long unix) => DateTimeOffset.FromUnixTimeSeconds(unix).ToLocalTime().ToString("yyyy-MM-dd HH:mm");

        static string StateWords(string state, long expires, string lang) =>
            state == "licensed" ? Words.F(lang, "lic_licensed", Until(expires))
            : state == "expired" ? Words.F(lang, "lic_expired", Until(expires))
            : Words.Get(lang, "lic_" + state);

        static TextBlock Small(string text, Thickness margin) =>
            new TextBlock { Text = text, FontSize = 12, Foreground = Brush("Muted"), TextWrapping = TextWrapping.Wrap, Margin = margin };

        /// <summary>A dot, the state in words, and what it is about underneath.</summary>
        static UIElement Line(string words, string colour, string about)
        {
            var head = new DockPanel { Margin = new Thickness(0, 12, 0, 0) };
            var dot = new Ellipse { Width = 10, Height = 10, Fill = Brush(colour), Margin = new Thickness(0, 5, 10, 0), VerticalAlignment = VerticalAlignment.Top };
            DockPanel.SetDock(dot, Dock.Left);
            head.Children.Add(dot);
            var text = new StackPanel();
            text.Children.Add(new TextBlock { Text = words, FontSize = 14, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            text.Children.Add(Small(about, new Thickness(0, 2, 0, 0)));
            head.Children.Add(text);
            return head;
        }

        /// <summary>The card's body: what the plugin is for, then each author.</summary>
        public static FrameworkElement Panel(Window owner, Dictionary<string, object> host)
        {
            string lang = Words.Lang(host);
            string home = Home(host), appData = AppData(host);
            var panel = new StackPanel();
            panel.Children.Add(Small(Words.Get(lang, "lic_intro"), new Thickness(0, 8, 0, 0)));
            var known = Known(home, LibraryOf(host));
            if (known.Count == 0)
            {
                panel.Children.Add(Small(Words.Get(lang, "lic_nothing"), new Thickness(0, 8, 0, 0)));
                return panel;
            }
            foreach (var (decl, mods, folder) in known)
            {
                string issuer = Json.Str(decl, "issuer");
                // read now: a sign-in or sign-out shows at once
                var now = folder != null ? StateOf(home, appData, folder) : Status(home, appData, decl);
                string state = Json.Str(now, "state") ?? "none";
                bool busy = signingIn == issuer;
                var line = Line(busy ? Words.Get(lang, "lic_waiting") : StateWords(state, Json.Long(now, "expires"), lang),
                                busy ? "Blue" : state == "licensed" ? "Blue" : "Yellow",
                                Json.Str(decl, "name") + " · " + issuer + " · " +
                                (mods.Count > 0 ? Words.F(lang, "lic_mods", string.Join(Words.Get(lang, "lic_mods_separator"), mods)) : Words.Get(lang, "lic_no_mods")));
                var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(20, 10, 0, 0) };
                var about = new List<string>();
                if (busy)
                {
                    var cancel = new Button { Content = Words.Get(lang, "cancel"), Style = Style("Ghost"), MinHeight = 36 };
                    cancel.Click += (s, e) => wait?.Cancel();
                    buttons.Children.Add(cancel);
                }
                else
                {
                    bool canSignIn = state != "no_account" && state != "key_changed";
                    // a test build's issuer has no site: no button that can only fail
                    if (!TestIssuer(issuer))
                    {
                        var signIn = new Button
                        {
                            Content = Words.Get(lang, state == "licensed" || state == "expired" ? "lic_sign_in_again" : "lic_sign_in"),
                            Style = Style(state == "licensed" ? "Ghost" : "Primary"), MinHeight = 36, IsEnabled = canSignIn && signingIn == null,
                        };
                        signIn.Click += (s, e) => SignIn(decl, host);
                        buttons.Children.Add(signIn);
                        var redeem = new Button
                        {
                            Content = Words.Get(lang, "lic_redeem"), Style = Style("Ghost"), MinHeight = 36,
                            Margin = new Thickness(8, 0, 0, 0), IsEnabled = canSignIn && signingIn == null,
                        };
                        redeem.Click += (s, e) => RedeemCode(owner, decl, host);
                        buttons.Children.Add(redeem);
                    }
                    if (state != "none" && state != "no_account" && state != "test_issuer")
                    {
                        var signOut = new Button { Content = Words.Get(lang, "lic_sign_out"), Style = Style("Ghost"), MinHeight = 36, Margin = new Thickness(buttons.Children.Count > 0 ? 8 : 0, 0, 0, 0) };
                        signOut.Click += (s, e) =>
                        {
                            if (!Ask(host, Words.Get(lang, "lic_sign_out_ask"), Words.Get(lang, "lic_sign_out"))) return;
                            try { Forget(home, appData, issuer); }
                            catch (Exception x) when (x is System.IO.IOException || x is UnauthorizedAccessException) { Tell(host, Words.F(lang, "failed", x.Message)); }
                            Refresh(host);
                        };
                        buttons.Children.Add(signOut);
                    }
                }
                // (1.6.0) the member content of this author's mods that ship it per game account
                bool segmentsMissing = false, anySealed = false;
                if (state == "licensed")
                    foreach (var m in LibraryOf(host))
                    {
                        var path = Json.Str(m, "path");
                        if (path == null || !System.IO.Directory.Exists(path) || Json.Str(Declaration(path), "issuer") != issuer) continue;
                        var seg = SegmentsOf(path);
                        if (seg == null) continue;
                        string st;
                        try { st = SegmentsState(home, appData, path); }
                        catch (Exception x) when (x is System.IO.IOException || x is UnauthorizedAccessException) { st = "other"; }
                        var label = Json.Str(m, "name");
                        segmentsMissing |= st != "claimed";
                        anySealed |= Json.Bool(seg, "sealed");
                        about.Add(SegmentsWords(st, label, lang));
                    }
                // a sealed (C1) mod is unlocked only while this program runs when the game starts:
                // a manager older than 0.22.0 ends when its window closes, and then the mod does
                // nothing in that game with no word why (2026-11-19)
                if (anySealed && !RunsOnInTray(host)) about.Add(Words.Get(lang, "seg_needs_tray"));
                if (segmentsMissing && !busy && signingIn == null)
                {
                    var again = new Button { Content = Words.Get(lang, "seg_claim"), Style = Style("Ghost"), MinHeight = 36, Margin = new Thickness(buttons.Children.Count > 0 ? 8 : 0, 0, 0, 0) };
                    again.Click += (s, e) => ClaimNow(host, false);
                    buttons.Children.Add(again);
                }
                // (1.8.0) the log of this author's sign-ins, renewals and claims, to the author
                if (!busy && !TestIssuer(issuer))
                {
                    var send = new Button { Content = Words.Get(lang, "lic_send_log"), Style = Style("Ghost"), MinHeight = 36,
                                            Margin = new Thickness(buttons.Children.Count > 0 ? 8 : 0, 0, 0, 0), IsEnabled = signingIn == null && sendingLog == null };
                    send.Click += (s, e) => SendLogNow(decl, host);
                    buttons.Children.Add(send);
                }
                var block = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
                block.Children.Add(line);
                foreach (var words in about) block.Children.Add(Small(words, new Thickness(20, 4, 0, 0)));
                block.Children.Add(buttons);
                panel.Children.Add(block);
            }
            return panel;
        }

        /// <summary>Whether the manager hosting this plugin keeps running in the notification area
        /// when its window closes: HD2 Mod Quick Deploy 0.22.0 and later, the first to say its
        /// version to plugins (host "version").</summary>
        public static bool RunsOnInTray(Dictionary<string, object> host)
        {
            var v = host != null && host.TryGetValue("version", out var o) ? o as string : null;
            var m = v == null ? null : System.Text.RegularExpressions.Regex.Match(v, @"^(\d+)\.(\d+)");
            if (m == null || !m.Success) return false;
            int major = int.Parse(m.Groups[1].Value), minor = int.Parse(m.Groups[2].Value);
            return major > 0 || minor >= 22;
        }

        static bool Ask(Dictionary<string, object> host, string text, string action) =>
            Get<Func<string, string, bool>>(host, "ask") is var ask && ask != null ? ask(text, action) : MessageBox.Show(text, action, MessageBoxButton.OKCancel) == MessageBoxResult.OK;

        static void Tell(Dictionary<string, object> host, string text)
        {
            if (Get<Action<string>>(host, "tell") is Action<string> tell) tell(text);
            else MessageBox.Show(text);
        }

        static void Foot(Dictionary<string, object> host, string text, string colour) => Get<Action<string, string>>(host, "foot")?.Invoke(text, colour);

        static void Refresh(Dictionary<string, object> host) => Get<Action>(host, "refresh")?.Invoke();

        /// <summary>Signing in: the player is told what the issuer learns, the browser opens the
        /// issuer's members' site, and the answer is waited for (10 minutes, or Cancel).</summary>
        static async void SignIn(Dictionary<string, object> decl, Dictionary<string, object> host)
        {
            string lang = Words.Lang(host);
            string home = Home(host), appData = AppData(host), issuer = Json.Str(decl, "issuer");
            Dictionary<string, object> begin;
            List<string> accounts;
            try
            {
                begin = BeginSignIn(appData, decl);
                accounts = Accounts(appData);
            }
            catch (Exception x) when (x is System.IO.IOException || x is UnauthorizedAccessException) { Tell(host, Words.F(lang, "failed", x.Message)); return; }
            if (Json.Str(begin, "error") == "other") { Tell(host, Words.F(lang, "failed", Json.Str(begin, "detail"))); return; }
            if (Json.Str(begin, "error") != null) { Tell(host, Words.Get(lang, "lic_" + Json.Str(begin, "error"))); return; }
            var session = Json.Str(begin, "session");
            // the issuer learns the game account: said before anything is sent
            if (!Ask(host, Words.F(lang, "lic_ask", issuer, Json.Str(decl, "name"), accounts[0]), Words.Get(lang, "lic_sign_in")))
            {
                AbandonSignIn(session);
                return;
            }

            signingIn = issuer;
            wait = new CancellationTokenSource();
            Refresh(host);
            Foot(host, Words.Get(lang, "lic_waiting"), "Blue");
            Dictionary<string, object> r;
            try
            {
                Process.Start(new ProcessStartInfo(Json.Str(begin, "url")) { UseShellExecute = true });
                var token = wait.Token;
                r = await Task.Run(() => FinishSignIn(home, appData, decl, session, 600, token, lang));
            }
            catch (Exception x) when (x is System.ComponentModel.Win32Exception || x is System.IO.IOException || x is UnauthorizedAccessException)
            {
                r = new Dictionary<string, object> { ["error"] = "other", ["detail"] = x.Message };
            }
            finally
            {
                AbandonSignIn(session);        // the browser would not open: stop listening
                signingIn = null;
                wait = null;
            }
            var error = Json.Str(r, "error");
            if (error == null) { Foot(host, Words.F(lang, "lic_done", Until(Json.Long(r, "expires"))), "Blue"); ClaimNow(host, false); }
            else if (error == "cancelled") Foot(host, Words.Get(lang, "lic_cancelled"), "Muted");
            else
            {
                Foot(host, ErrorWords(r, lang), "Yellow");
                Tell(host, ErrorWords(r, lang));
            }
            Refresh(host);
        }

        /// <summary>Activating with a code: asked for (saying what the issuer learns), checked here
        /// for typos, then sent. A mistyped code is asked for again with what was typed.</summary>
        static async void RedeemCode(Window owner, Dictionary<string, object> decl, Dictionary<string, object> host)
        {
            string lang = Words.Lang(host);
            string home = Home(host), appData = AppData(host), issuer = Json.Str(decl, "issuer");
            List<string> accounts;
            try { accounts = Accounts(appData); }
            catch (Exception x) when (x is System.IO.IOException || x is UnauthorizedAccessException) { Tell(host, Words.F(lang, "failed", x.Message)); return; }
            if (accounts.Count == 0) { Tell(host, Words.Get(lang, "lic_no_account")); return; }
            string typed = "";
            while (true)
            {
                typed = AskText(owner, host, Words.F(lang, "lic_redeem_ask", issuer, Json.Str(decl, "name"), accounts[0]), Words.Get(lang, "lic_redeem_action"), typed);
                if (typed == null) return;
                if (NormalizeCode(typed) != null) break;
                Tell(host, Words.Get(lang, "lic_err_bad_code"));
            }

            signingIn = issuer;
            Refresh(host);
            Foot(host, Words.Get(lang, "lic_redeem_waiting"), "Blue");
            Dictionary<string, object> r;
            try { r = await Task.Run(() => Redeem(home, appData, decl, typed)); }
            catch (Exception x) when (x is System.IO.IOException || x is UnauthorizedAccessException || x is System.Security.Cryptography.CryptographicException)
            {
                r = new Dictionary<string, object> { ["error"] = "other", ["detail"] = x.Message };
            }
            finally { signingIn = null; }
            var error = Json.Str(r, "error");
            if (error == null) { Foot(host, Words.F(lang, "lic_done", Until(Json.Long(r, "expires"))), "Blue"); ClaimNow(host, false); }
            else
            {
                var words = error == "no_account" || error == "test_issuer" ? Words.Get(lang, "lic_" + error) : ErrorWords(r, lang);
                Foot(host, words, "Yellow");
                Tell(host, words);
            }
            Refresh(host);
        }

        /// <summary>(1.8.0) Sending the license log to one author: asked first (saying what is in
        /// it), then sent in the background; the code is copied and shown.</summary>
        static async void SendLogNow(Dictionary<string, object> decl, Dictionary<string, object> host)
        {
            string lang = Words.Lang(host);
            string home = Home(host), appData = AppData(host), issuer = Json.Str(decl, "issuer");
            if (!Ask(host, Words.F(lang, "lic_send_log_ask", Json.Str(decl, "name"), issuer), Words.Get(lang, "lic_send_log"))) return;
            sendingLog = issuer;
            Refresh(host);
            Foot(host, Words.Get(lang, "lic_send_log_waiting"), "Blue");
            var manager = host.TryGetValue("version", out var v) ? v as string : null;
            Dictionary<string, object> r;
            try { r = await Task.Run(() => SendLog(home, appData, decl, manager)); }
            catch (Exception x) when (x is System.IO.IOException || x is UnauthorizedAccessException) { r = new Dictionary<string, object> { ["error"] = "other", ["detail"] = x.Message }; }
            finally { sendingLog = null; }
            var code = Json.Str(r, "code");
            if (code != null)
            {
                bool copied = false;
                try { Clipboard.SetText(code); copied = true; }
                catch (Exception x) when (x is System.Runtime.InteropServices.COMException || x is System.Threading.ThreadStateException) { }
                var words = Words.F(lang, copied ? "lic_send_log_done" : "lic_send_log_done_nocopy", code, Json.Long(r, "days") > 0 ? Json.Long(r, "days") : 30);
                Foot(host, words, "Blue");
                Tell(host, words);
            }
            else
            {
                var error = Json.Str(r, "error");
                var words = error == "rate" || error == "no_diag" || error == "empty" ? Words.Get(lang, "lic_send_log_" + error)
                    : error == "network" ? Words.Get(lang, "lic_err_network") : Words.F(lang, "failed", Json.Str(r, "detail") ?? error);
                Foot(host, words, "Yellow");
                Tell(host, words);
            }
            Refresh(host);
        }

        /// <summary>A line typed in: the manager's own box when it offers one (host "ask_text"),
        /// else a plain window of this plugin's. Null when cancelled.</summary>
        static string AskText(Window owner, Dictionary<string, object> host, string text, string action, string start)
        {
            if (Get<Func<string, string, string, string>>(host, "ask_text") is Func<string, string, string, string> ask) return ask(text, action, start);
            var box = new TextBox { Text = start ?? "", FontSize = 14, Padding = new Thickness(6, 4, 6, 4), Margin = new Thickness(0, 12, 0, 0) };
            var ok = new Button { Content = action, IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 16, 8, 0) };
            var cancel = new Button { Content = Words.Get(Words.Lang(host), "cancel"), IsCancel = true, MinWidth = 90, Margin = new Thickness(0, 16, 0, 0) };
            var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            row.Children.Add(ok);
            row.Children.Add(cancel);
            var body = new StackPanel { Margin = new Thickness(20) };
            body.Children.Add(new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, MaxWidth = 460 });
            body.Children.Add(box);
            body.Children.Add(row);
            var w = new Window { Owner = owner, Content = body, SizeToContent = SizeToContent.WidthAndHeight, ResizeMode = ResizeMode.NoResize,
                                 WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen, Title = action, ShowInTaskbar = false };
            ok.Click += (s, e) => w.DialogResult = true;
            w.Loaded += (s, e) => { box.Focus(); box.SelectAll(); };
            return w.ShowDialog() == true ? box.Text : null;
        }

        /// <summary>(1.6.0) One mod's member content in words.</summary>
        static string SegmentsWords(string st, string mod, string lang)
        {
            switch (st)
            {
                case "claimed": case "missing": case "pending": case "not_signed_in": case "no_version":
                    return Words.F(lang, "seg_" + st, mod);
                case "bad_receipt": case "account": case "not_member": case "banned": case "network":
                    return Words.F(lang, "seg_failed", mod, Words.Get(lang, "lic_err_" + st));
                case "unsealed":
                    return Words.F(lang, "seg_unsealed", mod);
                case "sign_in_again": case "unknown":
                    return Words.F(lang, "seg_failed", mod, Words.Get(lang, "lic_err_sign_in_again"));
                default: return Words.F(lang, "seg_failed", mod, st);
            }
        }

        /// <summary>Claims in the background (after a sign-in, or the card's button), then redraws.</summary>
        static void ClaimNow(Dictionary<string, object> host, bool force) =>
            Task.Run(() =>
            {
                try { ClaimAll(host, force); }
                catch (Exception x) when (x is System.IO.IOException || x is UnauthorizedAccessException || x is System.Security.Cryptography.CryptographicException) { }
                RefreshFromWorker(host);
            });

        /// <summary>The manager's redraw, on its own thread when it has a window.</summary>
        static void RefreshFromWorker(Dictionary<string, object> host)
        {
            var refresh = Get<Action>(host, "refresh");
            if (refresh == null) return;
            var d = Application.Current?.Dispatcher;
            if (d != null) d.BeginInvoke(refresh); else refresh();
        }

        /// <summary>A failed sign-in in words: {error, detail?, wait_days?}.</summary>
        static string ErrorWords(Dictionary<string, object> r, string lang)
        {
            long wait = Json.Long(r, "wait_days");
            if (Json.Str(r, "error") == "account_limit" && wait > 0) return Words.F(lang, "lic_err_account_limit_wait", wait);
            return ErrorWords(Json.Str(r, "error"), Json.Str(r, "detail"), lang);
        }

        static string ErrorWords(string error, string detail, string lang)
        {
            switch (error)
            {
                case "not_member": case "account_limit": case "banned": case "denied": case "timeout": case "network": case "bad_license": case "key_changed":
                case "bad_code": case "unknown_code": case "no_codes":
                    return Words.Get(lang, "lic_err_" + error);
                case "sign_in_again": case "unknown": return Words.Get(lang, "lic_err_sign_in_again");
                default: return Words.F(lang, "lic_err_other", detail ?? error);
            }
        }
    }
}
