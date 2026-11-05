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
                var block = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
                block.Children.Add(line);
                block.Children.Add(buttons);
                panel.Children.Add(block);
            }
            return panel;
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
            if (error == null) Foot(host, Words.F(lang, "lic_done", Until(Json.Long(r, "expires"))), "Blue");
            else if (error == "cancelled") Foot(host, Words.Get(lang, "lic_cancelled"), "Muted");
            else
            {
                Foot(host, ErrorWords(r, lang), "Yellow");
                Tell(host, ErrorWords(r, lang));
            }
            Refresh(host);
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
                    return Words.Get(lang, "lic_err_" + error);
                case "sign_in_again": case "unknown": return Words.Get(lang, "lic_err_sign_in_again");
                default: return Words.F(lang, "lic_err_other", detail ?? error);
            }
        }
    }
}
