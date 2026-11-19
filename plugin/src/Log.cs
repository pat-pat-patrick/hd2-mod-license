using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Hd2Qd.License
{
    // (1.8.0) The plugin's own log, home\license\license.log: every request to an issuer and its
    // answer, each sign-in, activation, renewal and sign-out, each change of where a license
    // stands, and the member content's claims and unlocks (before 1.8.0 those alone, in
    // payload.log, which carries on here). Never a renew token, code or verifier. Not the
    // manager's log, never in its problem reports (DESIGN_sealed_lua): a player sends it to one
    // author with the card's "Send license log" (SendLog), which takes only that author's lines.
    public static partial class Plugin
    {
        static readonly object logLock = new object();
        const long LogMax = 256 * 1024;
        /// <summary>The most of the log sent to an issuer (the issuer takes 128 KB).</summary>
        const int SendMax = 100 * 1024;

        /// <summary>home\license\license.log; the previous one is license.previous.log past 256 KB.</summary>
        public static string LogPath(string home) => Path.Combine(home, "license", "license.log");
        static string PreviousLogPath(string home) => Path.Combine(home, "license", "license.previous.log");

        /// <summary>This plugin's version, as the issuer's request log shows it.</summary>
        public static string PluginVersion
        {
            get { var v = typeof(Plugin).Assembly.GetName().Version; return v.Major + "." + v.Minor + "." + v.Build; }
        }

        static string IssuerOf(string modFolder)
        {
            try { return Json.Str(Declaration(modFolder), "issuer"); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return null; }
        }

        /// <summary>A line about one issuer (its host leads it in brackets), or about none (null).</summary>
        static void Log(string home, string issuer, string line)
        {
            if (home == null) return;
            lock (logLock)
                try
                {
                    var path = LogPath(home);
                    var dir = Path.GetDirectoryName(path);
                    Directory.CreateDirectory(dir);
                    // payload.log (1.6.0 and 1.7.0, claims only) is the start of this log
                    var old = Path.Combine(dir, "payload.log");
                    if (File.Exists(old) && !File.Exists(path)) File.Move(old, path);
                    var oldPrev = Path.Combine(dir, "payload.previous.log");
                    if (File.Exists(oldPrev) && !File.Exists(PreviousLogPath(home))) File.Move(oldPrev, PreviousLogPath(home));
                    if (File.Exists(path) && new FileInfo(path).Length > LogMax)
                    {
                        var prev = PreviousLogPath(home);
                        if (File.Exists(prev)) File.Delete(prev);
                        File.Move(path, prev);
                    }
                    File.AppendAllText(path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + (issuer != null ? " [" + issuer + "] " : " ")
                                             + line.Replace('\r', ' ').Replace('\n', ' ') + Environment.NewLine, new UTF8Encoding(false));
                }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
        }

        /// <summary>A request's line: what was asked (the mod and account it names, never a token
        /// or code) and how it was answered.</summary>
        static string RequestWords(string path, Dictionary<string, object> body, int status, Dictionary<string, object> answer, long ms, Exception failed)
        {
            var what = new StringBuilder("POST " + path);
            foreach (var field in new[] { "id", "version", "account", "acct" })
                if (Json.Str(body, field) is string v && v.Length <= 64) what.Append(' ').Append(field == "acct" ? "account" : field == "id" ? "mod" : field).Append(' ').Append(v);
            what.Append(" -> ");
            if (status == 0) what.Append("unreachable").Append(failed != null ? " (" + failed.GetType().Name + ": " + Inner(failed) + ")" : "");
            else
            {
                what.Append(status);
                if (Json.Str(answer, "error") is string e && e.Length <= 40) what.Append(' ').Append(e);
                if (Json.Long(answer, "wait_days") > 0) what.Append(" (wait ").Append(Json.Long(answer, "wait_days")).Append(" days)");
            }
            return what.Append(" (").Append(ms).Append(" ms)").ToString();
        }

        /// <summary>Windows as the registry says it ("Windows 11 24H2 build 26100.4349"):
        /// Environment.OSVersion says 6.2.9200 (Windows 8) to a .NET Framework program without a
        /// manifest. ProductName says Windows 10 on 11 too, so the build tells them apart.</summary>
        static string WindowsVersion()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    var build = k?.GetValue("CurrentBuildNumber") as string ?? k?.GetValue("CurrentBuild") as string;
                    if (build == null) return Environment.OSVersion.VersionString;
                    var name = int.TryParse(build, out var b) && b >= 22000 ? "Windows 11" : "Windows 10";
                    var display = k.GetValue("DisplayVersion") as string ?? k.GetValue("ReleaseId") as string;
                    var ubr = k.GetValue("UBR") is int u ? "." + u : "";
                    return name + (display != null ? " " + display : "") + " build " + build + ubr;
                }
            }
            catch (Exception e) when (e is System.Security.SecurityException || e is UnauthorizedAccessException || e is IOException) { return Environment.OSVersion.VersionString; }
        }

        static string Inner(Exception e)
        {
            while (e.InnerException != null) e = e.InnerException;
            var m = e.Message ?? "";
            return m.Length > 160 ? m.Substring(0, 160) : m;
        }

        // -- states ------------------------------------------------------------------------

        static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> lastState =
            new System.Collections.Concurrent.ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Where a license stands, logged when it differs from the last time this program
        /// looked (so once at each start, and at each change).</summary>
        static void LogState(string home, string appData, Dictionary<string, object> r)
        {
            if (home == null) return;
            string issuer = Json.Str(r, "issuer");
            string words = Json.Str(r, "state");
            if (r.ContainsKey("expires")) words += " until " + DateTimeOffset.FromUnixTimeSeconds(Json.Long(r, "expires")).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            if (Json.List(r, "accounts") is List<object> named && named.Count > 0) words += ", license names " + string.Join(",", named);
            List<string> here;
            try { here = Accounts(appData); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { here = new List<string>(); }
            words += ", accounts here " + (here.Count > 0 ? string.Join(",", here) : "none");
            if (Json.Long(r, "members") > 1) words += ", " + Json.Long(r, "members") + " members' licenses";
            var key = home + "|" + issuer;
            if (lastState.TryGetValue(key, out var was) && was == words) return;
            lastState[key] = words;
            Log(home, issuer, "license: " + words);
        }

        // -- sending ----------------------------------------------------------------------

        /// <summary>Sends this computer's license log to one issuer (the card's "Send license log"):
        /// a head (plugin and manager version, Windows, the game accounts here, where the license
        /// stands now), then the log's lines about that issuer and those about none, the newest
        /// 100 KB. {code, days}: the code the player gives the author, who reads it on the issuer
        /// for that many days; or {error}: "test_issuer", "empty", "rate" (too many today),
        /// "no_diag" (an issuer that takes no logs), "network".</summary>
        public static Dictionary<string, object> SendLog(string home, string appData, Dictionary<string, object> decl, string manager = null)
        {
            string issuer = Json.Str(decl, "issuer");
            if (TestIssuer(issuer)) return Err("test_issuer");
            var st = Status(home, appData, decl);
            var head = new StringBuilder();
            head.Append("HD2 MOD LICENSE LOG 1\n");
            head.Append("issuer=").Append(issuer).Append('\n');
            head.Append("plugin=").Append(PluginVersion).Append('\n');
            if (manager != null) head.Append("manager=").Append(manager).Append('\n');
            head.Append("windows=").Append(WindowsVersion()).Append('\n');
            head.Append("sent=").Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss zzz")).Append('\n');
            head.Append("state=").Append(lastState.TryGetValue(home + "|" + issuer, out var now) ? now : Json.Str(st, "state")).Append('\n');
            head.Append("---\n");

            var lines = new List<string>();
            lock (logLock)
                foreach (var file in new[] { PreviousLogPath(home), LogPath(home) })
                    try { if (File.Exists(file)) lines.AddRange(File.ReadAllLines(file, Encoding.UTF8)); }
                    catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
            var mine = "[" + issuer + "]";
            var taken = lines.Where(l => l.Length > 20 && (l.Substring(20).StartsWith(mine + " ") || !l.Substring(20).StartsWith("["))).ToList();
            if (taken.Count == 0) return Err("empty");
            var bodyText = new StringBuilder();
            int size = 0, from = taken.Count;
            while (from > 0 && size + taken[from - 1].Length + 1 <= SendMax) size += taken[--from].Length + 1;
            if (from > 0) bodyText.Append("(the ").Append(from).Append(" older lines are left out)\n");
            foreach (var l in taken.Skip(from)) bodyText.Append(l).Append('\n');

            var (status, answer) = Post(home, issuer, "/diag", new Dictionary<string, object>
            { ["log"] = head.ToString() + bodyText, ["plugin"] = PluginVersion });
            if (status == 200 && Json.Str(answer, "code") is string code)
            {
                Log(home, issuer, "sent this log to the author: code " + code);
                return new Dictionary<string, object> { ["code"] = code, ["days"] = Json.Long(answer, "days") };
            }
            if (status == 429) return Err("rate");
            if (status == 404) return Err("no_diag");
            return Err("network");
        }
    }
}
