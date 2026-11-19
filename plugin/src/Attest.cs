using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Hd2Qd.License
{
    /// <summary>The online check (spec section 7, the user 2026-11-16: the plugin answers for
    /// the mod, so changing the computer's clock gets nowhere while the manager runs). A mod
    /// writes licenses\&lt;issuer&gt;.ask (a nonce and its account) when its license passes; this
    /// asks the issuer's /attest with the renew token of the member whose license names that
    /// account, and writes the signed answer to &lt;issuer&gt;.attest (through a temporary file).
    /// A refusal is written unsigned (nonce and error): a forged refusal helps no one. When the
    /// issuer cannot be reached nothing is written, so the mod keeps its grace. A question
    /// older than AskMinutes, or answered already, is left alone.</summary>
    public static partial class Plugin
    {
        const string AskHeader = "HD2 MOD ASK 1\n", AttestHeader = "HD2 MOD ATTEST 1\n";
        const int AskMinutes = 10;
        static readonly Regex NonceHex = new Regex("^[0-9a-f]{32}$");
        // (1.5.0) the Steam ID the official game showed before the account: a SteamID64 of an
        // individual account in the public universe; the issuer keeps it beside the account,
        // taking no place (spec section 7)
        static readonly Regex SteamHex = new Regex("^01100001[0-9a-f]{8}$");

        static string LicenseDir(string appData) => Path.Combine(appData, "Arrowhead", "Helldivers2", "licenses");
        static string AskPath(string appData, string issuer) => Path.Combine(LicenseDir(appData), issuer.Replace(':', '_') + ".ask");
        static string AttestPath(string appData, string issuer) => Path.Combine(LicenseDir(appData), issuer.Replace(':', '_') + ".attest");

        /// <summary>Answers the issuer's question, if a fresh one is waiting: {answered: true,
        /// nonce, time}; {answered: false, why} (no_question, old, malformed, answered); or
        /// {error} (the issuer's refusal, written for the mod; "network", nothing written;
        /// "key_changed").</summary>
        public static Dictionary<string, object> Answer(string home, string appData, Dictionary<string, object> decl)
        {
            string issuer = Json.Str(decl, "issuer"), key = Json.Str(decl, "key");
            var ask = AskPath(appData, issuer);
            string text;
            try
            {
                if (!File.Exists(ask)) return Idle("no_question");
                if ((DateTime.UtcNow - File.GetLastWriteTimeUtc(ask)).TotalMinutes > AskMinutes) return Idle("old");
                text = File.ReadAllText(ask).Replace("\r", "");
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return Idle("unreadable"); }
            var q = text.StartsWith(AskHeader, StringComparison.Ordinal) ? Fields(text) : null;
            if (q == null || !q.TryGetValue("nonce", out var nonce) || !NonceHex.IsMatch(nonce)
                || !q.TryGetValue("account", out var account) || !Account.IsMatch(account)) return Idle("malformed");
            q.TryGetValue("steam", out var steam);
            if (steam != null && (!SteamHex.IsMatch(steam) || steam == account)) steam = null;     // not one: the question stands without it
            var before = ReadText(AttestPath(appData, issuer));
            if (before != null && Fields(before).TryGetValue("nonce", out var had) && had == nonce) return Idle("answered");

            var rec = IssuerRecord(home, issuer);
            var tokens = RenewTokens(rec);
            if (tokens.Count == 0) return Refuse(appData, issuer, nonce, "sign_in_again");
            if (Json.Str(rec, "key") != key) return Err("key_changed");
            // the member whose license names the account is asked first
            var held = ReadLicense(appData, issuer) is string lt ? Licenses(lt, issuer, key) : new List<Dictionary<string, string>>();
            var naming = new HashSet<string>(held.Where(f => Named(f).Contains(account)).Select(Holder));
            string error = null;
            foreach (var (_, token) in tokens.OrderBy(t => naming.Contains(t.Holder) ? 0 : 1))
            {
                var question = new Dictionary<string, object> { ["renew"] = token, ["nonce"] = nonce, ["account"] = account };
                if (steam != null) question["steam"] = steam;
                var (status, body) = Post(home, issuer, "/attest", question);
                if (status == 200)
                {
                    var got = Json.Str(body, "attest");
                    var f = got == null ? null : VerifyAttest(got, issuer, key);
                    if (f == null || f["nonce"] != nonce || f["account"] != account) { error = error ?? "bad_answer"; continue; }
                    // (2026-11-17) the account was bound by this answer: the license naming it
                    // comes with it and replaces the member's own (written first, so the mod
                    // finds it when it reads the answer)
                    var lic = Json.Str(body, "license");
                    if (lic != null)
                    {
                        if (Verify(lic, issuer, key) == null) { error = error ?? "bad_license"; continue; }
                        WriteLicense(appData, issuer, key, lic);
                    }
                    WriteText(AttestPath(appData, issuer), got);
                    return new Dictionary<string, object> { ["answered"] = true, ["nonce"] = nonce, ["time"] = long.Parse(f["time"]) };
                }
                if (status == 403) { error = error ?? Json.Str(body, "error") ?? "unknown"; continue; }
                return Err("network");
            }
            return Refuse(appData, issuer, nonce, error ?? "unknown");
        }

        static Dictionary<string, object> Idle(string why) => new Dictionary<string, object> { ["answered"] = false, ["why"] = why };

        static Dictionary<string, object> Refuse(string appData, string issuer, string nonce, string error)
        {
            WriteText(AttestPath(appData, issuer), AttestHeader + "nonce=" + nonce + "\nerror=" + error + "\n");
            return Err(error);
        }

        /// <summary>key=value lines after the header.</summary>
        static Dictionary<string, string> Fields(string text)
        {
            var f = new Dictionary<string, string>();
            foreach (var line in text.Replace("\r", "").Split('\n').Skip(1))
            {
                int eq = line.IndexOf('=');
                if (eq > 0 && !f.ContainsKey(line.Substring(0, eq))) f[line.Substring(0, eq)] = line.Substring(eq + 1);
            }
            return f;
        }

        /// <summary>The fields of an answer signed by key for issuer, else null (the license's rules).</summary>
        static Dictionary<string, string> VerifyAttest(string text, string issuer, string key)
        {
            text = text.Replace("\r", "");
            int at = text.IndexOf("\nsig=", StringComparison.Ordinal);
            if (!text.StartsWith(AttestHeader, StringComparison.Ordinal) || at < 0) return null;
            string signed = text.Substring(0, at + 1), sig = text.Substring(at + 5).Trim();
            var f = Fields(signed);
            if (!f.TryGetValue("issuer", out var iss) || iss != issuer || !f.ContainsKey("nonce") || !f.ContainsKey("account")
                || !f.TryGetValue("time", out var t) || !long.TryParse(t, out _)) return null;
            var modulus = Bytes(key);
            if (!Regex.IsMatch(sig, "^[0-9a-fA-F]+$") || sig.Length != modulus.Length * 2) return null;
            using (var rsa = new RSACng())
            {
                rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = new byte[] { 1, 0, 1 } });
                if (!rsa.VerifyData(Encoding.UTF8.GetBytes(signed), Bytes(sig), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return null;
            }
            return f;
        }

        static string ReadText(string path)
        {
            try { return File.Exists(path) ? File.ReadAllText(path) : null; }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return null; }
        }

        static void WriteText(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, text.Replace("\r", ""), new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(tmp, path, null);
            else File.Move(tmp, path);
        }

        // -- watching ------------------------------------------------------------------------

        static FileSystemWatcher watcher;
        static string watchedDir;
        static Dictionary<string, object> watchedHost;
        static readonly object watchLock = new object(), answerLock = new object();
        static int answerAgain;

        /// <summary>From the manager's start on: a question is answered when a mod writes it.
        /// One watcher for the folder, made again only when the folder changes (another AppData:
        /// the tests); never in a loop (2026-10-26 a watcher loop leaked kernel pool). One pass
        /// at once for a question written before the manager ran.</summary>
        public static void Watch(Dictionary<string, object> host)
        {
            lock (watchLock)
            {
                var dir = LicenseDir(AppData(host));
                watchedHost = host;
                if (watcher == null || !string.Equals(watchedDir, dir, StringComparison.OrdinalIgnoreCase))
                {
                    watcher?.Dispose();
                    Directory.CreateDirectory(dir);
                    var w = new FileSystemWatcher(dir, "*.ask") { NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite };
                    FileSystemEventHandler on = (s, e) => ThreadPool.QueueUserWorkItem(_ => AnswerAll(watchedHost));
                    w.Created += on;
                    w.Changed += on;
                    w.Renamed += (s, e) => ThreadPool.QueueUserWorkItem(_ => AnswerAll(watchedHost));
                    w.EnableRaisingEvents = true;
                    (watcher, watchedDir) = (w, dir);
                }
            }
            AnswerAll(host);
        }

        /// <summary>Every issuer of the library's mods; one pass at a time, and another after it
        /// when a question came meanwhile.</summary>
        static void AnswerAll(Dictionary<string, object> host)
        {
            Interlocked.Exchange(ref answerAgain, 1);
            if (!Monitor.TryEnter(answerLock)) return;
            try
            {
                while (Interlocked.Exchange(ref answerAgain, 0) == 1)
                    foreach (var (decl, _, _) in Issuers(LibraryOf(host)))
                        try { Answer(Home(host), AppData(host), decl); }
                        catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is CryptographicException || e is FormatException) { }
            }
            finally { Monitor.Exit(answerLock); }
        }
    }
}
