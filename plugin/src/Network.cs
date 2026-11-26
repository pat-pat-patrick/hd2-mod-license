using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Hd2Qd.License
{
    // (1.15.0) What this computer's network looked like when a site could not be reached, for the
    // license log (2026-11-26: a player in mainland China lost sign-ins to 20 s timeouts and member
    // content to "the remote certificate is invalid" in about 120 ms, i.e. something on that
    // computer or network answered in the issuer's place; the log could not say what).
    //
    // NetFacts knows nothing of licenses: it takes a URL and gives lines of words, so the manager
    // can take this file as it is if its own updates ever need the same.
    //
    // Never in these words: this computer's IP addresses, a network's name (SSID), a MAC address,
    // the computer's or Windows user's name, a remote proxy's address, the full process list.
    // Public server addresses (the site's own, public DNS servers) are not personal and are said.
    public static class NetFacts
    {
        // -- certificates Windows refused on a request ---------------------------------------

        static readonly ConcurrentDictionary<string, (DateTime At, string Words)> refused =
            new ConcurrentDictionary<string, (DateTime, string)>(StringComparer.OrdinalIgnoreCase);

        /// <summary>A handler whose check of a site's certificate is Windows' own, unchanged (only
        /// a certificate with no error passes, as with no callback); one it refuses is remembered
        /// with who issued it and why (Refused).</summary>
        public static HttpClientHandler Handler() => new HttpClientHandler { ServerCertificateCustomValidationCallback = See };

        static bool See(HttpRequestMessage request, X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors)
        {
            if (errors == SslPolicyErrors.None) return true;
            try { refused[request?.RequestUri?.Host ?? ""] = (DateTime.UtcNow, CertificateWords(cert, chain, errors)); }
            catch (Exception e) when (e is System.Security.Cryptography.CryptographicException || e is ArgumentException) { }
            return false;
        }

        /// <summary>Why the last certificate of this host was refused, when that was at or after
        /// <paramref name="since"/> (UTC); else null.</summary>
        public static string Refused(string host, DateTime since) =>
            host != null && refused.TryGetValue(host, out var r) && r.At >= since ? r.Words : null;

        /// <summary>"refused (RemoteCertificateChainErrors: UntrustedRoot): for x, issued by CN=y,
        /// O=z, root CN=r, valid 2026-01-01 to 2026-04-01". Names only, never the key.</summary>
        public static string CertificateWords(X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            var w = new StringBuilder(errors == SslPolicyErrors.None ? "accepted by Windows" : "refused (" + errors);
            var status = chain?.ChainStatus?.Select(s => s.Status).Where(s => s != X509ChainStatusFlags.NoError).Distinct().ToList();
            if (errors != SslPolicyErrors.None)
            {
                if (status != null && status.Count > 0) w.Append(": ").Append(string.Join(",", status));
                w.Append(')');
            }
            if (cert == null) return w.Append(": no certificate").ToString();
            var c2 = cert as X509Certificate2 ?? new X509Certificate2(cert);
            w.Append(": for ").Append(Clip(c2.GetNameInfo(X509NameType.SimpleName, false), 60));
            w.Append(", issued by ").Append(NameParts(c2.Issuer));
            if (chain != null && chain.ChainElements.Count > 1)
            {
                var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                if (root != null && root.Thumbprint != c2.Thumbprint) w.Append(", root ").Append(NameParts(root.Subject));
            }
            w.Append(", valid ").Append(c2.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd")).Append(" to ").Append(c2.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"));
            var now = DateTime.Now;
            if (now < c2.NotBefore || now > c2.NotAfter) w.Append(" (outside it by this computer's clock)");
            return w.ToString();
        }

        static readonly Regex NamePart = new Regex(@"(?:^|,\s*)(CN|O)=(""(?:[^""]|"""")*""|[^,]*)");

        /// <summary>A distinguished name's CN and O only ("CN=WE1, O=Google Trust Services").</summary>
        public static string NameParts(string dn)
        {
            var parts = NamePart.Matches(dn ?? "").Cast<Match>().Select(m => m.Groups[1].Value + "=" + m.Groups[2].Value.Trim().Trim('"')).ToList();
            return parts.Count == 0 ? "(no name)" : Clip(string.Join(", ", parts), 100);
        }

        // -- the site's clock -----------------------------------------------------------------

        static readonly ConcurrentDictionary<string, (DateTime Seen, double Ahead)> clocks =
            new ConcurrentDictionary<string, (DateTime, double)>(StringComparer.OrdinalIgnoreCase);

        /// <summary>A site's answer said this time (its Date header): how far this computer's
        /// clock is from it is kept, for ClockWords.</summary>
        public static void SawDate(string host, DateTimeOffset? date)
        {
            if (host == null || date == null) return;
            clocks[host] = (DateTime.UtcNow, (DateTimeOffset.UtcNow - date.Value).TotalSeconds);
        }

        /// <summary>This computer's clock against the site's last answer. A wrong clock makes a
        /// good certificate look expired or not yet valid.</summary>
        public static string ClockWords(string host)
        {
            if (host == null || !clocks.TryGetValue(host, out var c))
                return "no answer from the site since the manager started; this computer says " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm") + " UTC";
            var seen = " (its answer at " + c.Seen.ToLocalTime().ToString("HH:mm") + ")";
            var s = Math.Round(c.Ahead);
            if (Math.Abs(s) <= 5) return "agrees with the site to within 5 s" + seen;
            var size = Math.Abs(s) < 120 ? Math.Abs(s) + " s" : Math.Abs(s) < 7200 ? Math.Round(Math.Abs(s) / 60) + " min" : Math.Round(Math.Abs(s) / 3600, 1) + " h";
            return "this computer is " + size + (s > 0 ? " ahead of" : " behind") + " the site" + seen;
        }

        // -- addresses ------------------------------------------------------------------------

        /// <summary>What kind of address: "this computer", "blocked" (0.0.0.0, ::), "local network",
        /// "stand-in" (198.18.0.0/15: a proxy's fake address for a name it answers itself),
        /// "carrier NAT", "link-local", "Cloudflare", or "public".</summary>
        public static string Kind(IPAddress a)
        {
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            if (IPAddress.IsLoopback(a)) return "this computer";
            var b = a.GetAddressBytes();
            if (a.AddressFamily == AddressFamily.InterNetwork)
            {
                if (b[0] == 0) return "blocked";
                if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)) return "local network";
                if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return "stand-in";
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return "carrier NAT";
                if (b[0] == 169 && b[1] == 254) return "link-local";
            }
            else
            {
                if (a.Equals(IPAddress.IPv6Any)) return "blocked";
                if (a.IsIPv6LinkLocal) return "link-local";
                if ((b[0] & 0xfe) == 0xfc || a.IsIPv6SiteLocal) return "local network";
            }
            return Cloudflare.Any(n => n.Holds(a)) ? "Cloudflare" : "public";
        }

        /// <summary>An address as the log may say it: public ones (a server's) and this computer's
        /// loopback as they are, a stand-in one with its kind; a local network's, carrier NAT's or
        /// link-local one by its kind only (it is this computer's own, or its router's).</summary>
        public static string AddressWords(IPAddress a)
        {
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();      // ::ffff:127.0.2.2 is 127.0.2.2
            var kind = Kind(a);
            switch (kind)
            {
                case "local network": case "carrier NAT": case "link-local": return "a " + kind + " address";
                case "public": return a.ToString();
                default: return a + " (" + kind + ")";
            }
        }

        struct Net
        {
            public byte[] Bytes; public int Bits;
            public bool Holds(IPAddress a)
            {
                var b = a.GetAddressBytes();
                if (b.Length != Bytes.Length) return false;
                for (int i = 0, left = Bits; left > 0; i++, left -= 8)
                {
                    int mask = left >= 8 ? 0xff : (0xff << (8 - left)) & 0xff;
                    if ((b[i] & mask) != (Bytes[i] & mask)) return false;
                }
                return true;
            }
        }

        // Cloudflare's published ranges (cloudflare.com/ips, 2026-11)
        static readonly Net[] Cloudflare = new[]
        {
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
            "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
            "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
            "2a06:98c0::/29", "2c0f:f248::/32",
        }.Select(s => { var p = s.Split('/'); return new Net { Bytes = IPAddress.Parse(p[0]).GetAddressBytes(), Bits = int.Parse(p[1]) }; }).ToArray();

        /// <summary>"127.0.0.1:7890 (this computer)", "a local network address, port 8080", "a
        /// remote host, port 443": where a proxy or a script is, never a remote one's address.</summary>
        public static string EndpointWords(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return "(empty)";
            text = text.Trim();
            if (!Uri.TryCreate(text.Contains("://") ? text : "http://" + text, UriKind.Absolute, out var u)) return "(unreadable)";
            var port = u.IsDefaultPort && !text.Contains("://") ? "" : u.Port.ToString();
            var host = u.Host.Trim('[', ']');
            if (IPAddress.TryParse(host, out var a))
            {
                var kind = Kind(a);
                if (kind == "this computer") return a + (port != "" ? ":" + port : "") + " (this computer)";
                return (kind == "public" || kind == "Cloudflare" ? "a remote address" : "a " + kind + " address") + (port != "" ? ", port " + port : "");
            }
            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return "localhost" + (port != "" ? ":" + port : "") + " (this computer)";
            return "a remote host" + (port != "" ? ", port " + port : "");
        }

        // -- the facts ------------------------------------------------------------------------

        /// <summary>Lines "name: words" about reaching <paramref name="site"/> from here: proxy,
        /// adapters, windows (whether Windows itself finds the internet), hosts (lines of the hosts
        /// file that name the site's domain), software, clock; with <paramref name="probe"/> also
        /// dns (the site's name looked up here) and probe (connections made as a request would
        /// make them, through the proxy and straight over IPv4 and IPv6, side by side, up to the
        /// site's certificate, sending nothing; about 20 s at most). Never throws.</summary>
        public static List<string> Facts(Uri site, bool probe)
        {
            var lines = new List<string>();
            void Add(string name, Func<string> f)
            {
                string s;
                try { s = f(); }
                catch (Exception e) { s = "(" + e.GetType().Name + ")"; }   // a fact that fails is said, never thrown
                if (s != null) lines.Add(name + ": " + s);
            }
            Add("proxy", () => ProxyWords(site));
            Add("adapters", AdapterWords);
            Add("windows", WindowsConnectivityWords);
            Add("hosts", () => HostsWords(site.Host));
            Add("software", SoftwareWords);
            Add("clock", () => ClockWords(site.Host));
            if (probe)
            {
                Add("dns", () => DnsWords(site.Host));
                Add("probe", () => ProbeWords(site));
            }
            return lines;
        }

        /// <summary>Windows' proxy setting for this user (what .NET's requests use), and where a
        /// request to the site goes through it.</summary>
        public static string ProxyWords(Uri site)
        {
            var w = new List<string>();
            using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
            {
                bool on = k?.GetValue("ProxyEnable") is int e && e != 0;
                var server = k?.GetValue("ProxyServer") as string;
                w.Add("manual " + (on ? "on, " + ProxyListWords(server) : "off"));
                if (k?.GetValue("AutoConfigURL") is string pac && pac.Trim() != "") w.Add("setup script from " + EndpointWords(pac));
            }
            var sys = WebRequest.GetSystemWebProxy();
            var via = sys.IsBypassed(site) ? null : sys.GetProxy(site);
            w.Add(via == null || via == site || via.Equals(site) ? "a request to " + site.Host + " goes direct"
                : "a request to " + site.Host + " goes via " + EndpointWords(via.GetLeftPart(UriPartial.Authority)));
            return string.Join("; ", w);
        }

        static string ProxyListWords(string server)
        {
            if (string.IsNullOrWhiteSpace(server)) return "(no server)";
            return string.Join(", ", server.Split(';').Where(p => p.Trim() != "").Take(4).Select(p =>
            {
                var eq = p.IndexOf('=');
                return eq > 0 && !p.Substring(0, eq).Contains("/") ? p.Substring(0, eq).Trim() + " " + EndpointWords(p.Substring(eq + 1)) : EndpointWords(p);
            }));
        }

        /// <summary>Each network adapter that is up: its kind and driver name ("Wireless80211
        /// "Intel(R) Wi-Fi 6 AX201""; a VPN's or accelerator's tunnel shows as such), whether it is
        /// a way out (a default gateway), and its DNS servers. Not its name, address or network.</summary>
        public static string AdapterWords()
        {
            var parts = new List<string>();
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.OperationalStatus != OperationalStatus.Up || n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var p = n.GetIPProperties();
                bool way = p.GatewayAddresses.Any(g => g.Address != null && !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.IPv6Any));
                var dns = p.DnsAddresses.Select(AddressWords).Distinct().Take(4).ToList();
                parts.Add(TypeWords(n.NetworkInterfaceType) + " \"" + Clip(n.Description, 60) + "\"" + (way ? ", default gateway" : "") + (dns.Count > 0 ? ", DNS " + string.Join(" / ", dns) : ""));
                if (parts.Count == 8) break;
            }
            return parts.Count == 0 ? "none up" : string.Join("; ", parts);
        }

        /// <summary>An adapter's kind; 53 (IANA propVirtual, which .NET's list lacks) is how
        /// Windows reports most VPN and accelerator tunnels (Wintun, Meta Tunnel, WARP).</summary>
        public static string TypeWords(NetworkInterfaceType t) =>
            Enum.IsDefined(typeof(NetworkInterfaceType), t) ? t.ToString() : (int)t == 53 ? "Virtual" : "type " + (int)t;

        // Programs that commonly stand between a computer and a site: proxies and VPNs, accelerators,
        // traffic tools, and security suites that scan HTTPS. Exact process names (lower case, no
        // .exe), then words a name only has to contain. A program not on the list is not said.
        static readonly Dictionary<string, string> Known = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["steam++"] = "Watt Toolkit (Steam++)", ["watt toolkit"] = "Watt Toolkit",
            ["clash"] = "Clash", ["clash-win64"] = "Clash", ["clash for windows"] = "Clash for Windows",
            ["clash-verge"] = "Clash Verge", ["verge-mihomo"] = "Clash Verge (mihomo)", ["verge-mihomo-alpha"] = "Clash Verge (mihomo)",
            ["mihomo"] = "mihomo", ["clash-meta"] = "Clash Meta", ["flclash"] = "FlClash", ["clash-nyanpasu"] = "Clash Nyanpasu",
            ["v2rayn"] = "v2rayN", ["v2ray"] = "V2Ray", ["xray"] = "Xray", ["sing-box"] = "sing-box", ["nekoray"] = "NekoRay",
            ["hiddify"] = "Hiddify", ["shadowsocks"] = "Shadowsocks", ["shadowsocksr"] = "ShadowsocksR", ["trojan"] = "Trojan",
            ["fiddler"] = "Fiddler", ["fiddler everywhere"] = "Fiddler Everywhere", ["charles"] = "Charles",
            ["mitmproxy"] = "mitmproxy", ["mitmdump"] = "mitmproxy", ["mitmweb"] = "mitmproxy", ["proxifier"] = "Proxifier",
            ["reqable"] = "Reqable", ["httpdebuggerui"] = "HTTP Debugger", ["burp"] = "Burp Suite",
            ["uu"] = "UU accelerator", ["avp"] = "Kaspersky", ["ekrn"] = "ESET", ["avastsvc"] = "Avast", ["avgsvc"] = "AVG",
            ["vsserv"] = "Bitdefender", ["bdagent"] = "Bitdefender", ["360tray"] = "360", ["360sd"] = "360", ["zhudongfangyu"] = "360",
            ["hipsdaemon"] = "Huorong (火绒)", ["hipstray"] = "Huorong (火绒)", ["qqpcrtp"] = "Tencent PC Manager", ["qqpctray"] = "Tencent PC Manager",
            ["nortonsecurity"] = "Norton", ["mcshield"] = "McAfee",
        };
        static readonly (string Part, string Label)[] KnownParts =
        {
            ("uubooster", "UU accelerator"), ("leigod", "Leigod accelerator"), ("xunyou", "Xunyou accelerator"),
            ("qiyou", "Qiyou accelerator"), ("golink", "GoLink accelerator"), ("biubiu", "biubiu accelerator"),
        };

        /// <summary>The programs from the list above that are running, by name; never any other.</summary>
        public static string SoftwareWords()
        {
            var found = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in Process.GetProcesses())
                using (p)
                {
                    string name;
                    try { name = p.ProcessName; } catch (InvalidOperationException) { continue; }
                    var label = Label(name);
                    if (label != null) found.Add(label);
                }
            return found.Count == 0 ? "none from the list" : string.Join(", ", found);
        }

        /// <summary>The list's name for a process name, or null when it is not on the list.</summary>
        public static string Label(string processName)
        {
            if (string.IsNullOrEmpty(processName)) return null;
            if (Known.TryGetValue(processName, out var label)) return label;
            var lower = processName.ToLowerInvariant();
            foreach (var (part, l) in KnownParts) if (lower.Contains(part)) return l;
            return null;
        }

        const int StepMs = 10000;

        /// <summary>What Windows itself says of the internet (its Network List Manager, the same
        /// check as the taskbar's "no internet" mark), for IPv4 and IPv6. Sends nothing.</summary>
        public static string WindowsConnectivityWords()
        {
            var type = Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B"));
            var nlm = Activator.CreateInstance(type);
            try { return ConnectivityWords(Convert.ToInt32(type.InvokeMember("GetConnectivity", System.Reflection.BindingFlags.InvokeMethod, null, nlm, null))); }
            finally { if (System.Runtime.InteropServices.Marshal.IsComObject(nlm)) System.Runtime.InteropServices.Marshal.ReleaseComObject(nlm); }
        }

        /// <summary>NLM_CONNECTIVITY in words: "internet" for IPv4 and for IPv6, or what less.</summary>
        public static string ConnectivityWords(int c)
        {
            string One(int notraffic, int subnet, int local, int internet) =>
                (c & internet) != 0 ? "internet" : (c & local) != 0 ? "local network only" : (c & subnet) != 0 ? "subnet only" : (c & notraffic) != 0 ? "no traffic" : "none";
            return "IPv4 " + One(0x1, 0x10, 0x20, 0x40) + ", IPv6 " + One(0x2, 0x100, 0x200, 0x400);
        }

        /// <summary>The lines of the hosts file that name the site's domain (a tool that points a
        /// name at this computer writes one there); comments left out. Never another line.</summary>
        public static string HostsWords(string host, string path = null)
        {
            path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
            var labels = host.Split('.');
            var domain = labels.Length >= 2 ? labels[labels.Length - 2] + "." + labels[labels.Length - 1] : host;
            if (!File.Exists(path)) return "no hosts file";
            var hits = new List<string>();
            foreach (var raw in File.ReadLines(path))
            {
                var hash = raw.IndexOf('#');
                var line = (hash >= 0 ? raw.Substring(0, hash) : raw).Trim();
                if (line == "") continue;
                var names = Regex.Split(line, @"\s+").Skip(1);
                if (names.Any(n => n.Equals(domain, StringComparison.OrdinalIgnoreCase) || n.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)))
                    hits.Add(Clip(Regex.Replace(line, @"\s+", " "), 100));
                if (hits.Count == 5) break;
            }
            return hits.Count == 0 ? "no line names " + domain : string.Join("; ", hits);
        }

        /// <summary>The site's name looked up here: its addresses and their kinds (a stand-in, this
        /// computer or a non-Cloudflare one tells a proxy or a redirect), and how long it took.</summary>
        public static string DnsWords(string host)
        {
            var clock = Stopwatch.StartNew();
            var (found, failed) = Lookup(host);
            if (found == null) return host + ": " + failed;
            return host + " -> " + string.Join(", ", found.Take(6).Select(AddressWords)) + " in " + clock.ElapsedMilliseconds + " ms";
        }

        static (IPAddress[] Found, string Failed) Lookup(string host)
        {
            if (IPAddress.TryParse(host.Trim('[', ']'), out var literal)) return (new[] { literal }, null);
            var clock = Stopwatch.StartNew();
            var t = Dns.GetHostAddressesAsync(host);
            try { if (!t.Wait(StepMs)) return (null, "no answer in " + StepMs / 1000 + " s"); }
            catch (AggregateException e) when (e.InnerException is SocketException s) { return (null, "failed (" + s.SocketErrorCode + ") in " + clock.ElapsedMilliseconds + " ms"); }
            return t.Result.Length == 0 ? (null, "no address") : (t.Result, null);
        }

        /// <summary>The proxy Windows names for a request to the site, or null when it goes direct.</summary>
        static Uri ProxyFor(Uri site)
        {
            var sys = WebRequest.GetSystemWebProxy();
            var via = sys.IsBypassed(site) ? null : sys.GetProxy(site);
            return via == null || via == site || via.Equals(site) ? null : via;
        }

        /// <summary>Connections made as a request to the site would make them, side by side: through
        /// the proxy Windows names (HTTP CONNECT), when it names one; and straight to the site's
        /// first IPv4 and first IPv6 address. A request that only fails one way (a broken IPv6, a
        /// proxy that answers for the site) shows as that way alone failing. Each goes up to the
        /// certificate the other side shows and is closed, nothing sent to the site; " | " between.</summary>
        public static string ProbeWords(Uri site)
        {
            var routes = new List<Func<string>>();
            var via = ProxyFor(site);
            if (via != null) routes.Add(() => Probe(site, via, null));
            var (found, failed) = Lookup(site.Host);
            if (found == null) routes.Add(() => "direct: name lookup " + failed);
            else
            {
                var v4 = found.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                var v6 = found.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);
                if (v4 != null) routes.Add(() => Probe(site, null, v4));
                if (v6 != null) routes.Add(() => Probe(site, null, v6));
                if (v4 == null && v6 == null) routes.Add(() => "direct: no IPv4 or IPv6 address");
            }
            var runs = routes.Select(r => Task.Run(() =>
            {
                try { return r(); }
                catch (Exception e) { return "(" + e.GetType().Name + ")"; }   // one way failing says so; never thrown
            })).ToArray();
            Task.WaitAll(runs);
            return string.Join(" | ", runs.Select(t => t.Result));
        }

        /// <summary>One way to the site: through <paramref name="via"/>, or straight to
        /// <paramref name="address"/>; how long each step took and whose certificate came back.</summary>
        static string Probe(Uri site, Uri via, IPAddress address)
        {
            int port = site.Port > 0 ? site.Port : 443;
            var w = new StringBuilder();
            var clock = Stopwatch.StartNew();
            int targetPort = port;
            if (via != null)
            {
                var (found, failed) = Lookup(via.Host);
                if (found == null) return "via proxy " + EndpointWords(via.GetLeftPart(UriPartial.Authority)) + ": name lookup " + failed;
                address = found.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? found[0];
                targetPort = via.Port;
                w.Append("via proxy ").Append(EndpointWords(via.GetLeftPart(UriPartial.Authority))).Append(": ");
            }
            else
                w.Append("direct ").Append(address.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4").Append(" to ")
                 .Append(AddressWords(address)).Append(":").Append(port).Append(": ");

            using (var tcp = new TcpClient(address.AddressFamily))
            {
                clock.Restart();
                var connect = tcp.ConnectAsync(address, targetPort);
                try { if (!connect.Wait(StepMs)) return w.Append("connect: no answer in " + StepMs / 1000 + " s").ToString(); }
                catch (AggregateException e) when (e.InnerException is SocketException s) { return w.Append("connect failed (" + s.SocketErrorCode + ") in " + clock.ElapsedMilliseconds + " ms").ToString(); }
                w.Append("connect ").Append(clock.ElapsedMilliseconds).Append(" ms");
                var stream = tcp.GetStream();
                stream.ReadTimeout = stream.WriteTimeout = StepMs;

                if (via != null)
                {
                    clock.Restart();
                    var ask = Encoding.ASCII.GetBytes("CONNECT " + site.Host + ":" + port + " HTTP/1.1\r\nHost: " + site.Host + ":" + port + "\r\n\r\n");
                    string head;
                    try
                    {
                        stream.Write(ask, 0, ask.Length);
                        head = ReadHead(stream);
                    }
                    catch (IOException e) { return w.Append(", proxy: " + Clip(Inner(e), 80) + " in " + clock.ElapsedMilliseconds + " ms").ToString(); }
                    var first = head.Split('\n')[0].Trim();
                    w.Append(", proxy answered \"").Append(Clip(first, 40)).Append("\" in ").Append(clock.ElapsedMilliseconds).Append(" ms");
                    if (!Regex.IsMatch(first, @"^HTTP/1\.[01] 200\b")) return w.ToString();
                }

                string seen = null;
                using (var ssl = new SslStream(stream, false, (s, c, ch, e) => { seen = CertificateWords(c, ch, e); return false; }))
                {
                    clock.Restart();
                    var hello = ssl.AuthenticateAsClientAsync(site.Host);
                    try { if (!hello.Wait(StepMs)) return w.Append(seen != null ? ", TLS: certificate " + seen : ", TLS: no answer in " + StepMs / 1000 + " s").ToString(); }
                    catch (AggregateException e)
                    {
                        // the check above refuses every certificate on purpose (nothing is to be sent), so
                        // having seen one is the end of a handshake that worked as far as it can
                        if (seen != null) return w.Append(", TLS ").Append(clock.ElapsedMilliseconds).Append(" ms, certificate ").Append(seen).ToString();
                        return w.Append(", TLS failed in ").Append(clock.ElapsedMilliseconds).Append(" ms: ").Append(Clip(Inner(e), 100)).ToString();
                    }
                    return w.Append(", TLS ").Append(clock.ElapsedMilliseconds).Append(" ms, certificate ").Append(seen ?? "(none seen)").ToString();
                }
            }
        }

        /// <summary>What kind of failure a request met, so a new kind is looked at again at once:
        /// "certificate" (Windows refused it), "timeout", "name lookup", "connect", "closed"
        /// (reset or dropped during TLS or the answer), or the exception's own name.</summary>
        public static string FailureKind(Exception e, bool certificateRefused)
        {
            if (certificateRefused) return "certificate";
            if (e == null) return "unknown";
            if (e is TaskCanceledException || e is OperationCanceledException) return "timeout";
            for (var x = e; x != null; x = x.InnerException)
            {
                if (x is WebException w)
                    switch (w.Status)
                    {
                        case WebExceptionStatus.NameResolutionFailure: case WebExceptionStatus.ProxyNameResolutionFailure: return "name lookup";
                        case WebExceptionStatus.ConnectFailure: return "connect";
                        case WebExceptionStatus.Timeout: return "timeout";
                        case WebExceptionStatus.TrustFailure: return "certificate";
                        case WebExceptionStatus.SecureChannelFailure: case WebExceptionStatus.ReceiveFailure:
                        case WebExceptionStatus.SendFailure: case WebExceptionStatus.ConnectionClosed: return "closed";
                    }
                if (x is SocketException s)
                    return s.SocketErrorCode == SocketError.TimedOut ? "timeout" : s.SocketErrorCode == SocketError.HostNotFound ? "name lookup"
                         : s.SocketErrorCode == SocketError.ConnectionRefused ? "connect" : "closed";
            }
            return e.Message != null && e.Message.StartsWith("no answer in") ? "timeout" : e.GetType().Name;
        }

        /// <summary>An HTTP head, up to its blank line (4 KB at most).</summary>
        static string ReadHead(Stream s)
        {
            var b = new List<byte>();
            while (b.Count < 4096)
            {
                int x = s.ReadByte();
                if (x < 0) break;
                b.Add((byte)x);
                int n = b.Count;
                if (n >= 4 && b[n - 4] == '\r' && b[n - 3] == '\n' && b[n - 2] == '\r' && b[n - 1] == '\n') break;
            }
            if (b.Count == 0) throw new IOException("the proxy closed the connection");
            return Encoding.ASCII.GetString(b.ToArray());
        }

        static string Inner(Exception e)
        {
            while (e.InnerException != null) e = e.InnerException;
            return e.GetType().Name + ": " + (e.Message ?? "");
        }

        static string Clip(string s, int n) => s == null ? "" : s.Length > n ? s.Substring(0, n) : s;
    }

    public static partial class Plugin
    {
        /// <summary>(1.15.0) Tests turn this off: a failed request then looks at nothing.</summary>
        public static bool LookAtNetworkOnFailure = true;

        /// <summary>(1.15.0) How often a failing issuer's network is looked at for the same kind of
        /// failure (once per issuer in this time, so a run of retries logs it once); a new kind
        /// (a timeout, then a refused certificate) is looked at at once.</summary>
        public static TimeSpan LookEvery = TimeSpan.FromMinutes(10);

        static readonly Dictionary<string, (DateTime At, string Kind)> lastLook = new Dictionary<string, (DateTime, string)>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Whether a failure of this kind is to be looked at now (and, when it is, notes it):
        /// the first, a kind unlike the last one looked at, or the same kind LookEvery later.</summary>
        public static bool LookNow(string home, string issuer, string kind)
        {
            var key = home + "|" + issuer;
            lock (lastLook)
            {
                if (lastLook.TryGetValue(key, out var was) && was.Kind == kind && DateTime.UtcNow - was.At < LookEvery) return false;
                lastLook[key] = (DateTime.UtcNow, kind);
                return true;
            }
        }

        /// <summary>An issuer just could not be reached: in the background, this computer's network
        /// facts (NetFacts.Facts, with the probe) go into the log as "network: ..." lines, after one
        /// that says which failure they follow. Not for a test issuer or one on this computer (http).</summary>
        static void LookAtNetwork(string home, string issuer, Exception failed, DateTime since)
        {
            if (!LookAtNetworkOnFailure || home == null || issuer == null || TestIssuer(issuer) || !Base(issuer).StartsWith("https://")) return;
            var kind = NetFacts.FailureKind(failed, NetFacts.Refused(IssuerHost(issuer), since) != null);
            if (!LookNow(home, issuer, kind)) return;
            Task.Run(() =>
            {
                try
                {
                    var facts = NetFacts.Facts(new Uri(Base(issuer) + "/"), probe: true);
                    Log(home, issuer, "network: looked at after a failure: " + kind);
                    foreach (var line in facts) Log(home, issuer, "network: " + line);
                }
                catch (Exception e) { Log(home, issuer, "network: (" + e.GetType().Name + ")"); }   // never into the manager
            });
        }

        /// <summary>The host of an issuer ("license.example.com" of "license.example.com:8443").</summary>
        static string IssuerHost(string issuer)
        {
            try { return new Uri(Base(issuer) + "/").Host; }
            catch (UriFormatException) { return issuer; }
        }

        /// <summary>" [certificate refused (...): ...]" when Windows refused this issuer's
        /// certificate since <paramref name="since"/>; else "".</summary>
        static string RefusedWords(string issuer, DateTime since) =>
            NetFacts.Refused(IssuerHost(issuer), since) is string c ? " [certificate " + c + "]" : "";
    }
}
