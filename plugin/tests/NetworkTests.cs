using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Hd2Qd.License;
using Xunit;

namespace Hd2Qd.License.Tests
{
    /// <summary>(1.15.0) NetFacts: what the license log says about this computer's network when
    /// an issuer cannot be reached, and what it never says.</summary>
    public class NetworkFacts
    {
        [Fact]
        public void Addresses_are_said_by_kind_and_this_computers_own_never_as_they_are()
        {
            Assert.Equal("127.0.0.1 (this computer)", NetFacts.AddressWords(IPAddress.Parse("127.0.0.1")));
            Assert.Equal("198.18.0.7 (stand-in)", NetFacts.AddressWords(IPAddress.Parse("198.18.0.7")));
            Assert.Equal("104.16.1.1 (Cloudflare)", NetFacts.AddressWords(IPAddress.Parse("104.16.1.1")));
            Assert.Equal("2606:4700::1 (Cloudflare)", NetFacts.AddressWords(IPAddress.Parse("2606:4700::1")));
            Assert.Equal("0.0.0.0 (blocked)", NetFacts.AddressWords(IPAddress.Parse("0.0.0.0")));
            Assert.Equal("8.8.8.8", NetFacts.AddressWords(IPAddress.Parse("8.8.8.8")));             // a public server: as it is
            Assert.Equal("a local network address", NetFacts.AddressWords(IPAddress.Parse("192.168.1.5")));
            Assert.Equal("a local network address", NetFacts.AddressWords(IPAddress.Parse("10.2.3.4")));
            Assert.Equal("a local network address", NetFacts.AddressWords(IPAddress.Parse("172.20.0.9")));
            Assert.Equal("a carrier NAT address", NetFacts.AddressWords(IPAddress.Parse("100.72.1.2")));
            Assert.Equal("a link-local address", NetFacts.AddressWords(IPAddress.Parse("fe80::1234")));
            Assert.Equal("a local network address", NetFacts.AddressWords(IPAddress.Parse("fd00::5")));
            Assert.Equal("127.0.2.2 (this computer)", NetFacts.AddressWords(IPAddress.Parse("::ffff:127.0.2.2")));
            Assert.Equal("Virtual", NetFacts.TypeWords((NetworkInterfaceType)53));                 // how tunnels are reported
            Assert.Equal("Wireless80211", NetFacts.TypeWords(NetworkInterfaceType.Wireless80211));
            Assert.Equal("public", NetFacts.Kind(IPAddress.Parse("172.15.0.1")));                   // just outside 172.16/12
            Assert.Equal("public", NetFacts.Kind(IPAddress.Parse("104.32.0.1")));                   // just outside 104.16/13 + 104.24/14
        }

        [Fact]
        public void A_proxy_on_this_computer_is_named_and_a_remote_one_only_by_its_port()
        {
            Assert.Equal("127.0.0.1:7890 (this computer)", NetFacts.EndpointWords("127.0.0.1:7890"));
            Assert.Equal("localhost:33331 (this computer)", NetFacts.EndpointWords("http://localhost:33331/pac?t=1"));
            Assert.Equal("a local network address, port 8080", NetFacts.EndpointWords("192.168.0.2:8080"));
            Assert.Equal("a remote host, port 3128", NetFacts.EndpointWords("proxy.someone.example:3128"));
            Assert.Equal("a remote address, port 1080", NetFacts.EndpointWords("http://203.0.113.5:1080"));
            Assert.DoesNotContain("someone", NetFacts.EndpointWords("http://proxy.someone.example:3128/x.pac"));
        }

        [Fact]
        public void Only_programs_on_the_list_are_named()
        {
            Assert.Equal("Watt Toolkit (Steam++)", NetFacts.Label("Steam++"));
            Assert.Equal("Clash Verge (mihomo)", NetFacts.Label("verge-mihomo"));
            Assert.Equal("Leigod accelerator", NetFacts.Label("LeigodLauncher"));
            Assert.Equal("Huorong (火绒)", NetFacts.Label("HipsDaemon"));
            Assert.Null(NetFacts.Label("notepad"));
            Assert.Null(NetFacts.Label("uuid-tool"));                                              // "uu" is a whole name only
            Assert.Null(NetFacts.Label(""));
        }

        [Fact]
        public void A_certificates_names_are_its_CN_and_O_only()
        {
            Assert.Equal("CN=WE1, O=Google Trust Services", NetFacts.NameParts("CN=WE1, O=Google Trust Services, C=US"));
            Assert.Equal("CN=Some Root, O=A, B Ltd", NetFacts.NameParts("CN=Some Root, O=\"A, B Ltd\", OU=x, L=Somewhere"));
            Assert.Equal("(no name)", NetFacts.NameParts("C=CN"));
        }

        [Fact]
        public void The_clock_is_said_against_the_sites_last_answer()
        {
            Assert.StartsWith("no answer from the site", NetFacts.ClockWords("clock-never.test"));
            NetFacts.SawDate("clock-ahead.test", DateTimeOffset.UtcNow.AddMinutes(-10));
            Assert.StartsWith("this computer is 10 min ahead of the site", NetFacts.ClockWords("clock-ahead.test"));
            NetFacts.SawDate("clock-ok.test", DateTimeOffset.UtcNow);
            Assert.StartsWith("agrees with the site", NetFacts.ClockWords("clock-ok.test"));
        }

        /// <summary>A site that answers with a certificate Windows does not trust, as an
        /// interceptor on a player's computer does: the request is refused as before, and the
        /// refusal says whose certificate it was. The probe sees the same and sends nothing.</summary>
        [Fact]
        public void An_untrusted_certificate_is_refused_and_named()
        {
            using (var site = new TlsSite("CN=Test Interceptor Root, O=HD2 Test"))
            {
                var since = DateTime.UtcNow;
                using (var http = new HttpClient(NetFacts.Handler()) { Timeout = TimeSpan.FromSeconds(10) })
                    Assert.ThrowsAny<HttpRequestException>(() => http.GetAsync("https://localhost:" + site.Port + "/").GetAwaiter().GetResult());
                var why = NetFacts.Refused("localhost", since);
                Assert.NotNull(why);
                Assert.StartsWith("refused (", why);
                Assert.Contains("UntrustedRoot", why);
                Assert.Contains("issued by CN=Test Interceptor Root, O=HD2 Test", why);
                Assert.Null(NetFacts.Refused("localhost", DateTime.UtcNow.AddMinutes(1)));          // only one since then

                // IPv4 and IPv6 side by side: the site listens on IPv4 only, so IPv6 alone fails
                var probe = NetFacts.ProbeWords(new Uri("https://localhost:" + site.Port + "/"));
                Assert.Matches(@"(^| \| )direct IPv4 to 127\.0\.0\.1 \(this computer\):\d+: connect \d+ ms, TLS \d+ ms, certificate refused \(", probe);
                Assert.Contains("CN=Test Interceptor Root, O=HD2 Test", probe);
                if (probe.Contains("direct IPv6")) Assert.Matches(@"direct IPv6 to ::1 \(this computer\):\d+: connect failed \(ConnectionRefused\)", probe);
                Thread.Sleep(200);
                Assert.Equal(0, site.DataReceived);                                                 // nothing ever sent past the handshake
            }
        }

        [Fact]
        public void A_site_that_takes_no_connection_is_said_so()
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            var probe = NetFacts.ProbeWords(new Uri("https://localhost:" + port + "/"));
            Assert.Contains("connect failed (ConnectionRefused)", probe);
        }

        /// <summary>Every fact together, as a failed request logs them: each is there, none throws,
        /// and none says this computer's own addresses, its name or the Windows user's.</summary>
        [Fact]
        public void The_facts_never_say_this_computers_addresses_or_names()
        {
            using (var site = new TlsSite("CN=Test Interceptor Root, O=HD2 Test"))
            {
                var lines = NetFacts.Facts(new Uri("https://localhost:" + site.Port + "/"), probe: true);
                Assert.Equal(new[] { "proxy", "adapters", "windows", "hosts", "software", "clock", "dns", "probe" }, lines.Select(l => l.Substring(0, l.IndexOf(':'))));
                var all = string.Join("\n", lines);
                Assert.DoesNotContain("(Exception)", all);
                foreach (var own in NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(u => u.Address))
                    if (!IPAddress.IsLoopback(own)) Assert.DoesNotContain(own.ToString(), all);
                foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
                {
                    var mac = n.GetPhysicalAddress().ToString();
                    if (mac.Length >= 12) Assert.DoesNotContain(mac, all.Replace("-", "").Replace(":", ""));
                }
                Assert.DoesNotContain(Environment.MachineName, all, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(Environment.UserName, all, StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void Windows_own_view_of_the_internet_is_read_and_said()
        {
            Assert.Equal("IPv4 internet, IPv6 local network only", NetFacts.ConnectivityWords(0x40 | 0x20 | 0x200));
            Assert.Equal("IPv4 none, IPv6 none", NetFacts.ConnectivityWords(0));
            Assert.Equal("IPv4 no traffic, IPv6 subnet only", NetFacts.ConnectivityWords(0x1 | 0x100));
            Assert.Matches(@"^IPv4 [a-z ]+, IPv6 [a-z ]+$", NetFacts.WindowsConnectivityWords());   // this computer's, read for real
        }

        [Fact]
        public void Only_the_hosts_lines_that_name_the_sites_domain_are_said()
        {
            var dir = Path.Combine(Path.GetTempPath(), "hd2lic_hosts_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            try
            {
                var hosts = Path.Combine(dir, "hosts");
                File.WriteAllLines(hosts, new[]
                {
                    "# 102.54.94.97     rhino.acme.com",
                    "127.0.0.1\tlicense.example.org   # a tool's line",
                    "#127.0.0.2 license.example.org",
                    "10.1.2.3 nas.home.lan my-own-pc",
                    "127.0.0.1 example.org",
                    "1.2.3.4 notexample.org",
                });
                Assert.Equal("127.0.0.1 license.example.org; 127.0.0.1 example.org", NetFacts.HostsWords("license.example.org", hosts));
                File.WriteAllLines(hosts, new[] { "10.1.2.3 nas.home.lan" });
                Assert.Equal("no line names example.org", NetFacts.HostsWords("license.example.org", hosts));
                Assert.Equal("no hosts file", NetFacts.HostsWords("license.example.org", Path.Combine(dir, "none")));
            }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public void A_failure_is_told_by_kind()
        {
            Assert.Equal("certificate", NetFacts.FailureKind(new HttpRequestException("x"), certificateRefused: true));
            Assert.Equal("timeout", NetFacts.FailureKind(new System.Threading.Tasks.TaskCanceledException(), false));
            Assert.Equal("name lookup", NetFacts.FailureKind(new HttpRequestException("x", new WebException("y", WebExceptionStatus.NameResolutionFailure)), false));
            Assert.Equal("connect", NetFacts.FailureKind(new HttpRequestException("x", new WebException("y", WebExceptionStatus.ConnectFailure)), false));
            Assert.Equal("closed", NetFacts.FailureKind(new HttpRequestException("x", new WebException("y", WebExceptionStatus.SecureChannelFailure)), false));
            Assert.Equal("timeout", NetFacts.FailureKind(new IOException("no answer in 1.5 s"), false));
            Assert.Equal("unknown", NetFacts.FailureKind(null, false));
        }

        /// <summary>A run of the same failure is looked at once per LookEvery; a new kind (a
        /// timeout, then a refused certificate, as a player switching a tool on) at once.</summary>
        [Fact]
        public void A_new_kind_of_failure_is_looked_at_again_at_once()
        {
            var home = "look-" + Guid.NewGuid().ToString("N");
            Assert.True(Plugin.LookNow(home, "lic.example", "timeout"));
            Assert.False(Plugin.LookNow(home, "lic.example", "timeout"));
            Assert.True(Plugin.LookNow(home, "lic.example", "certificate"));
            Assert.False(Plugin.LookNow(home, "lic.example", "certificate"));
            Assert.True(Plugin.LookNow(home, "lic.example", "timeout"));
            Assert.True(Plugin.LookNow(home, "other.example", "timeout"));                          // per issuer
        }

        /// <summary>A site on this computer that shows a certificate of its own making and counts
        /// any bytes that arrive after the handshake.</summary>
        sealed class TlsSite : IDisposable
        {
            readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            readonly X509Certificate2 cert;
            readonly Thread thread;
            public readonly int Port;
            int received;
            public int DataReceived => Volatile.Read(ref received);

            public TlsSite(string subject)
            {
                using (var rsa = new RSACng(2048))
                {
                    var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    using (var made = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30)))
                        cert = new X509Certificate2(made.Export(X509ContentType.Pfx), (string)null, X509KeyStorageFlags.Exportable);
                }
                listener.Start();
                Port = ((IPEndPoint)listener.LocalEndpoint).Port;
                thread = new Thread(Serve) { IsBackground = true };
                thread.Start();
            }

            void Serve()
            {
                while (true)
                {
                    TcpClient c;
                    try { c = listener.AcceptTcpClient(); }
                    catch (Exception e) when (e is SocketException || e is ObjectDisposedException || e is InvalidOperationException) { return; }
                    new Thread(() =>
                    {
                        using (c)
                        using (var ssl = new SslStream(c.GetStream()))
                            try
                            {
                                c.ReceiveTimeout = 5000;
                                ssl.AuthenticateAsServer(cert, false, SslProtocols.Tls12, false);
                                var b = new byte[256];
                                int n = ssl.Read(b, 0, b.Length);
                                if (n > 0) Interlocked.Add(ref received, n);
                            }
                            catch (Exception e) when (e is IOException || e is AuthenticationException || e is ObjectDisposedException) { }
                    }) { IsBackground = true }.Start();
                }
            }

            public void Dispose()
            {
                listener.Stop();
                cert.Dispose();
            }
        }
    }
}
