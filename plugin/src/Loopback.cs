using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Hd2Qd.License
{
    /// <summary>Where the browser comes back to after signing in (OAuth for native apps, RFC 8252):
    /// a listener on 127.0.0.1 at a port the system picks, for this one sign-in. Only this
    /// computer can reach it. A plain socket rather than HttpListener, so it needs no URL
    /// reservation and no administrator.</summary>
    sealed class Loopback : IDisposable
    {
        readonly TcpListener listener;

        public int Port { get; }

        public Loopback()
        {
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }

        /// <summary>The browser's return: GET /done?s=&lt;state&gt;&amp;..., its query, with the
        /// connection kept open for the page that answers it (Return.Reply). Anything else that
        /// arrives (a favicon, a wrong state: another page poking at this port) is answered 404 and
        /// passed over. null when the time runs out; OperationCanceledException when cancelled.</summary>
        public Return Receive(string state, DateTime until, CancellationToken cancel)
        {
            while (true)
            {
                cancel.ThrowIfCancellationRequested();
                if (!listener.Pending())
                {
                    if (DateTime.UtcNow >= until) return null;
                    if (cancel.WaitHandle.WaitOne(100)) throw new OperationCanceledException(cancel);
                    continue;
                }
                var client = listener.AcceptTcpClient();
                Dictionary<string, string> query = null;
                try
                {
                    client.ReceiveTimeout = client.SendTimeout = 5000;
                    query = Read(client.GetStream());
                }
                catch (IOException) { }
                catch (SocketException) { }
                if (query != null && query.TryGetValue("s", out var s) && s == state)
                    return new Return(client, query);
                try { Reply(client, 404, "<!doctype html><title>404</title>"); }
                catch (IOException) { }
                catch (SocketException) { }
                client.Dispose();
            }
        }

        /// <summary>The query of a GET /done request, or null.</summary>
        static Dictionary<string, string> Read(Stream stream)
        {
            var head = new StringBuilder();
            while (head.Length < 8192)
            {
                int b = stream.ReadByte();
                if (b < 0) return null;
                head.Append((char)b);
                if (head.Length >= 4 && head.ToString(head.Length - 4, 4) == "\r\n\r\n") break;
            }
            var first = head.ToString().Split(new[] { "\r\n" }, StringSplitOptions.None)[0].Split(' ');
            if (first.Length != 3 || first[0] != "GET") return null;
            var target = first[1];
            int q = target.IndexOf('?');
            if ((q < 0 ? target : target.Substring(0, q)) != "/done") return null;
            var query = new Dictionary<string, string>();
            if (q >= 0)
                foreach (var pair in target.Substring(q + 1).Split('&'))
                {
                    int eq = pair.IndexOf('=');
                    if (eq <= 0) continue;
                    query[Uri.UnescapeDataString(pair.Substring(0, eq))] = Uri.UnescapeDataString(pair.Substring(eq + 1).Replace('+', ' '));
                }
            return query;
        }

        static void Reply(TcpClient client, int status, string html)
        {
            var body = Encoding.UTF8.GetBytes(html);
            var head = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + (status == 200 ? " OK" : " Not Found") + "\r\n"
                + "Content-Type: text/html; charset=utf-8\r\nContent-Length: " + body.Length + "\r\n"
                + "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n");
            var s = client.GetStream();
            s.Write(head, 0, head.Length);
            s.Write(body, 0, body.Length);
            s.Flush();
        }

        /// <summary>The browser that came back, waiting for its page.</summary>
        public sealed class Return
        {
            readonly TcpClient client;
            public readonly Dictionary<string, string> Query;

            internal Return(TcpClient client, Dictionary<string, string> query)
            {
                this.client = client;
                Query = query;
            }

            public string this[string key] => Query.TryGetValue(key, out var v) ? v : null;

            /// <summary>Answers the browser with a page and lets it go; a browser already gone is no matter.</summary>
            public void Reply(string html)
            {
                try { Loopback.Reply(client, 200, html); }
                catch (IOException) { }
                catch (SocketException) { }
                catch (ObjectDisposedException) { }
                finally { client.Dispose(); }
            }
        }

        public void Dispose() => listener.Stop();
    }
}
