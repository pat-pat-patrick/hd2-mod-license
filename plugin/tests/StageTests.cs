using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Hd2Qd.License;
using Xunit;

namespace Hd2Qd.License.Tests
{
    /// <summary>(1.12.0) Protected game packages: the mod ships its patch files sealed, the issuer
    /// gives the key and the account's fingerprinted files, the plugin stages the plaintext for
    /// the manager (ModSource, PrepareDeploy, EndSession).</summary>
    public partial class LicensePlugin
    {
        const string PackWire = "pack.v1.0.0";

        string Stage => Path.Combine(Root, "game", "hd2qd_stage");

        Dictionary<string, object> StageHost(bool forSession = false, string lang = "en")
        {
            var h = Host(lang);
            h["stage"] = Stage;
            h["for_session"] = forSession;
            return h;
        }

        static byte[] Bytes(int seed, int length)
        {
            var b = new byte[length];
            new Random(seed).NextBytes(b);
            return b;
        }

        static string ShaHex(byte[] b) { using (var sha = SHA256.Create()) return string.Concat(sha.ComputeHash(b).Select(x => x.ToString("x2"))); }

        static byte[] SealWith(byte[] key, byte[] plain)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = key; aes.GenerateIV();
                using (var enc = aes.CreateEncryptor()) return aes.IV.Concat(enc.TransformFinalBlock(plain, 0, plain.Length)).ToArray();
            }
        }

        /// <summary>The plaintext of a protected package: files (sealed into the mod) and parts (the
        /// issuer's fingerprinted files, V variants each), by path relative to the mod.</summary>
        sealed class Pack
        {
            public string Folder;
            public Dictionary<string, byte[]> Files = new Dictionary<string, byte[]>();
            public List<(string Path, byte[][] Variants)> Parts = new List<(string, byte[][])>();
            public string BaseHash;
        }

        /// <summary>(1.12.2) Raw DEFLATE, as the author tool's format 2 seals a file.</summary>
        static byte[] Deflate(byte[] plain)
        {
            using (var ms = new MemoryStream())
            {
                using (var z = new DeflateStream(ms, CompressionLevel.Optimal, true)) z.Write(plain, 0, plain.Length);
                return ms.ToArray();
            }
        }

        /// <summary>format 2 (the author tool's now) deflates each file before sealing it; format 1
        /// seals it as is. sealAs overrides what is sealed for a file (by path): a wrong build.</summary>
        Pack GamePack(string name = "Pack", string mode = "deploy", int parts = 2, int variants = 3, string wrongBase = null,
                      long format = 2, Func<string, byte[], byte[]> sealAs = null)
        {
            var pack = new Pack { Folder = Path.Combine(Root, "library", name) };
            pack.Files["opt/A/9ba626afa44a3aa3.patch_0"] = Bytes(1, 3 * 1024 * 1024 + 5);
            pack.Files["opt/A/9ba626afa44a3aa3.patch_0.gpu_resources"] = Bytes(2, 70001);
            pack.Files["9ba626afa44a3aa3.patch_0"] = Bytes(3, 1000);
            pack.Files["opt/A/0123456789abcdef.patch_0.gpu_resources"] = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("holo shader bytes ", 12000)));
            for (int p = 0; p < parts; p++)
                pack.Parts.Add(("opt/A/20bdec2a51065e1f.patch_" + p, Enumerable.Range(0, variants).Select(v => Bytes(100 + p * 10 + v, 4000 + p)).ToArray()));

            var key = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(key);
            Directory.CreateDirectory(pack.Folder);
            var files = new List<object>();
            foreach (var kv in pack.Files)
            {
                var sealedBytes = SealWith(key, sealAs != null ? sealAs(kv.Key, kv.Value) : format == 2 ? Deflate(kv.Value) : kv.Value);
                var target = Path.Combine(pack.Folder, "protected", kv.Key.Replace('/', '\\') + ".seal");
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                File.WriteAllBytes(target, sealedBytes);
                files.Add(new Dictionary<string, object> { ["path"] = kv.Key, ["size"] = (long)kv.Value.Length, ["sealed"] = ShaHex(sealedBytes), ["plain"] = ShaHex(kv.Value) });
            }
            var manifest = Encoding.UTF8.GetBytes(Json.Write(new Dictionary<string, object>
            {
                ["format"] = format, ["wire"] = PackWire, ["files"] = files,
                ["parts"] = pack.Parts.Select(x => (object)new Dictionary<string, object> { ["path"] = x.Path, ["size"] = (long)x.Variants[0].Length }).ToList(),
            }));
            File.WriteAllBytes(Path.Combine(pack.Folder, "protected", "manifest.json"), manifest);
            pack.BaseHash = ShaHex(manifest);
            File.WriteAllText(Path.Combine(pack.Folder, "hd2_license.json"), Json.Write(new Dictionary<string, object>
            {
                ["protocol"] = 1L, ["issuer"] = issuer.Name, ["name"] = "Test Author", ["key"] = KeyN("a"),
                ["payload"] = new Dictionary<string, object> { ["kind"] = "static", ["id"] = "pack", ["version"] = "v1.0.0", ["deploy"] = "game", ["mode"] = mode },
            }));
            File.WriteAllText(Path.Combine(pack.Folder, "manifest.json"), "{\"Version\":1,\"Name\":\"" + name + "\"}");
            issuer.PublishParts(PackWire, pack.Parts.Select(x => x.Variants).ToArray(), key);
            issuer.PartedBase[PackWire] = wrongBase ?? pack.BaseHash;
            return pack;
        }

        /// <summary>Signed in with a protected package in the library (its parts fetched).</summary>
        Pack SignedInPack(string mode = "deploy", int parts = 2, string wrongBase = null, long format = 2, Func<string, byte[], byte[]> sealAs = null)
        {
            Account(A);
            var pack = GamePack(mode: mode, parts: parts, wrongBase: wrongBase, format: format, sealAs: sealAs);
            InLibrary("Pack", pack.Folder);
            Assert.Equal("ok", SignIn(pack.Folder));
            return pack;
        }

        void AssertStagedAsPlain(Pack pack, string folder)
        {
            foreach (var kv in pack.Files)
                Assert.Equal(kv.Value, File.ReadAllBytes(Path.Combine(folder, kv.Key.Replace('/', '\\'))));
            var combo = issuer.ComboOf(A, pack.Parts.Count, 3);
            for (int p = 0; p < pack.Parts.Count; p++)
                Assert.Equal(pack.Parts[p].Variants[combo[p]], File.ReadAllBytes(Path.Combine(folder, pack.Parts[p].Path.Replace('/', '\\'))));
        }

        const string Roomy = "opt/A/0123456789abcdef.patch_0.gpu_resources";

        [Fact]
        public void A_deflated_package_is_staged_and_its_seal_is_far_smaller_than_the_file()
        {
            var pack = SignedInPack();
            var sealedSize = new FileInfo(Path.Combine(pack.Folder, "protected", Roomy.Replace('/', '\\') + ".seal")).Length;
            Assert.True(sealedSize < pack.Files[Roomy].Length / 4, sealedSize + " of " + pack.Files[Roomy].Length);
            var host = StageHost();
            Assert.True(Plugin.PrepareDeploy(host));
            AssertStagedAsPlain(pack, Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
        }

        [Fact]
        public void A_format_1_package_sealed_as_is_is_still_staged()
        {
            var pack = SignedInPack(format: 1);
            var host = StageHost();
            Assert.True(Plugin.PrepareDeploy(host));
            AssertStagedAsPlain(pack, Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
        }

        [Fact]
        public void A_format_2_file_sealed_without_deflating_is_not_staged()
        {
            var pack = SignedInPack(sealAs: (path, plain) => path == Roomy ? plain : Deflate(plain));
            var host = StageHost();
            Plugin.PrepareDeploy(host);
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
        }

        [Fact]
        public void A_deflated_file_that_inflates_past_its_size_is_not_staged()
        {
            // the manifest signs the real size; the seal inflates to 64 MB of zeros
            var pack = SignedInPack(sealAs: (path, plain) => Deflate(path == Roomy ? new byte[64 * 1024 * 1024] : plain));
            var host = StageHost();
            Plugin.PrepareDeploy(host);
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
            Assert.Empty(Directory.Exists(Stage) ? Directory.GetFiles(Stage, "*.new-*", SearchOption.AllDirectories) : new string[0]);
        }

        [Fact]
        public void An_unknown_manifest_format_is_not_staged()
        {
            var pack = SignedInPack(format: 3);
            var host = StageHost();
            Plugin.PrepareDeploy(host);
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
        }

        [Fact]
        public void A_game_package_is_staged_for_the_manager_and_never_written_again()
        {
            var pack = SignedInPack();
            var host = StageHost();
            var before = Plugin.ModSource(pack.Folder, host);
            Assert.Equal("", Json.Str(before, "folder"));
            Assert.Equal("deploy", Json.Str(before, "mode"));
            Assert.False(string.IsNullOrEmpty(Json.Str(before, "why")));

            Assert.True(Plugin.PrepareDeploy(host));
            var src = Plugin.ModSource(pack.Folder, host);
            var folder = Json.Str(src, "folder");
            Assert.StartsWith(Stage, folder);
            AssertStagedAsPlain(pack, folder);

            var big = Path.Combine(folder, "opt", "A", "9ba626afa44a3aa3.patch_0");
            var stamp = File.GetLastWriteTimeUtc(big);
            System.Threading.Thread.Sleep(20);
            Assert.True(Plugin.PrepareDeploy(host));                 // ready already: nothing written
            Assert.Equal(stamp, File.GetLastWriteTimeUtc(big));
            Assert.Equal(folder, Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
        }

        [Fact]
        public void A_package_with_no_fingerprinted_files_is_staged_from_its_key_alone()
        {
            var pack = SignedInPack(parts: 0);
            var host = StageHost();
            Assert.True(Plugin.PrepareDeploy(host));
            AssertStagedAsPlain(pack, Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
        }

        [Fact]
        public void A_game_package_neither_unlocks_at_a_game_start_nor_breaks_one()
        {
            var pack = SignedInPack();
            var host = StageHost();
            Assert.True(Plugin.ClaimAll(host));
            Plugin.OnGameStart(host, false);
            Plugin.OnGameStop(host);
            Assert.Contains("game started: 0 mod(s) with sealed member content", File.ReadAllText(Plugin.LogPath(Home)));
            Assert.False(Directory.Exists(Stage));
        }

        [Fact]
        public void A_tampered_sealed_file_stages_nothing()
        {
            var pack = SignedInPack();
            var seal = Path.Combine(pack.Folder, "protected", "9ba626afa44a3aa3.patch_0.seal");
            var b = File.ReadAllBytes(seal);
            b[40] ^= 1;
            File.WriteAllBytes(seal, b);
            var host = StageHost();
            Assert.False(Plugin.PrepareDeploy(host));
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
            Assert.Contains("did not decrypt to what the manifest signs", File.ReadAllText(Plugin.LogPath(Home)));
            Assert.DoesNotContain(Directory.GetFiles(Stage, "9ba626afa44a3aa3.patch_0*", SearchOption.AllDirectories),
                f => Path.GetDirectoryName(f).EndsWith("." + pack.BaseHash.Substring(0, 12)));
        }

        [Fact]
        public void A_receipt_for_another_build_stages_nothing()
        {
            var pack = SignedInPack(wrongBase: new string('e', 64));
            var host = StageHost();
            Assert.False(Plugin.PrepareDeploy(host));
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
            Assert.Contains("does not sign this mod's protected/manifest.json", File.ReadAllText(Plugin.LogPath(Home)));
        }

        [Fact]
        public void A_refused_membership_removes_the_staged_plaintext()
        {
            var pack = SignedInPack();
            var host = StageHost();
            Assert.True(Plugin.PrepareDeploy(host));
            var folder = Json.Str(Plugin.ModSource(pack.Folder, host), "folder");
            issuer.PayloadError = "not_member";
            Directory.CreateDirectory(Path.Combine(Stage, "other"));     // not ours: the root stays
            Plugin.ClaimAll(host, true);
            Assert.False(Directory.Exists(folder));
            Assert.False(Directory.Exists(Path.GetDirectoryName(folder)));    // the issuer's folder, now empty
            Assert.True(Directory.Exists(Path.Combine(Stage, "other")));
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateHardLink(string newName, string existing, IntPtr security);

        [Fact]
        public void A_session_package_is_staged_only_for_a_session_and_ends_with_it()
        {
            var pack = SignedInPack(mode: "session");
            Assert.True(Plugin.PrepareDeploy(StageHost(forSession: false)));     // not asked for: nothing to fail
            Assert.False(Directory.Exists(Stage));
            var host = StageHost(forSession: true);
            Assert.Equal("session", Json.Str(Plugin.ModSource(pack.Folder, host), "mode"));
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
            Assert.True(Plugin.PrepareDeploy(host));
            var folder = Json.Str(Plugin.ModSource(pack.Folder, host), "folder");
            Assert.False(string.IsNullOrEmpty(folder));

            // the manager's teardown deploy failed for one file: the game's data folder still links it
            var data = Path.Combine(Root, "game", "data");
            Directory.CreateDirectory(data);
            var linked = Path.Combine(folder, "9ba626afa44a3aa3.patch_0");
            Assert.True(CreateHardLink(Path.Combine(data, "9ba626afa44a3aa3.patch_0"), linked, IntPtr.Zero));

            Plugin.EndSession(host);
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
            Assert.True(File.Exists(linked));
            Assert.False(File.Exists(Path.Combine(folder, "opt", "A", "9ba626afa44a3aa3.patch_0")));
            Assert.True(Directory.Exists(Stage));          // a file is still in it: the folders above stay

            // once a deploy took it out of data, the next end removes it too, and (1.12.1) the empty
            // folders above it, the stage root included: nothing is left in the game's folder
            File.Delete(Path.Combine(data, "9ba626afa44a3aa3.patch_0"));
            Plugin.EndSession(host);
            Assert.False(Directory.Exists(folder));
            Assert.False(Directory.Exists(Stage));
        }

        [Fact]
        public void An_older_manager_is_named_on_the_row()
        {
            var pack = SignedInPack();
            var note = Plugin.ModNote(pack.Folder, Host());
            Assert.Equal("Manager update needed", Json.Str(note, "text"));
            Assert.NotEqual("Manager update needed", Json.Str(Plugin.ModNote(pack.Folder, StageHost()), "text"));
        }

        [Theory]
        [InlineData("../x.patch_0")] [InlineData("/x.patch_0")] [InlineData("a//b")] [InlineData("C:/x")] [InlineData("a/./b")]
        public void A_manifest_path_out_of_the_mod_stages_nothing(string bad)
        {
            var pack = SignedInPack();
            var path = Path.Combine(pack.Folder, "protected", "manifest.json");
            var d = (Dictionary<string, object>)Json.Parse(File.ReadAllText(path));
            ((Dictionary<string, object>)Json.List(d, "files")[0])["path"] = bad;
            var bytes = Encoding.UTF8.GetBytes(Json.Write(d));
            File.WriteAllBytes(path, bytes);
            issuer.PartedBase[PackWire] = ShaHex(bytes);
            var host = StageHost();
            Assert.False(Plugin.PrepareDeploy(host));
            Assert.Equal("", Json.Str(Plugin.ModSource(pack.Folder, host), "folder"));
        }
    }
}
