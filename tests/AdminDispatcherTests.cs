using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Dispatcher admin (spec phase 3 §5, §6) -----------------------------------

        private sealed class FakeDaemon : IDaemonControl
        {
            public bool Paused;
            public int ProcessId { get { return 4242; } }
            public DateTime StartedAt { get { return T0; } }
            public string Version { get { return "9.9.9"; } }
            public bool IsPaused { get { return Paused; } }
            public void SetPaused(bool paused) { Paused = paused; }
        }

        /// <summary>Dispatcher complet sur un dossier temporaire : config réelle, journal JSONL, porte en mémoire (ouverte) ou KeePass.</summary>
        private sealed class DispatcherRig : IDisposable
        {
            public string Dir;
            public bool OwnsDir;
            public DateTime Now = T0;
            public ConfigStore Config;
            public EventPipeline Events;
            public VaultGate Vault;
            public InMemorySecretStore Store = new InMemorySecretStore();
            public FakeDaemon Daemon = new FakeDaemon();
            public List<Config> Applied = new List<Config>();
            public bool Trusted;
            public string TrustedAsked;
            public AdminDispatcher Dispatcher;
            public string LastResponse;

            /// <summary>`memory` : porte ouverte en mémoire ; sinon porte KeePass sur `dir` (Absent ou Locked selon le contenu).</summary>
            public DispatcherRig(bool memory, string dir)
            {
                OwnsDir = dir == null;
                Dir = dir ?? TestDir.Create();
                Func<DateTime> clock = delegate { return Now; };
                DataDir.Prepare(Dir);
                Config = ConfigStore.Open(Dir, T0);
                Events = new EventPipeline(new EventRing(100), new JsonlEventStore(Path.Combine(Dir, "events"), 7, clock), new EventsBus());
                Vault = memory ? VaultGate.InMemory(Dir, Store, clock) : new VaultGate(Dir, VaultCA(), clock);
                AdminContext ctx = new AdminContext();
                ctx.Config = Config;
                ctx.Vault = Vault;
                ctx.Events = Events;
                ctx.Daemon = Daemon;
                ctx.Clock = clock;
                ctx.OnConfigChanged = delegate(Config c) { Applied.Add(c); };
                ctx.IsCATrusted = delegate(string thumbprint) { TrustedAsked = thumbprint; return Trusted; };
                Dispatcher = new AdminDispatcher(ctx);
            }

            public object Call(string method, IDictionary parameters)
            {
                byte[] response = Wait(Dispatcher.HandleAsync(JsonRpc.Request(7, method, parameters)));
                LastResponse = Encoding.UTF8.GetString(response);
                return JsonRpc.ParseResponse(response, 7);
            }

            public RpcException Fails(string method, IDictionary parameters, int code)
            {
                RpcException ex = Check.Throws<RpcException>(delegate { Call(method, parameters); }, method + " doit échouer");
                Check.Eq(code, ex.Code, method + " : code d'erreur (" + ex.Message + ")");
                return ex;
            }

            public void Dispose()
            {
                Vault.Dispose();
                Events.Store.Dispose();
                if (OwnsDir) TestDir.Delete(Dir);
            }
        }

        private static OrderedDictionary P(params object[] kv)
        {
            OrderedDictionary o = new OrderedDictionary();
            for (int i = 0; i < kv.Length; i += 2) o[(string)kv[i]] = kv[i + 1];
            return o;
        }

        private static JsonObject R(object result) { return new JsonObject((IDictionary<string, object>)result); }

        private static string B64(string s) { return Convert.ToBase64String(Encoding.UTF8.GetBytes(s)); }

        private static void Dispatcher_EnvelopeErrors()
        {
            using (DispatcherRig rig = new DispatcherRig(true, null))
            {
                string raw = Encoding.UTF8.GetString(Wait(rig.Dispatcher.HandleAsync(Bytes("{nope"))));
                Check.True(raw.Contains("\"id\":null") && raw.Contains("-32700"), "JSON illisible → -32700, id null : " + raw);
                raw = Encoding.UTF8.GetString(Wait(rig.Dispatcher.HandleAsync(Bytes("{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":[1],\"id\":4}"))));
                Check.True(raw.Contains("\"id\":4") && raw.Contains("-32602"), "params tableau → -32602 avec l'id");
                rig.Fails("bogus.method", null, RpcErrors.MethodNotFound);
                RpcException e = rig.Fails("secret.get", null, RpcErrors.InvalidParams);
                Check.True(e.Message.Contains("params"), "params manquants");
                rig.Fails("secret.get", P("nom", "x"), RpcErrors.InvalidParams);
            }
        }

        private static void Dispatcher_SecretMethods()
        {
            using (DispatcherRig rig = new DispatcherRig(true, null))
            {
                JsonObject added = R(rig.Call("secret.add", P("name", "gh_token", "allowed_hosts", new[] { "API.GitHub.com" }, "value", B64("ghp_secret"))));
                Check.True(added.String("name") == "gh_token" && string.Join(",", added.StringArray("allowed_hosts")) == "api.github.com", "secret.add normalise les hôtes");
                Check.True(!added.Has("value") && !rig.LastResponse.Contains("ghp_secret") && !rig.LastResponse.Contains(B64("ghp_secret")), "jamais de valeur dans la réponse");
                IList<object> list = (IList<object>)rig.Call("secret.list", null);
                Check.True(list.Count == 1 && !rig.LastResponse.Contains("ghp_secret"), "secret.list sans valeur");
                Check.Eq("gh_token", R(rig.Call("secret.get", P("name", "gh_token"))).String("name"), "secret.get");
                Check.Eq("api.github.com,uploads.github.com", string.Join(",", R(rig.Call("secret.update", P("name", "gh_token", "allowed_hosts", new[] { "api.github.com", "uploads.github.com" }))).StringArray("allowed_hosts")), "secret.update");
                rig.Call("secret.rotate", P("name", "gh_token", "value", B64("ghp_new")));
                Check.Eq("ghp_new", Encoding.UTF8.GetString(Wait(rig.Store.ValueAsync("gh_token"))), "secret.rotate");
                Check.True(R(rig.Call("secret.set_quarantined", P("name", "gh_token", "quarantined", true))).Bool("quarantined", false), "secret.set_quarantined");
                Check.True(R(rig.Call("secret.delete", P("name", "gh_token"))).Bool("deleted", false), "secret.delete");
                rig.Fails("secret.get", P("name", "gh_token"), RpcErrors.UnknownSecret);
                rig.Fails("secret.add", P("name", "bad name", "allowed_hosts", new[] { "a.example" }, "value", B64("v")), RpcErrors.InvalidName);
                rig.Fails("secret.add", P("name", "k", "allowed_hosts", new string[0], "value", B64("v")), RpcErrors.InvalidAllowedHosts);
                rig.Call("secret.add", P("name", "k", "allowed_hosts", new[] { "a.example" }, "value", B64("v")));
                rig.Fails("secret.add", P("name", "k", "allowed_hosts", new[] { "a.example" }, "value", B64("v")), RpcErrors.Duplicate);
                rig.Fails("secret.add", P("name", "k2", "allowed_hosts", new[] { "a.example" }, "value", "%%%"), RpcErrors.InvalidParams);
                rig.Fails("secret.add", P("name", "k2", "value", B64("v")), RpcErrors.InvalidParams);
                rig.Fails("secret.set_quarantined", P("name", "k", "quarantined", "oui"), RpcErrors.InvalidParams);
            }
        }

        private static void Dispatcher_VaultLockedRefusals()
        {
            using (DispatcherRig rig = new DispatcherRig(false, null))
            {
                JsonObject status = R(rig.Call("vault.status", null));
                Check.True(status.String("state") == "absent" && status.String("path").EndsWith("iris.kdbx"), "vault.status : absent");
                rig.Fails("secret.list", null, RpcErrors.VaultLocked);
                rig.Fails("secret.get", P("name", "k"), RpcErrors.VaultLocked);
                rig.Fails("secret.add", P("name", "k", "allowed_hosts", new[] { "a.example" }, "value", B64("v")), RpcErrors.VaultLocked);
                rig.Fails("secret.update", P("name", "k", "allowed_hosts", new[] { "a.example" }), RpcErrors.VaultLocked);
                rig.Fails("secret.rotate", P("name", "k", "value", B64("v")), RpcErrors.VaultLocked);
                rig.Fails("secret.delete", P("name", "k"), RpcErrors.VaultLocked);
                rig.Fails("secret.set_quarantined", P("name", "k", "quarantined", true), RpcErrors.VaultLocked);
            }
        }

        private static void Dispatcher_VaultMethods()
        {
            string dir = TestDir.Create();
            try
            {
                using (DispatcherRig rig = new DispatcherRig(false, dir))
                {
                    rig.Fails("vault.unlock", P("password", "x"), RpcErrors.NotFound);
                    rig.Fails("vault.create", P("password", ""), RpcErrors.InvalidParams);
                    rig.Fails("vault.create", P("password", 5L), RpcErrors.InvalidParams);
                    rig.Fails("vault.create", null, RpcErrors.InvalidParams);
                    Check.Eq("unlocked", R(rig.Call("vault.create", P("password", "maître-é€"))).String("state"), "vault.create ouvre le coffre");
                    Check.Eq("unlocked", R(rig.Call("vault.status", null)).String("state"), "vault.status : unlocked");
                    rig.Fails("vault.create", P("password", "autre"), RpcErrors.VaultExists);
                    Check.Eq("unlocked", R(rig.Call("vault.unlock", P("password", "faux"))).String("state"), "déjà ouvert : pas d'oracle");
                    rig.Call("secret.add", P("name", "k", "allowed_hosts", new[] { "a.example" }, "value", B64("v")));
                    File.WriteAllText(Path.Combine(dir, "iris.kdbx.lock"), "");
                    rig.Fails("secret.add", P("name", "k2", "allowed_hosts", new[] { "a.example" }, "value", B64("v")), RpcErrors.VaultBusy);
                    File.Delete(Path.Combine(dir, "iris.kdbx.lock"));
                }
                using (DispatcherRig rig = new DispatcherRig(false, dir))
                {
                    Check.Eq("locked", R(rig.Call("vault.status", null)).String("state"), "réouverture : locked");
                    rig.Fails("vault.unlock", P("password", "faux"), RpcErrors.BadPassword);
                    RpcException wait = rig.Fails("vault.unlock", P("password", "maître-é€"), RpcErrors.RateLimited);
                    Check.Eq(1L, (long)((IDictionary<string, object>)wait.ErrorData)["retry_after_s"], "retry_after_s");
                    rig.Now = rig.Now.AddSeconds(1);
                    Check.Eq("unlocked", R(rig.Call("vault.unlock", P("password", "maître-é€"))).String("state"), "mot de passe non ASCII par le pipe");
                    Check.True(R(rig.Call("secret.get", P("name", "k"))).String("name") == "k", "coffre utilisable après vault.unlock");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Dispatcher_LogsMethodNeverParams()
        {
            StringWriter log = new StringWriter();
            Log.Reset(); Log.Writer = log; Log.Minimum = LogLevel.Trace;
            string dir = TestDir.Create();
            try
            {
                StringBuilder responses = new StringBuilder();
                using (DispatcherRig rig = new DispatcherRig(false, dir))
                {
                    rig.Call("vault.create", P("password", "PASSWORD-XYZ-42")); responses.Append(rig.LastResponse);
                    rig.Call("secret.add", P("name", "leak_probe", "allowed_hosts", new[] { "a.example" }, "value", B64("TOPSECRET-123"))); responses.Append(rig.LastResponse);
                    rig.Call("secret.get", P("name", "leak_probe")); responses.Append(rig.LastResponse);
                    try { rig.Call("vault.unlock", P("password", "PASSWORD-XYZ-42")); } catch (RpcException) { }
                    responses.Append(rig.LastResponse);
                }
                string all = log.ToString() + responses;
                Check.True(log.ToString().Contains("admin secret.add id=7") && log.ToString().Contains("admin vault.create id=7"), "méthode et id logués");
                Check.True(!all.Contains("TOPSECRET-123") && !all.Contains(B64("TOPSECRET-123")), "aucune valeur dans les logs ni les réponses");
                Check.True(!all.Contains("PASSWORD-XYZ-42"), "aucun mot de passe dans les logs ni les réponses");
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }
    }
}
