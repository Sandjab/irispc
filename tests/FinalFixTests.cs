using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Corrections de la revue finale de la phase 3 ------------------------------

        /// <summary>
        /// events.query lit le journal pendant que le proxy émet : la lecture d'un gros fichier JSONL ne doit pas
        /// bloquer Append (donc EventPipeline.Emit sur le chemin du proxy) pendant toute la durée du parsing.
        /// </summary>
        private static void Final_JournalReadDoesNotBlockAppend()
        {
            string dir = TestDir.Create();
            try
            {
                DateTime now = T0.AddHours(1);
                using (JsonlEventStore store = new JsonlEventStore(Path.Combine(dir, "events"), 7, delegate { return now; }))
                {
                    string line = Json.EmitCompact(IpcEvent(EventKind.NoMatch, "bulk.example", now).ToJson());
                    StringBuilder bulk = new StringBuilder();
                    for (int i = 0; i < 30000; i++) bulk.Append(line).Append('\n');
                    File.WriteAllText(Path.Combine(store.Directory, JsonlEventStore.FileNameFor(now)), bulk.ToString(), new UTF8Encoding(false));

                    Stopwatch one = Stopwatch.StartNew();
                    int count = store.Read(now).Count;
                    one.Stop();
                    Check.Eq(30000, count, "journal relu en entier");
                    Check.True(one.ElapsedMilliseconds >= 150, "lecture assez longue pour que le test soit probant (" + one.ElapsedMilliseconds + " ms)");

                    bool reading = true;
                    Task reader = Task.Run(delegate { while (Volatile.Read(ref reading)) store.Read(now); });
                    long worst = 0;
                    try
                    {
                        Thread.Sleep(50);
                        for (int i = 0; i < 20; i++)
                        {
                            Stopwatch w = Stopwatch.StartNew();
                            store.Append(IpcEvent(EventKind.Substituted, "live-" + i + ".example", now));
                            worst = Math.Max(worst, w.ElapsedMilliseconds);
                            Thread.Sleep(20);
                        }
                    }
                    finally { Volatile.Write(ref reading, false); Wait(reader); }
                    Check.True(worst < one.ElapsedMilliseconds / 2, "Append jamais bloqué par une lecture du journal (pire " + worst + " ms, lecture " + one.ElapsedMilliseconds + " ms)");
                    Check.Eq(30020, store.Read(now).Count, "les events écrits pendant les lectures sont tous là");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        /// <summary>Une trame JSON illisible ne renvoie jamais de fragment de la requête (un mot de passe mal cité par exemple).</summary>
        private static void Final_ParseErrorNeverEchoesPayload()
        {
            using (DispatcherRig rig = new DispatcherRig(true, null))
            {
                string raw = Encoding.UTF8.GetString(Wait(rig.Dispatcher.HandleAsync(Bytes("{\"jsonrpc\":\"2.0\",\"method\":\"vault.unlock\",\"params\":{\"password\":Hunter2Secret},\"id\":1}"))));
                Check.True(raw.Contains("-32700"), "-32700 : " + raw);
                Check.True(!raw.Contains("Hunter2Secret"), "aucun fragment de la requête dans l'erreur : " + raw);
                object id;
                RpcException e = Check.Throws<RpcException>(delegate { JsonRpc.ParseRequest(Bytes("{\"x\":Hunter2Secret}"), out id); }, "JSON illisible");
                Check.True(!e.Message.Contains("Hunter2Secret"), "message sans fragment : " + e.Message);
            }
        }

        /// <summary>Un échec de création d'une instance du pipe ne tue pas le serveur : il réessaie et sert le client suivant.</summary>
        private static void Final_AdminPipeSurvivesInstanceFailure()
        {
            string name = TestPipeName();
            int faults = 1;
            using (AdminServer server = new AdminServer(name, new EchoHandler().Handle))
            {
                server.RetryDelay = TimeSpan.FromMilliseconds(50);
                server.InstanceFault = delegate(bool first)
                {
                    if (first) return null;
                    return Interlocked.Decrement(ref faults) >= 0 ? new IOException("échec injecté (test)") : null;
                };
                server.Start();
                using (AdminClient a = AdminClient.Connect(name, SelfPath(), TimeSpan.FromSeconds(5)))
                    Check.True(a.Call("ping", null) != null, "premier client servi");
                using (AdminClient b = AdminClient.Connect(name, SelfPath(), TimeSpan.FromSeconds(5)))
                    Check.True(b.Call("ping", null) != null, "client suivant servi après l'échec de création d'instance");
            }
        }
    }
}
