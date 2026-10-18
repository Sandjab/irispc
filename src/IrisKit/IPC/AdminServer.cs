using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// Serveur du pipe admin (spec phase 3 §4) : instances asynchrones (16 au plus), une requête à la fois par connexion,
    /// trame > 1 Mio = fermeture sans réponse, tampon de chaque trame effacé après traitement. Le traitement est délégué
    /// à `handler` (AdminDispatcher.HandleAsync en production), qui ne doit pas lever.
    /// </summary>
    public sealed class AdminServer : IDisposable
    {
        public const int MaxInstances = 16;

        private readonly string pipeName;
        private readonly Func<byte[], Task<byte[]>> handler;
        private readonly PipeSecurity security;
        private readonly SemaphoreSlim slots = new SemaphoreSlim(MaxInstances, MaxInstances);
        private readonly object gate = new object();
        private readonly HashSet<NamedPipeServerStream> open = new HashSet<NamedPipeServerStream>();
        private readonly List<Task> tasks = new List<Task>();
        private CancellationTokenSource stopping;
        private Task acceptLoop;
        private bool stopped;

        public string PipeName { get { return pipeName; } }

        public AdminServer(string pipeName, Func<byte[], Task<byte[]>> handler)
        {
            if (string.IsNullOrEmpty(pipeName)) throw new ArgumentException("nom de pipe vide", "pipeName");
            if (handler == null) throw new ArgumentNullException("handler");
            this.pipeName = pipeName;
            this.handler = handler;
            security = AdminPipeSecurity.Create();
        }

        /// <summary>Crée la première instance (AdminPipeInUseException si le pipe existe déjà) puis lance la boucle d'acceptation.</summary>
        public void Start()
        {
            if (stopping != null) throw new InvalidOperationException("serveur du pipe déjà démarré");
            slots.Wait();
            NamedPipeServerStream first;
            try { first = PipeNative.CreateServer(pipeName, true, MaxInstances, security); }
            catch { slots.Release(); throw; }
            stopping = new CancellationTokenSource();
            acceptLoop = AcceptLoopAsync(first, stopping.Token);
            Log.Info("ipc", "pipe admin à l'écoute : \\\\.\\pipe\\" + pipeName);
        }

        private async Task AcceptLoopAsync(NamedPipeServerStream listening, CancellationToken cancel)
        {
            while (true)
            {
                if (!Track(listening))
                {
                    // Stop est passé entre la création de l'instance et son suivi : elle ne doit pas lui survivre
                    try { listening.Dispose(); }
                    catch (IOException) { }
                    slots.Release();
                    return;
                }
                Exception waitError = null;
                try { await Task.Factory.FromAsync(listening.BeginWaitForConnection, listening.EndWaitForConnection, null).ConfigureAwait(false); }
                catch (Exception ex) { waitError = ex; }
                if (cancel.IsCancellationRequested) { Release(listening); return; }
                if (waitError == null)
                {
                    Task t = ServeAsync(listening, cancel);
                    lock (gate) { tasks.Add(t); tasks.RemoveAll(delegate(Task x) { return x.IsCompleted; }); }
                }
                else
                {
                    Release(listening);
                    if (!(waitError is IOException))
                    {
                        Log.Error("ipc", "pipe admin arrêté : " + waitError.GetType().Name + " : " + waitError.Message);
                        return;
                    }
                    // client parti avant l'acceptation : instance jetée, on en crée une autre
                }
                try { await slots.WaitAsync(cancel).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                try { listening = PipeNative.CreateServer(pipeName, false, MaxInstances, security); }
                catch (IOException ex)
                {
                    slots.Release();
                    Log.Error("ipc", "nouvelle instance du pipe admin impossible : " + ex.Message);
                    return;
                }
            }
        }

        private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancel)
        {
            try
            {
                while (!cancel.IsCancellationRequested)
                {
                    byte[] request;
                    try { request = await FrameCodec.ReadAsync(pipe, FrameCodec.MaxRequestBytes, cancel).ConfigureAwait(false); }
                    catch (FrameTooLargeException ex)
                    {
                        Log.Warn("ipc", "trame refusée sur le pipe admin : " + ex.Message + " ; connexion fermée");
                        return;
                    }
                    if (request == null) return;
                    byte[] response;
                    try { response = await handler(request).ConfigureAwait(false); }
                    finally { Array.Clear(request, 0, request.Length); }
                    await FrameCodec.WriteAsync(pipe, response, cancel).ConfigureAwait(false);
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Log.Error("ipc", "erreur inattendue sur le pipe admin : " + ex.GetType().Name + " : " + ex.Message); }
            finally { Release(pipe); }
        }

        /// <summary>Suit une instance pour que Stop la ferme ; faux si Stop a déjà photographié les instances.</summary>
        private bool Track(NamedPipeServerStream pipe)
        {
            lock (gate)
            {
                if (stopped) return false;
                open.Add(pipe);
                return true;
            }
        }

        /// <summary>Ferme une instance et rend son créneau (une seule fois par instance suivie).</summary>
        private void Release(NamedPipeServerStream pipe)
        {
            bool removed;
            lock (gate) { removed = open.Remove(pipe); }
            try { pipe.Dispose(); }
            catch (IOException) { }
            if (removed) slots.Release();
        }

        /// <summary>Ferme toutes les instances (connexions en cours abandonnées) et attend la fin des tâches, 2 s au plus.</summary>
        public void Stop()
        {
            if (stopping == null) return;
            List<NamedPipeServerStream> snapshot;
            List<Task> pending;
            lock (gate)
            {
                if (stopped) return;
                stopped = true; // sous le verrou : Track refuse toute instance créée après la photographie
                snapshot = new List<NamedPipeServerStream>(open);
                pending = new List<Task>(tasks);
            }
            stopping.Cancel();
            foreach (NamedPipeServerStream pipe in snapshot)
            {
                try { pipe.Dispose(); }
                catch (IOException) { }
            }
            try { Task.WaitAll(pending.ToArray(), TimeSpan.FromSeconds(2)); }
            catch (AggregateException) { }
            try { acceptLoop.Wait(TimeSpan.FromSeconds(2)); }
            catch (AggregateException) { }
            Log.Info("ipc", "pipe admin fermé");
        }

        public void Dispose() { Stop(); }
    }
}
