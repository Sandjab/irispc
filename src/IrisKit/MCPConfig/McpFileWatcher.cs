using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// Observe un fichier (FileSystemWatcher sur son dossier, filtré sur son nom) et signale un changement après `debounce` sans
    /// nouvel événement (500 ms pour `mcp wrap --watch`, comme le FSEvents d'IRIS). Un changement survenu pendant le traitement du
    /// précédent n'est jamais perdu : il complète l'attente suivante.
    /// </summary>
    public sealed class McpFileWatcher : IDisposable
    {
        private readonly FileSystemWatcher watcher;
        private readonly Timer timer;
        private readonly TimeSpan debounce;
        private readonly object gate = new object();
        private TaskCompletionSource<bool> pending = new TaskCompletionSource<bool>();

        public McpFileWatcher(string path, TimeSpan debounce)
        {
            this.debounce = debounce;
            timer = new Timer(Fire, null, Timeout.Infinite, Timeout.Infinite);
            watcher = new FileSystemWatcher(Path.GetDirectoryName(path), Path.GetFileName(path));
            watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime;
            watcher.Changed += OnEvent;
            watcher.Created += OnEvent;
            watcher.Renamed += OnEvent;
            watcher.EnableRaisingEvents = true;
        }

        private void OnEvent(object sender, FileSystemEventArgs e)
        {
            lock (gate) timer.Change(debounce, Timeout.InfiniteTimeSpan);
        }

        private void Fire(object state)
        {
            // Le signal reste posé jusqu'à ce qu'une attente le consomme : un changement survenu pendant le traitement du
            // précédent, ou avant le premier WaitForChange, complète l'attente suivante (revue finale phase 5, I1).
            lock (gate) pending.TrySetResult(true);
        }

        /// <summary>
        /// Rend la main au prochain changement (après debounce), ou tout de suite si un changement est survenu depuis la dernière
        /// attente ; OperationCanceledException si `cancel` est déclenché.
        /// </summary>
        public void WaitForChange(CancellationToken cancel)
        {
            Task next;
            lock (gate) next = pending.Task;
            try { next.Wait(cancel); }
            catch (AggregateException ex) { throw ex.InnerException; }
            lock (gate)
                if (pending.Task.IsCompleted) pending = new TaskCompletionSource<bool>();
        }

        public void Dispose()
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
            timer.Dispose();
        }
    }
}
