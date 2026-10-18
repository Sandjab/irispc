using System;
using System.IO;
using System.Security;
using System.Threading;
using IrisKit;

namespace Irisd
{
    /// <summary>
    /// Invite console du mot de passe maître (spec socle §4.3, phase 3 §6, §9) : création avec confirmation si le coffre est absent,
    /// sinon déverrouillage ; trois échecs → code 2 ; délai anti-force brute attendu avant chaque essai (compteur partagé avec le pipe).
    /// Un déverrouillage par le pipe pendant la saisie annule l'invite ; Ctrl+C → code 0.
    /// </summary>
    internal sealed class ConsoleUnlock
    {
        private readonly VaultGate vault;
        private readonly IConsoleInput console;
        private readonly TextWriter stderr;

        public ConsoleUnlock(VaultGate vault, IConsoleInput console, TextWriter stderr)
        {
            this.vault = vault;
            this.console = console;
            this.stderr = stderr;
        }

        public int Run(CancellationToken cancel)
        {
            using (CancellationTokenSource prompt = CancellationTokenSource.CreateLinkedTokenSource(cancel))
            {
                Action opened = delegate
                {
                    try { prompt.Cancel(); }
                    catch (ObjectDisposedException) { }
                };
                vault.Opened += opened;
                try
                {
                    if (vault.State == VaultState.Unlocked) return ExitCodes.Ok;
                    return vault.State == VaultState.Absent ? Create(prompt.Token) : Unlock(prompt.Token);
                }
                catch (OperationCanceledException)
                {
                    if (cancel.IsCancellationRequested)
                    {
                        stderr.WriteLine("irisd : arrêt demandé pendant la saisie du mot de passe.");
                        return ExitCodes.Ok;
                    }
                    Log.Info("irisd", "coffre déverrouillé par le pipe admin : invite console abandonnée");
                    return ExitCodes.Ok;
                }
                finally { vault.Opened -= opened; }
            }
        }

        private int Create(CancellationToken token)
        {
            stderr.WriteLine("Aucun coffre dans " + vault.KdbxPath + " : création d'un nouveau coffre KeePass.");
            for (int attempt = 1; attempt <= Daemon.MaxPasswordAttempts; attempt++)
            {
                SecureString first = console.ReadPassword("Mot de passe maître du nouveau coffre : ", token);
                if (first == null) return Closed();
                if (first.Length == 0) { stderr.WriteLine("Le mot de passe ne peut pas être vide (" + attempt + "/" + Daemon.MaxPasswordAttempts + ")."); continue; }
                SecureString second = console.ReadPassword("Confirmez le mot de passe maître : ", token);
                if (second == null) return Closed();
                if (!SecureStrings.Equal(first, second)) { stderr.WriteLine("Les deux saisies ne correspondent pas (" + attempt + "/" + Daemon.MaxPasswordAttempts + ")."); continue; }
                try
                {
                    vault.Create(first);
                    return ExitCodes.Ok;
                }
                catch (VaultGateException ex)
                {
                    if (ex.Kind == VaultGateErrorKind.Exists && vault.State == VaultState.Unlocked) return ExitCodes.Ok; // créé entre-temps par le pipe
                    stderr.WriteLine("irisd : " + ex.Message);
                    return ExitCodes.Vault;
                }
                catch (SecretStoreException ex)
                {
                    stderr.WriteLine("irisd : création du coffre impossible : " + ex.Message);
                    return ExitCodes.Vault;
                }
            }
            stderr.WriteLine("Trois échecs : arrêt sans créer de coffre.");
            return ExitCodes.Vault;
        }

        private int Unlock(CancellationToken token)
        {
            for (int attempt = 1; attempt <= Daemon.MaxPasswordAttempts; attempt++)
            {
                WaitRetry(token);
                SecureString password = console.ReadPassword("Mot de passe maître (" + vault.KdbxPath + ") : ", token);
                if (password == null) return Closed();
                while (true)
                {
                    try
                    {
                        vault.Unlock(password);
                        return ExitCodes.Ok;
                    }
                    catch (VaultGateException ex)
                    {
                        if (ex.Kind == VaultGateErrorKind.RateLimited) { WaitRetry(token); continue; } // délai ouvert par le pipe : la tentative ne compte pas
                        if (ex.Kind == VaultGateErrorKind.BadPassword) { stderr.WriteLine("Mot de passe refusé (" + attempt + "/" + Daemon.MaxPasswordAttempts + ")."); break; }
                        stderr.WriteLine("irisd : " + ex.Message);
                        return ExitCodes.Vault;
                    }
                    catch (SecretStoreException ex)
                    {
                        stderr.WriteLine("irisd : " + ex.Message);
                        return ExitCodes.Vault;
                    }
                }
            }
            stderr.WriteLine("Trois échecs : arrêt.");
            return ExitCodes.Vault;
        }

        /// <summary>Attend la fin du délai anti-force brute (annulable) avant d'examiner une tentative.</summary>
        private void WaitRetry(CancellationToken token)
        {
            TimeSpan left = vault.RetryAfter;
            if (left <= TimeSpan.Zero) return;
            stderr.WriteLine("Nouvel essai possible dans " + (int)Math.Ceiling(left.TotalSeconds) + " s.");
            if (token.WaitHandle.WaitOne(left)) token.ThrowIfCancellationRequested();
        }

        private int Closed()
        {
            stderr.WriteLine("irisd : entrée fermée pendant la saisie du mot de passe, arrêt.");
            return ExitCodes.Vault;
        }
    }
}
