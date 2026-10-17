using System;
using System.Security;
using System.Threading;
using System.Threading.Tasks;

namespace Irisd
{
    /// <summary>Saisie du mot de passe maître. null = entrée fermée (EOF) ; Ctrl+C = OperationCanceledException. Jamais loguée.</summary>
    public interface IConsoleInput
    {
        SecureString ReadPassword(string prompt, CancellationToken cancel);
    }

    /// <summary>
    /// Console réelle : saisie masquée (ReadKey) en surveillant l'annulation entre deux touches ; si l'entrée est redirigée,
    /// ReadLine avec avertissement unique. Revue phase 1, mineur 4 : Ctrl+C interrompt l'invite.
    /// </summary>
    public sealed class ConsoleInput : IConsoleInput
    {
        private bool warnedRedirected;

        public SecureString ReadPassword(string prompt, CancellationToken cancel)
        {
            Console.Error.Write(prompt);
            SecureString s = new SecureString();
            if (Console.IsInputRedirected)
            {
                if (!warnedRedirected)
                {
                    Console.Error.WriteLine();
                    Console.Error.WriteLine("(entrée redirigée : la saisie ne peut pas être masquée)");
                    warnedRedirected = true;
                }
                Task<string> line = Console.In.ReadLineAsync();
                int which = WaitHandle.WaitAny(new[] { ((IAsyncResult)line).AsyncWaitHandle, cancel.WaitHandle });
                if (which == 1) { Console.Error.WriteLine(); throw new OperationCanceledException(cancel); }
                string text;
                try { text = line.GetAwaiter().GetResult(); }
                catch (System.IO.IOException) { return null; }
                if (text == null) return null;
                foreach (char c in text) s.AppendChar(c);
                s.MakeReadOnly();
                return s;
            }
            while (true)
            {
                while (!Console.KeyAvailable)
                {
                    if (cancel.WaitHandle.WaitOne(50)) { Console.Error.WriteLine(); throw new OperationCanceledException(cancel); }
                }
                ConsoleKeyInfo key;
                try { key = Console.ReadKey(true); }
                catch (InvalidOperationException) { return null; }
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace) { if (s.Length > 0) s.RemoveAt(s.Length - 1); continue; }
                if (key.KeyChar != '\0') s.AppendChar(key.KeyChar);
            }
            Console.Error.WriteLine();
            s.MakeReadOnly();
            return s;
        }
    }
}
