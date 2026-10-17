using System;
using System.Security;

namespace Irisd
{
    /// <summary>Saisie du mot de passe maître. null = entrée fermée (EOF). Jamais loguée.</summary>
    public interface IConsoleInput
    {
        SecureString ReadPassword(string prompt);
    }

    /// <summary>Console réelle : saisie masquée (ReadKey) ; si l'entrée est redirigée, ReadLine avec avertissement unique.</summary>
    public sealed class ConsoleInput : IConsoleInput
    {
        private bool warnedRedirected;

        public SecureString ReadPassword(string prompt)
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
                string line = Console.In.ReadLine();
                if (line == null) return null;
                foreach (char c in line) s.AppendChar(c);
                s.MakeReadOnly();
                return s;
            }
            while (true)
            {
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
