using System;
using System.Collections.Generic;

namespace Iris.Tests
{
    /// <summary>Échec d'une vérification : le message décrit l'écart.</summary>
    public sealed class CheckException : Exception
    {
        public CheckException(string message) : base(message) { }
    }

    /// <summary>
    /// Assertions maison, sans framework : chaque vérification incrémente Checks,
    /// chaque test en échec est listé dans Failures, Summary() rend 0 ou 1.
    /// </summary>
    public static class Check
    {
        public static int Checks;
        public static int Passed;
        public static readonly List<string> Failures = new List<string>();

        public static void True(bool condition, string what)
        {
            Checks++;
            if (!condition) throw new CheckException(what);
        }

        public static void Eq<T>(T expected, T actual, string what)
        {
            Checks++;
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
                throw new CheckException(what + " : attendu <" + Show(expected) + ">, obtenu <" + Show(actual) + ">");
        }

        /// <summary>Vérifie qu'une exception du type attendu est levée et la rend pour inspection.</summary>
        public static TException Throws<TException>(Action action, string what) where TException : Exception
        {
            Checks++;
            try
            {
                action();
            }
            catch (TException ex)
            {
                return ex;
            }
            catch (Exception ex)
            {
                throw new CheckException(what + " : " + ex.GetType().Name + " levée au lieu de "
                    + typeof(TException).Name + " (" + ex.Message + ")");
            }
            throw new CheckException(what + " : aucune exception, " + typeof(TException).Name + " attendue");
        }

        public static void Run(string name, Action test)
        {
            try
            {
                test();
                Passed++;
                Console.WriteLine("  OK   " + name);
            }
            catch (Exception ex)
            {
                Failures.Add(name + " : " + ex.Message);
                Console.WriteLine("  FAIL " + name);
                Console.WriteLine("       " + ex.Message);
            }
        }

        public static int Summary()
        {
            Console.WriteLine();
            Console.WriteLine("{0} test(s) réussi(s), {1} échec(s), {2} vérification(s)", Passed, Failures.Count, Checks);
            foreach (string failure in Failures) Console.WriteLine("  - " + failure);
            return Failures.Count == 0 ? 0 : 1;
        }

        private static string Show(object value)
        {
            return value == null ? "null" : value.ToString();
        }
    }
}
