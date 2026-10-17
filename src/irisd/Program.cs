using System;
using System.Text;
using System.Threading;

namespace Irisd
{
    /// <summary>Main réel : encodage UTF-8, Ctrl+C → annulation coopérative, tout le reste dans Entry.Run.</summary>
    public static class Program
    {
        public static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            CancellationTokenSource cts = new CancellationTokenSource();
            Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
                cts.Cancel();
            };
            return Entry.Run(args, Console.Out, Console.Error, new ConsoleInput(), cts.Token);
        }
    }
}
