namespace Irisd
{
    /// <summary>Codes de sortie de irisd (spec §7).</summary>
    public static class ExitCodes
    {
        public const int Ok = 0;
        public const int Data = 1;       // données ou config (et aide sans --foreground)
        public const int Vault = 2;      // coffre : mot de passe refusé trois fois, base illisible
        public const int Port = 3;       // port occupé (phase 2)
        public const int Arguments = 4;  // ligne de commande invalide
    }
}
