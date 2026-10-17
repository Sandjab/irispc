namespace IrisKit
{
    /// <summary>Persistance du matériel CA : coffre KeePass en production, mémoire pour les tests et `--in-memory-ca`.</summary>
    public interface ICAKeyStore
    {
        /// <summary>null si aucun CA n'est stocké.</summary>
        CAMaterial Load();
        void Store(CAMaterial material);
    }

    public sealed class InMemoryCAKeyStore : ICAKeyStore
    {
        private CAMaterial material;
        public CAMaterial Load() { return material; }
        public void Store(CAMaterial m) { material = m; }
    }

    /// <summary>Entrée `root` du groupe `ca` de iris.kdbx (spec §4.1) ; clé privée en champ protégé.</summary>
    public sealed class KeePassCAKeyStore : ICAKeyStore
    {
        private readonly KeePassVault vault;
        public KeePassCAKeyStore(KeePassVault vault) { this.vault = vault; }
        public CAMaterial Load() { return vault.ReadCA(); }
        public void Store(CAMaterial m) { vault.WriteCA(m); }
    }
}
