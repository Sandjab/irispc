using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// ISecretStore de production (spec §4.4) : identité et valeurs dans KeePassVault, usage et quarantaine
    /// dans SecretsMetaStore (jamais de réécriture du kdbx sur le chemin chaud).
    /// </summary>
    public sealed class KeePassSecretStore : ISecretStore
    {
        private readonly KeePassVault vault;
        private readonly SecretsMetaStore meta;

        public KeePassSecretStore(KeePassVault vault, SecretsMetaStore meta)
        {
            if (vault == null) throw new ArgumentNullException("vault");
            if (meta == null) throw new ArgumentNullException("meta");
            this.vault = vault;
            this.meta = meta;
        }

        private Secret Compose(VaultSecretEntry e)
        {
            SecretMeta m = meta.Get(e.Name);
            return new Secret(e.Name, e.AllowedHosts, e.CreatedAt, m.LastUsedAt, m.UsageCount, m.Quarantined);
        }

        private Secret Require(string name)
        {
            VaultSecretEntry e = vault.FindSecret(name);
            if (e == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
            return Compose(e);
        }

        public Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt)
        {
            Secret.ValidateName(name);
            IList<string> hosts = InMemorySecretStore.NormalizeHosts(allowedHosts);
            vault.AddSecret(name, value, hosts, createdAt);
            meta.Remove(name);
            return Task.FromResult(Require(name));
        }

        public Task<Secret> UpdateAsync(string name, IList<string> allowedHosts)
        {
            IList<string> hosts = InMemorySecretStore.NormalizeHosts(allowedHosts);
            Require(name);
            vault.SetAllowedHosts(name, hosts);
            return Task.FromResult(Require(name));
        }

        public Task<Secret> RotateAsync(string name, byte[] newValue)
        {
            Require(name);
            vault.SetValue(name, newValue);
            return Task.FromResult(Require(name));
        }

        public Task DeleteAsync(string name)
        {
            Require(name);
            vault.DeleteSecret(name);
            meta.Remove(name);
            return Task.FromResult(0);
        }

        public Task<byte[]> ValueAsync(string name)
        {
            byte[] value = vault.ReadValue(name);
            if (value == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
            return Task.FromResult(value);
        }

        public Task<Secret> SecretAsync(string name) { return Task.FromResult(Require(name)); }

        public Task<IList<Secret>> ListAsync()
        {
            List<Secret> list = new List<Secret>();
            foreach (VaultSecretEntry e in vault.ListSecrets()) list.Add(Compose(e));
            return Task.FromResult((IList<Secret>)list);
        }

        public Task<Secret> RecordUsageAsync(string name, DateTime at)
        {
            Require(name);
            meta.RecordUsage(name, at);
            return Task.FromResult(Require(name));
        }

        public Task<Secret> SetQuarantinedAsync(string name, bool quarantined)
        {
            Require(name);
            meta.SetQuarantined(name, quarantined);
            return Task.FromResult(Require(name));
        }
    }
}
