using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IrisKit
{
    public enum SecretStoreErrorKind
    {
        InvalidName,
        InvalidAllowedHosts,
        UnknownSecret,
        Duplicate,
        VaultLocked,
        VaultBusy,
        DataCorruption
    }

    /// <summary>Erreur typée du coffre (spec §4.4). Message en français ; ne contient jamais une valeur.</summary>
    public sealed class SecretStoreException : Exception
    {
        public SecretStoreErrorKind Kind { get; private set; }
        public string Name { get; private set; }

        public SecretStoreException(SecretStoreErrorKind kind, string name, string message) : base(message)
        {
            Kind = kind;
            Name = name;
        }

        public SecretStoreException(SecretStoreErrorKind kind, string name, string message, Exception inner) : base(message, inner)
        {
            Kind = kind;
            Name = name;
        }
    }

    /// <summary>Accès aux secrets (spec §4.4). La valeur n'est jamais loguée ni mise dans un Event.</summary>
    public interface ISecretStore
    {
        Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt);
        Task<Secret> UpdateAsync(string name, IList<string> allowedHosts);
        Task<Secret> RotateAsync(string name, byte[] newValue);
        Task DeleteAsync(string name);
        Task<byte[]> ValueAsync(string name);
        Task<Secret> SecretAsync(string name);
        Task<IList<Secret>> ListAsync();
        Task<Secret> RecordUsageAsync(string name, DateTime at);
        Task<Secret> SetQuarantinedAsync(string name, bool quarantined);
    }
}
