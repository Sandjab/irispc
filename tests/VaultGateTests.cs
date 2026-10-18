using System;
using System.IO;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- VaultGate (spec phase 3 §3, §6) ---------------------------------------

        private static Func<KeePassVault, ICAKeyStore> VaultCA()
        {
            return delegate(KeePassVault v) { return new KeePassCAKeyStore(v); };
        }

        private static void VaultGate_AbsentCreateThenUnlock()
        {
            string dir = TestDir.Create();
            DateTime now = T0;
            Func<DateTime> clock = delegate { return now; };
            try
            {
                int opened = 0;
                using (VaultGate g = new VaultGate(dir, VaultCA(), clock))
                {
                    g.Opened += delegate { opened++; };
                    Check.Eq(VaultState.Absent, g.State, "pas de coffre → Absent");
                    Check.True(g.Secrets == null && g.CA == null, "rien n'est exposé porte fermée");
                    Check.Eq(Path.Combine(dir, "iris.kdbx"), g.KdbxPath, "chemin du coffre");
                    Check.Eq(VaultGateErrorKind.Absent, Check.Throws<VaultGateException>(delegate { g.Unlock(Secure("x")); }, "unlock sans coffre").Kind, "Absent");
                    g.Create(Secure("maître-é"));
                    Check.True(g.State == VaultState.Unlocked && opened == 1 && g.Secrets != null && g.CA != null, "créé, ouvert, Opened levé une fois");
                    Check.True(File.Exists(Path.Combine(dir, "ca.pem")), "ca.pem exporté");
                    Check.Eq(VaultGateErrorKind.Exists, Check.Throws<VaultGateException>(delegate { g.Create(Secure("y")); }, "second create").Kind, "Exists");
                    Wait(g.Secrets.AddAsync("probe", Bytes("valeur"), new[] { "api.example.com" }, T0));
                }
                using (VaultGate g = new VaultGate(dir, VaultCA(), clock))
                {
                    g.Opened += delegate { opened++; };
                    Check.Eq(VaultState.Locked, g.State, "coffre présent → Locked");
                    VaultGateException bad = Check.Throws<VaultGateException>(delegate { g.Unlock(Secure("mauvais")); }, "mauvais mot de passe");
                    Check.True(bad.Kind == VaultGateErrorKind.BadPassword && bad.RetryAfter == TimeSpan.FromSeconds(1), "BadPassword, 1 s");
                    Check.True(!bad.Message.Contains("mauvais"), "le message ne contient pas le mot de passe");
                    VaultGateException wait = Check.Throws<VaultGateException>(delegate { g.Unlock(Secure("maître-é")); }, "pendant le délai");
                    Check.True(wait.Kind == VaultGateErrorKind.RateLimited && wait.RetryAfter == TimeSpan.FromSeconds(1), "RateLimited sans examiner le mot de passe");
                    Check.Eq(TimeSpan.FromSeconds(1), g.RetryAfter, "RetryAfter");
                    now = now.AddSeconds(1);
                    g.Unlock(Secure("maître-é"));
                    Check.True(g.State == VaultState.Unlocked && opened == 2, "ouvert après le délai");
                    Check.Eq("valeur", System.Text.Encoding.UTF8.GetString(Wait(g.Secrets.ValueAsync("probe"))), "secret relu");
                    g.Unlock(Secure("n'importe quoi"));
                    Check.True(opened == 2 && g.RetryAfter == TimeSpan.Zero, "déjà ouvert : pas d'oracle, pas d'échec compté");
                    g.MaxBackups = 3;
                    Check.Eq(3, g.MaxBackups, "MaxBackups transmis");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void VaultGate_DelayDoublesAndCaps()
        {
            Check.Eq(TimeSpan.FromSeconds(1), VaultGate.DelayAfter(1), "1 échec → 1 s");
            Check.Eq(TimeSpan.FromSeconds(2), VaultGate.DelayAfter(2), "2 → 2 s");
            Check.Eq(TimeSpan.FromSeconds(4), VaultGate.DelayAfter(3), "3 → 4 s");
            Check.Eq(TimeSpan.FromSeconds(32), VaultGate.DelayAfter(6), "6 → 32 s");
            Check.Eq(TimeSpan.FromSeconds(60), VaultGate.DelayAfter(7), "7 → plafond 60 s");
            Check.Eq(TimeSpan.FromSeconds(60), VaultGate.DelayAfter(40), "40 → 60 s");
            string dir = TestDir.Create();
            DateTime now = T0;
            try
            {
                using (VaultGate g = new VaultGate(dir, VaultCA(), delegate { return now; })) g.Create(Secure("bon"));
                using (VaultGate g = new VaultGate(dir, VaultCA(), delegate { return now; }))
                {
                    for (int i = 1; i <= 3; i++)
                    {
                        VaultGateException e = Check.Throws<VaultGateException>(delegate { g.Unlock(Secure("faux")); }, "échec " + i);
                        Check.Eq(VaultGate.DelayAfter(i), e.RetryAfter, "délai après l'échec " + i);
                        now = now + e.RetryAfter;
                    }
                    g.Unlock(Secure("bon"));
                    Check.Eq(VaultState.Unlocked, g.State, "succès après trois échecs");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void VaultGate_ConcurrentWrongAttempts()
        {
            string dir = TestDir.Create();
            DateTime now = T0;
            try
            {
                using (VaultGate g = new VaultGate(dir, VaultCA(), delegate { return now; })) g.Create(Secure("bon"));
                using (VaultGate g = new VaultGate(dir, VaultCA(), delegate { return now; }))
                {
                    Func<VaultGateErrorKind> attempt = delegate
                    {
                        try { g.Unlock(Secure("faux")); return (VaultGateErrorKind)(-1); }
                        catch (VaultGateException ex) { return ex.Kind; }
                    };
                    Task<VaultGateErrorKind> a = Task.Run(attempt);
                    Task<VaultGateErrorKind> b = Task.Run(attempt);
                    VaultGateErrorKind ka = Wait(a), kb = Wait(b);
                    Check.True((ka == VaultGateErrorKind.BadPassword && kb == VaultGateErrorKind.RateLimited)
                        || (kb == VaultGateErrorKind.BadPassword && ka == VaultGateErrorKind.RateLimited),
                        "une seule tentative examinée, l'autre attend le verrou puis tombe dans le délai : " + ka + "/" + kb);
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void VaultGate_CAFailureStaysLocked()
        {
            string dir = TestDir.Create();
            try
            {
                int opened = 0;
                Func<KeePassVault, ICAKeyStore> broken = delegate(KeePassVault v)
                {
                    throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "CA illisible (test)");
                };
                using (VaultGate g = new VaultGate(dir, broken, delegate { return T0; }))
                {
                    g.Opened += delegate { opened++; };
                    Check.Throws<SecretStoreException>(delegate { g.Create(Secure("bon")); }, "échec du CA à la création");
                    Check.True(g.State == VaultState.Locked && g.Secrets == null && g.CA == null && opened == 0, "coffre créé mais porte fermée, Opened non levé");
                    Check.Throws<SecretStoreException>(delegate { g.Unlock(Secure("bon")); }, "échec du CA au déverrouillage");
                    Check.True(g.State == VaultState.Locked && g.RetryAfter == TimeSpan.Zero, "un échec du CA n'est pas un mauvais mot de passe");
                }
                using (VaultGate g = new VaultGate(dir, VaultCA(), delegate { return T0; }))
                {
                    g.Unlock(Secure("bon"));
                    Check.Eq(VaultState.Unlocked, g.State, "le coffre n'a pas été abîmé");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void VaultGate_InMemory()
        {
            string dir = TestDir.Create();
            try
            {
                InMemorySecretStore store = new InMemorySecretStore();
                using (VaultGate g = VaultGate.InMemory(dir, store, delegate { return T0; }))
                {
                    Check.True(g.State == VaultState.Unlocked && g.KdbxPath == null && g.CA != null && g.Secrets != null, "ouverte d'emblée, sans coffre");
                    Check.True(File.Exists(Path.Combine(dir, "ca.pem")), "CA éphémère exporté");
                    g.Unlock(Secure("x"));
                    Check.Eq(VaultGateErrorKind.Exists, Check.Throws<VaultGateException>(delegate { g.Create(Secure("x")); }, "create en mémoire").Kind, "Exists");
                    Check.True(!File.Exists(Path.Combine(dir, "iris.kdbx")), "aucun coffre créé");
                }
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
