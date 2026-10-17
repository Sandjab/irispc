using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- RequestProcessor (sans réseau) ------------------------------------------

        private static int pauseCalls;

        private static RequestProcessor Processor(ISecretStore store, int maxPerMinute, ExfilPolicy policy)
        {
            pauseCalls = 0;
            return new RequestProcessor(store, delegate { return maxPerMinute; }, delegate { return policy; }, delegate { pauseCalls++; }, delegate { return T0; });
        }

        private static HttpRequestHead Req(string method, string target, params string[] pairs)
        {
            return new HttpRequestHead(method, target, "HTTP/1.1", H(pairs));
        }

        private static void Processor_SubstitutesStripsHopHeadersRecordsUsage()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_K");
            RequestProcessor p = Processor(store, 1, ExfilPolicy.BlockAndNotify);
            byte[] body = Bytes("{\"t\":1}");
            HttpRequestHead head = Req("POST", "/v1/messages?x=1", "Host", "example.com", "x-api-key", "{{kc:k}}", "Accept-Encoding", "gzip, br", "Proxy-Connection", "keep-alive", "Expect", "100-continue", "Content-Length", "7");
            ProcessedRequest r = Wait(p.ProcessAsync(head, body, false, "EXAMPLE.com:443", false));
            Check.Eq(RequestOutcome.Substituted, r.Outcome, "substitué");
            Check.Eq(EventKind.Substituted, r.EventKind, "event substituted");
            Check.Eq("VALUE_K", r.Head.Headers.First("x-api-key"), "valeur réelle dans l'en-tête sortant");
            Check.True(!r.Head.Headers.Contains("Accept-Encoding") && !r.Head.Headers.Contains("Proxy-Connection") && !r.Head.Headers.Contains("Expect"), "Accept-Encoding, Proxy-Connection et Expect retirés");
            Check.Eq("example.com", r.Head.Headers.First("Host"), "les autres en-têtes restent");
            Check.Eq("HTTP/1.1", r.Head.Version, "version forcée");
            Check.Eq("/v1/messages?x=1", r.Head.Target, "cible inchangée");
            Check.True(ReferenceEquals(r.Body, body), "corps inchangé (même tableau)");
            Check.Eq("7", r.Head.Headers.First("Content-Length"), "Content-Length inchangé quand le corps ne change pas");
            Check.Eq(EventFlags.None, r.Flags, "aucun drapeau");
            Check.Eq("k", string.Join(",", r.Substituted), "noms substitués");
            Wait(p.LastUsageRecording);
            Check.Eq(1L, Wait(store.SecretAsync("k")).UsageCount, "usage enregistré (détaché)");
            r = Wait(p.ProcessAsync(head, body, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Blocked && r.Alert.Rule == ExfilRule.VolumeAnomaly, "R5 compte la substitution précédente (seuil 1)");
            Check.Eq("{{kc:k}}", r.Head.Headers.First("x-api-key"), "bloqué = littéral transmis");
        }

        private static void Processor_BlockedAppliesPolicy()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_K");
            HttpRequestHead head = Req("POST", "/v1/messages", "Authorization", "Bearer {{kc:k}}");
            RequestProcessor p = Processor(store, 60, ExfilPolicy.BlockOnly);
            ProcessedRequest r = Wait(p.ProcessAsync(head, null, false, "evil.example", false));
            Check.True(r.Outcome == RequestOutcome.Blocked && r.EventKind == EventKind.ExfilBlocked, "R1 → exfilBlocked");
            Check.True(r.Alert.Rule == ExfilRule.HostMismatch && r.Alert.Severity == AlertSeverity.High && r.Alert.SecretName == "k" && r.Alert.Snippet.Contains("{{kc:k}}"), "alerte R1 avec snippet");
            Check.Eq("Bearer {{kc:k}}", r.Head.Headers.First("Authorization"), "placeholder littéral conservé");
            Check.Eq(0, r.Substituted.Count, "rien substitué");
            Check.Eq(0, pauseCalls, "block_only : pas de pause");
            p = Processor(store, 60, ExfilPolicy.BlockNotifyPause);
            r = Wait(p.ProcessAsync(head, null, false, "evil.example", false));
            Check.True(r.Outcome == RequestOutcome.Blocked && pauseCalls == 1, "block_notify_pause : pause demandée");
            p = Processor(store, 60, ExfilPolicy.BlockAndNotify);
            Wait(p.ProcessAsync(head, null, false, "evil.example", false));
            Check.Eq(0, pauseCalls, "block_and_notify : pas de pause (notification = lot app)");
        }

        private static void Processor_PausedBypasses()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_K");
            RequestProcessor p = Processor(store, 1, ExfilPolicy.BlockOnly);
            HttpRequestHead head = Req("POST", "/v1", "x-api-key", "{{kc:k}}", "Accept-Encoding", "gzip");
            ProcessedRequest r = Wait(p.ProcessAsync(head, null, false, "example.com", true));
            Check.Eq(RequestOutcome.Bypassed, r.Outcome, "en pause : contourné");
            Check.Eq(EventKind.NoMatch, r.EventKind, "spec socle : noMatch avec drapeau paused");
            Check.Eq(EventFlags.Paused, r.Flags, "drapeau paused");
            Check.Eq("{{kc:k}}", r.Head.Headers.First("x-api-key"), "placeholder intact");
            Check.True(!r.Head.Headers.Contains("Accept-Encoding"), "Accept-Encoding retiré même en pause");
            r = Wait(p.ProcessAsync(head, null, false, "example.com", false));
            Check.Eq(RequestOutcome.Substituted, r.Outcome, "hors pause, la pause n'a pas consommé le quota R5");
        }

        private static void Processor_FlagsBodyTooLargeNonUtf8Compressed()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_K");
            RequestProcessor p = Processor(store, 60, ExfilPolicy.BlockOnly);
            byte[] partial = Bytes("{{kc:k}} dans un corps trop grand");
            ProcessedRequest r = Wait(p.ProcessAsync(Req("POST", "/up", "x-api-key", "{{kc:k}}", "Content-Length", "99999999"), partial, true, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Substituted && r.Flags == EventFlags.BodyTooLarge, "corps trop grand : en-têtes scannés, drapeau bodyTooLarge");
            Check.True(ReferenceEquals(r.Body, partial) && r.Head.Headers.First("Content-Length") == "99999999", "corps et Content-Length intacts (relais streaming par l'appelant)");
            Check.Eq("VALUE_K", r.Head.Headers.First("x-api-key"), "en-tête substitué malgré le corps trop grand");
            byte[] binary = new byte[] { 0xFF, 0xFE, 0x7B, 0x7B, 0x6B, 0x63, 0x3A, 0x6B, 0x7D, 0x7D }; // 0xFF 0xFE puis "{{kc:k}}"
            r = Wait(p.ProcessAsync(Req("POST", "/up", "x-api-key", "{{kc:k}}", "Content-Length", "10"), binary, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Substituted && r.Flags == EventFlags.NonUtf8, "corps non UTF-8 : non scanné (pas de R2), drapeau nonUtf8");
            Check.True(ReferenceEquals(r.Body, binary), "corps binaire inchangé");
            byte[] gz = Bytes("{{kc:k}}");
            r = Wait(p.ProcessAsync(Req("POST", "/up", "Content-Encoding", "gzip", "Content-Length", "8"), gz, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.NoMatch && r.Flags == EventFlags.CompressedBody, "corps compressé : non scanné, drapeau compressedBody, noMatch");
            Check.True(ReferenceEquals(r.Body, gz), "corps compressé inchangé");
            r = Wait(p.ProcessAsync(Req("POST", "/up", "Content-Length", "8"), gz, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Blocked && r.Alert.Rule == ExfilRule.NonCanonicalLocation, "le même corps non compressé est scanné : R2");
        }

        private static void Processor_NoMatchUnknownAndContentLength()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_LONGER_THAN_PLACEHOLDER");
            RequestProcessor p = Processor(store, 60, ExfilPolicy.BlockOnly);
            ProcessedRequest r = Wait(p.ProcessAsync(Req("GET", "/plain", "Host", "example.com"), null, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.NoMatch && r.EventKind == EventKind.NoMatch && r.Flags == EventFlags.None && r.Substituted.Count == 0, "sans placeholder : noMatch");
            r = Wait(p.ProcessAsync(Req("GET", "/plain", "x-api-key", "{{kc:ghost}}"), null, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.NoMatch && string.Join(",", r.Unresolved) == "ghost" && r.Head.Headers.First("x-api-key") == "{{kc:ghost}}", "nom inconnu : noMatch, Unresolved, littéral");
            byte[] body = Bytes("{\"k\":\"{{kc:k}}\"}");
            r = Wait(p.ProcessAsync(Req("POST", "/v1", "x-api-key", "{{kc:k}}", "Content-Length", body.Length.ToString()), body, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Blocked, "corps connu → R2 (le corps n'est jamais substitué)");
            body = Bytes("{\"k\":\"{{kc:ghost}}\"}");
            r = Wait(p.ProcessAsync(Req("POST", "/v1", "x-api-key", "{{kc:k}}", "Content-Length", body.Length.ToString()), body, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Substituted && ReferenceEquals(r.Body, body), "inconnu dans le corps : ignoré, corps inchangé");
            Check.Eq(body.Length.ToString(), r.Head.Headers.First("Content-Length"), "Content-Length inchangé");
        }
    }
}
