using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace IrisKit
{
    /// <summary>Le pipe existe déjà (un autre irisd de cet utilisateur, ou un usurpateur) : irisd sort avec le code 3.</summary>
    public sealed class AdminPipeInUseException : Exception
    {
        public string PipeName { get; private set; }

        public AdminPipeInUseException(string pipeName)
            : base("le pipe \\\\.\\pipe\\" + pipeName + " existe déjà : un autre irisd tourne pour cet utilisateur, ou un autre programme l'a créé")
        {
            PipeName = pipeName;
        }
    }

    /// <summary>ACL du pipe admin (spec phase 3 §4) : contrôle total pour l'utilisateur courant seul, refus explicite du SID NETWORK, héritage coupé.</summary>
    public static class AdminPipeSecurity
    {
        public static PipeSecurity Create()
        {
            SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
            PipeSecurity ps = new PipeSecurity();
            ps.SetAccessRuleProtection(true, false);
            ps.SetOwner(user);
            ps.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
            return ps;
        }
    }

    /// <summary>Win32 que System.IO.Pipes n'expose pas en .NET Framework 4.8 : FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_REJECT_REMOTE_CLIENTS, PID du serveur.</summary>
    internal static class PipeNative
    {
        private const uint PIPE_ACCESS_DUPLEX = 0x00000003;
        private const uint FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        private const uint PIPE_TYPE_BYTE = 0x00000000;
        private const uint PIPE_READMODE_BYTE = 0x00000000;
        private const uint PIPE_WAIT = 0x00000000;
        private const uint PIPE_REJECT_REMOTE_CLIENTS = 0x00000008;
        private const int ERROR_ACCESS_DENIED = 5;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances,
            uint outBufferSize, uint inBufferSize, uint defaultTimeout, ref SECURITY_ATTRIBUTES securityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        /// <summary>
        /// Instance serveur asynchrone, mode octet, clients distants refusés, ACL `security`. `first` : échec si le pipe existe déjà
        /// (AdminPipeInUseException). Rend un NamedPipeServerStream non connecté.
        /// </summary>
        public static NamedPipeServerStream CreateServer(string pipeName, bool first, int maxInstances, PipeSecurity security)
        {
            byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
            GCHandle pin = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
            try
            {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = pin.AddrOfPinnedObject();
                sa.bInheritHandle = 0;
                uint openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0u);
                uint pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
                IntPtr raw = CreateNamedPipe(@"\\.\pipe\" + pipeName, openMode, pipeMode, (uint)maxInstances, 65536, 65536, 0, ref sa);
                if (raw == InvalidHandle || raw == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (first && error == ERROR_ACCESS_DENIED) throw new AdminPipeInUseException(pipeName);
                    throw new IOException("création du pipe \\\\.\\pipe\\" + pipeName + " impossible : " + new Win32Exception(error).Message);
                }
                return new NamedPipeServerStream(PipeDirection.InOut, true, false, new SafePipeHandle(raw, true));
            }
            finally { pin.Free(); }
        }

        /// <summary>Chemin complet de l'exécutable du processus serveur d'un pipe client connecté.</summary>
        public static string ServerImagePath(NamedPipeClientStream client)
        {
            uint pid;
            if (!GetNamedPipeServerProcessId(client.SafePipeHandle, out pid))
                throw new IOException("PID du serveur du pipe illisible : " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
            IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (process == IntPtr.Zero)
                throw new IOException("processus serveur du pipe inaccessible (PID " + pid + ") : " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
            try
            {
                StringBuilder name = new StringBuilder(32768);
                uint size = (uint)name.Capacity;
                if (!QueryFullProcessImageName(process, 0, name, ref size))
                    throw new IOException("exécutable du serveur du pipe illisible : " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return name.ToString(0, (int)size);
            }
            finally { CloseHandle(process); }
        }
    }
}
