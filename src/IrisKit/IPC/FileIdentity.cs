using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace IrisKit
{
    /// <summary>
    /// Identité d'un fichier : numéro de série du volume + index de fichier (GetFileInformationByHandle). Deux chemins qui mènent
    /// au même fichier (subst, jonction, nom court 8.3, casse, lien physique) ont la même identité (spec phase 5 §8).
    /// </summary>
    public sealed class FileIdentity : IEquatable<FileIdentity>
    {
        private const uint FILE_SHARE_ALL = 0x00000007; // lecture | écriture | suppression
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out BY_HANDLE_FILE_INFORMATION info);

        public uint VolumeSerial { get; private set; }
        public ulong FileIndex { get; private set; }

        private FileIdentity(uint volumeSerial, ulong fileIndex)
        {
            VolumeSerial = volumeSerial;
            FileIndex = fileIndex;
        }

        /// <summary>Identité de `path` ; IOException si le fichier ne peut pas être ouvert (absent, chemin invalide, accès refusé).</summary>
        public static FileIdentity Of(string path)
        {
            if (string.IsNullOrEmpty(path)) throw new IOException("chemin vide");
            // Accès 0 et partage total : n'interfère ni avec un exécutable en cours ni avec un fichier ouvert en écriture.
            using (SafeFileHandle h = CreateFile(path, 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero))
            {
                if (h.IsInvalid)
                    throw new IOException("ouverture de " + path + " impossible : " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                BY_HANDLE_FILE_INFORMATION info;
                if (!GetFileInformationByHandle(h, out info))
                    throw new IOException("identité de " + path + " illisible : " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return new FileIdentity(info.VolumeSerialNumber, ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
            }
        }

        /// <summary>Vrai si les deux chemins désignent le même fichier ; faux si l'un des deux ne peut pas être ouvert (jamais d'acceptation par défaut).</summary>
        public static bool Same(string a, string b)
        {
            try { return Of(a).Equals(Of(b)); }
            catch (IOException) { return false; }
        }

        public bool Equals(FileIdentity other)
        {
            return other != null && other.VolumeSerial == VolumeSerial && other.FileIndex == FileIndex;
        }

        public override bool Equals(object obj) { return Equals(obj as FileIdentity); }

        public override int GetHashCode() { return VolumeSerial.GetHashCode() ^ FileIndex.GetHashCode(); }
    }
}
