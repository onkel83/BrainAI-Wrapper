using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ProChat.Core.Hashing
{
    /// <summary>
    /// C# Wrapper für den ProHash-256 Algorithmus ("The Shredder").
    /// </summary>
    public unsafe class ProHash : IDisposable
    {
        private const string LibName = "prohash.dll";

        // Struktur-Mapping des nativen ProHash_Ctx (136 Bytes)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct ProHashCtx
        {
            public fixed uint belt[16];   // 512-Bit interner Zustand
            public ulong count;           // Verarbeitete Bytes
            public fixed byte buffer[64]; // Block-Puffer
            public uint buf_idx;          // Puffer-Position
        }

        // --- Native Imports ---
        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void prohash_init(ProHashCtx* ctx);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void prohash_update(ProHashCtx* ctx, byte* data, UIntPtr len);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void prohash_final(ProHashCtx* ctx, byte* digest);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr prohash_get_version_info();

        private ProHashCtx* _ctx;
        private bool _disposed = false;

        public ProHash()
        {
            // Allokation des Kontexts im unmanaged Speicher
            _ctx = (ProHashCtx*)Marshal.AllocHGlobal(sizeof(ProHashCtx));
            prohash_init(_ctx);
        }

        /// <summary>
        /// Gibt die Versions- und Entwicklerinformationen der Library zurück.
        /// </summary>
        public static string GetVersionInfo()
        {
            IntPtr ptr = prohash_get_version_info();
            return Marshal.PtrToStringAnsi(ptr);
        }

        /// <summary>
        /// Aktualisiert den Hash mit neuen Daten.
        /// </summary>
        public void Update(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            fixed (byte* pData = data)
            {
                prohash_update(_ctx, pData, (UIntPtr)data.Length);
            }
        }

        /// <summary>
        /// Schließt die Berechnung ab und gibt den 32-Byte Digest zurück.
        /// </summary>
        public byte[] Final()
        {
            byte[] digest = new byte[32];
            fixed (byte* pDigest = digest)
            {
                prohash_final(_ctx, pDigest);
            }
            return digest;
        }

        /// <summary>
        /// Statische Hilfsmethode für das Hashing eines kompletten Byte-Arrays.
        /// </summary>
        public static string ComputeHash(byte[] data)
        {
            using (var hasher = new ProHash())
            {
                hasher.Update(data);
                byte[] hash = hasher.Final();

                StringBuilder sb = new StringBuilder();
                foreach (byte b in hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_ctx != null)
                {
                    // Sicherheits-Wipe: Speicher vor Freigabe nullen
                    byte* p = (byte*)_ctx;
                    for (int i = 0; i < sizeof(ProHashCtx); i++) p[i] = 0;

                    Marshal.FreeHGlobal((IntPtr)_ctx);
                    _ctx = null;
                }
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }

        ~ProHash() => Dispose();
    }
}