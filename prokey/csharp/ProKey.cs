using System;
using System.Runtime.InteropServices;

namespace ProChat.Core.ProKey
{
    /// <summary>
    /// Status-Codes der ProKey Engine.
    /// </summary>
    public enum ProKeyStatus : int
    {
        Success = 0,
        ErrorParam = -1,
        ErrorHardware = -2,
        ErrorStream = -3
    }

    /// <summary>
    /// Vordefinierte Schlüssellängen in Bit.
    /// </summary>
    public enum ProKeyBits : int
    {
        Bit128 = 128,
        Bit256 = 256,
        Bit512 = 512,
        Bit1024 = 1024
    }

    /// <summary>
    /// C# Wrapper für die native ProKey Engine (Entropie / RNG).
    /// </summary>
    public static class ProKey
    {
        // Bibliotheksname (wird unter Linux automatisch zu libprokey.so aufgelöst)
        private const string LibName = "prokey.dll";

        // --- Native API Imports ---

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ProKey_GetVersion();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ProKey_Generate(byte[] buffer, UIntPtr length);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void ProKey_Fill256Bit(byte[] buffer);

        // --- High-Level Methoden ---

        /// <summary>
        /// Gibt die Versions- und Entwicklerinformationen der Library zurück.
        /// </summary>
        public static string GetVersion()
        {
            IntPtr ptr = ProKey_GetVersion();
            return Marshal.PtrToStringAnsi(ptr);
        }

        /// <summary>
        /// Generiert eine angegebene Menge an kryptografisch starkem Zufall in Bytes.
        /// </summary>
        /// <param name="lengthInBytes">Die gewünschte Länge in Bytes.</param>
        /// <returns>Ein Byte-Array mit Entropie.</returns>
        public static byte[] GenerateBytes(int lengthInBytes)
        {
            if (lengthInBytes <= 0) throw new ArgumentOutOfRangeException(nameof(lengthInBytes), "Length must be greater than zero.");

            byte[] buffer = new byte[lengthInBytes];
            ProKey_Generate(buffer, (UIntPtr)lengthInBytes);

            return buffer;
        }

        /// <summary>
        /// Generiert kryptografisch starken Zufall basierend auf den vordefinierten Bit-Längen.
        /// </summary>
        /// <param name="bits">Die gewünschte Schlüssellänge (z.B. 256 Bit).</param>
        /// <returns>Ein Byte-Array mit Entropie.</returns>
        public static byte[] GenerateKey(ProKeyBits bits)
        {
            int lengthInBytes = (int)bits / 8;
            return GenerateBytes(lengthInBytes);
        }

        /// <summary>
        /// Convenience-Wrapper für genau 256 Bit (32 Byte), nutzt die optimierte C-Funktion.
        /// </summary>
        /// <returns>Ein 32-Byte Array mit Entropie.</returns>
        public static byte[] Generate256BitKey()
        {
            byte[] buffer = new byte[32];
            ProKey_Fill256Bit(buffer);
            return buffer;
        }
    }
}