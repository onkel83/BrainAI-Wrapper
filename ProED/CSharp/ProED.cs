using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ProED
{
    // --- KONSTANTEN & IOCTL ---
    public static class ProEDConstants
    {
        public const int HEADER_SIZE = 48; // 16 Byte IV + 32 Byte HMAC
        public const int KEY_SIZE = 32;    // 256-Bit Key
        public const int CTX_SIZE = 120;   // Größe der ProED_Context Struct

        // --- IOCTL Windows Kernel ---
        public const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        public const uint METHOD_BUFFERED = 0;
        public const uint FILE_ANY_ACCESS = 0;

        // Entspricht exakt CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
        public const uint IOCTL_PROKM_PROED = (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (0x801 << 2) | METHOD_BUFFERED;

        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint OPEN_EXISTING = 3;
    }

    public static unsafe class ProEDNative
    {
        private const string DllName = "proed";

        // --- DLL API (Software Fallback & Envelope) ---
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr proed_get_version_info(byte* out_major, byte* out_minor, byte* out_patch);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int proed_encrypt_envelope(byte[] ctx, byte[] key, UIntPtr key_len, byte[] buffer, UIntPtr total_len);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int proed_decrypt_envelope(byte[] ctx, byte[] key, UIntPtr key_len, byte[] buffer, UIntPtr total_len);

        // --- KERNEL API (kernel32.dll) ---
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, byte[] lpInBuffer, uint nInBufferSize, byte[] lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);
    }

    // --- HIGH-LEVEL HYBRID CLIENT ---
    public class ProEDClient : IDisposable
    {
        private readonly byte[] _key;
        private IntPtr _hDevice = IntPtr.Zero;

        // Flag: Zeigt an, ob Ring-0 Beschleunigung verfügbar ist
        public bool IsKernelModeActive { get; private set; }

        public ProEDClient(byte[] key)
        {
            if (key == null || key.Length != ProEDConstants.KEY_SIZE)
                throw new ArgumentException("Key must be exactly 32 bytes.");
            _key = key;

            // Prüfen, ob der ProKM Treiber im Windows Kernel läuft
            _hDevice = ProEDNative.CreateFile("\\\\.\\ProKM",
                ProEDConstants.GENERIC_READ | ProEDConstants.GENERIC_WRITE,
                0, IntPtr.Zero, ProEDConstants.OPEN_EXISTING, 0, IntPtr.Zero);

            IsKernelModeActive = (_hDevice != new IntPtr(-1) && _hDevice != IntPtr.Zero);
        }

        public string GetVersion(out byte major, out byte minor, out byte patch)
        {
            unsafe
            {
                byte ma, mi, pa;
                IntPtr ptr = ProEDNative.proed_get_version_info(&ma, &mi, &pa);
                major = ma; minor = mi; patch = pa;
                return Marshal.PtrToStringAnsi(ptr);
            }
        }

        // =========================================================================
        // METHODE 1: KERNEL-MODE (Ring-0) - Raw High-Speed Verschlüsselung
        // =========================================================================
        public byte[] ProcessKernel(byte[] payload, byte[] iv, bool isDecrypt)
        {
            if (!IsKernelModeActive)
                throw new InvalidOperationException("ProKM Kernel-Driver is not loaded. Fallback to Software Envelope required.");

            if (iv == null || iv.Length != 16)
                throw new ArgumentException("IV must be exactly 16 bytes.");

            uint mode = isDecrypt ? 1u : 0u;
            uint dataLen = (uint)payload.Length;

            // Struct Layout (Packed): Key(32) + IV(16) + Mode(4) + DataLen(4) + Payload(N)
            int reqSize = 32 + 16 + 4 + 4 + payload.Length;
            byte[] requestBuffer = new byte[reqSize];

            // Struct im Speicher zusammenbauen
            Buffer.BlockCopy(_key, 0, requestBuffer, 0, 32);
            Buffer.BlockCopy(iv, 0, requestBuffer, 32, 16);
            BitConverter.GetBytes(mode).CopyTo(requestBuffer, 48);
            BitConverter.GetBytes(dataLen).CopyTo(requestBuffer, 52);
            Buffer.BlockCopy(payload, 0, requestBuffer, 56, payload.Length);

            byte[] outBuffer = new byte[reqSize];
            uint bytesReturned = 0;

            // IOCTL Call an den Windows Kernel
            bool success = ProEDNative.DeviceIoControl(
                _hDevice,
                ProEDConstants.IOCTL_PROKM_PROED,
                requestBuffer, (uint)reqSize,
                outBuffer, (uint)reqSize,
                out bytesReturned, IntPtr.Zero);

            if (!success)
                throw new Exception("Kernel DeviceIoControl failed. Code: " + Marshal.GetLastWin32Error());

            // Die verschlüsselte/entschlüsselte Payload beginnt im outBuffer ab Byte 56
            byte[] result = new byte[payload.Length];
            Buffer.BlockCopy(outBuffer, 56, result, 0, payload.Length);

            return result;
        }

        // =========================================================================
        // METHODE 2: SOFTWARE-MODE (Ring-3) - Armored Envelope (inkl. MAC)
        // =========================================================================
        public byte[] EncryptEnvelopeSoftware(byte[] payload)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));

            byte[] buffer = new byte[ProEDConstants.HEADER_SIZE + payload.Length];
            Array.Copy(payload, 0, buffer, ProEDConstants.HEADER_SIZE, payload.Length);

            byte[] ctx = new byte[ProEDConstants.CTX_SIZE];
            int res = ProEDNative.proed_encrypt_envelope(ctx, _key, (UIntPtr)_key.Length, buffer, (UIntPtr)buffer.Length);

            if (res == 0) return null;
            return buffer;
        }

        public byte[] DecryptEnvelopeSoftware(byte[] packet)
        {
            if (packet == null || packet.Length < ProEDConstants.HEADER_SIZE) return null;

            byte[] buffer = new byte[packet.Length];
            Array.Copy(packet, buffer, packet.Length);

            byte[] ctx = new byte[ProEDConstants.CTX_SIZE];
            int res = ProEDNative.proed_decrypt_envelope(ctx, _key, (UIntPtr)_key.Length, buffer, (UIntPtr)buffer.Length);

            if (res == 0) return null; // MAC Check fehlgeschlagen!

            int payloadLen = buffer.Length - ProEDConstants.HEADER_SIZE;
            byte[] payload = new byte[payloadLen];
            Array.Copy(buffer, ProEDConstants.HEADER_SIZE, payload, 0, payloadLen);

            return payload;
        }

        public void Dispose()
        {
            if (_hDevice != new IntPtr(-1) && _hDevice != IntPtr.Zero)
            {
                ProEDNative.CloseHandle(_hDevice);
                _hDevice = IntPtr.Zero;
                IsKernelModeActive = false;
            }
        }
    }
}