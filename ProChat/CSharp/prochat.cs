using System;
using System.Runtime.InteropServices;

namespace ProChat
{
    // --- KONSTANTEN & FEHLERCODES ---
    public static class ProChatConstants
    {
        public const int PC_PKT_SIZE = 1024;    // Feste Paketgröße
        public const int PC_MAX_PAYLOAD = 988; // Maximale Nutzlast

        public const int PC_OK = 0;
        public const int PC_ERR_PARAM = -1;
        public const int PC_ERR_AUTH = -2;
        public const int PC_ERR_REPLAY = -3;
        public const int PC_ERR_DESYNC = -4;
    }

    public static unsafe class ProChatNative
    {
        // Name der Library (entspricht PROJECT in den Makefiles)
        private const string DllName = "prochat";

        // --- API DEFINITIONEN ---

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr pc_get_version_info(byte* out_major, byte* out_minor, byte* out_patch);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void pc_init(uint uid, byte[] seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pc_add_peer(uint uid, byte[] k);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pc_encrypt(uint target, byte type, byte[] msg, UIntPtr len, byte[] outPkt);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pc_decrypt(byte[] pkt, out uint out_sender, byte[] out_buf);

        // --- HELPER FÜR VERSION ---
        public static string GetVersion(out byte major, out byte minor, out byte patch)
        {
            byte ma, mi, pa;
            IntPtr ptr = pc_get_version_info(&ma, &mi, &pa);
            major = ma; minor = mi; patch = pa;
            return Marshal.PtrToStringAnsi(ptr);
        }
    }

    // --- HIGH-LEVEL CLIENT KLASSE ---
    public class ProChatClient
    {
        public uint MyUID { get; private set; }

        public ProChatClient(uint uid, byte[] seed)
        {
            if (seed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");
            MyUID = uid;
            ProChatNative.pc_init(uid, seed);
        }

        public bool AddPeer(uint uid, byte[] key)
        {
            if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.");
            return ProChatNative.pc_add_peer(uid, key) == ProChatConstants.PC_OK;
        }

        public byte[] EncryptMessage(uint targetUID, byte type, byte[] message)
        {
            byte[] packet = new byte[ProChatConstants.PC_PKT_SIZE];
            int res = ProChatNative.pc_encrypt(targetUID, type, message, (UIntPtr)message.Length, packet);
            
            if (res != ProChatConstants.PC_OK)
                return null;

            return packet;
        }

        public byte[] DecryptPacket(byte[] packet, out uint senderUID)
        {
            byte[] outputBuffer = new byte[ProChatConstants.PC_MAX_PAYLOAD];
            int bytesDecrypted = ProChatNative.pc_decrypt(packet, out senderUID, outputBuffer);

            if (bytesDecrypted < 0) return null;

            // Buffer auf die tatsächliche Größe kürzen
            byte[] finalMsg = new byte[bytesDecrypted];
            Array.Copy(outputBuffer, finalMsg, bytesDecrypted);
            return finalMsg;
        }
    }
}
