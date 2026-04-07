using System;
using System.Runtime.InteropServices;

namespace ProEDC
{
    // Entspricht ProED_Mode (aus ProED_Interface.h)
    public enum ProED_Mode : uint
    {
        ENCRYPT = 0,
        DECRYPT = 1
    }

    // Fehlercodes der ProEDC (aus ProEDC.h)
    public enum ProEDC_Status : int
    {
        SUCCESS = 0,
        ERR_PARAM = -1,
        ERR_FILE_IO = -2,
        ERR_CRYPTO = -3,
        ERR_HASH = -4,
        ERR_KEYGEN = -5,
        ERR_MEMORY = -6,
        ERR_LIMIT_REACHED = -7
    }

    // Entspricht ProED_Context (72 Bytes, 4 Byte Alignment)
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public unsafe struct ProED_Context
    {
        // uint32_t state[8]
        public fixed uint state[8];

        // uint8_t stream[32]
        public fixed byte stream[32];

        // uint32_t idx
        public uint idx;

        // uint32_t mode
        public ProED_Mode mode;
    }

    // Entspricht ProHash_Ctx (aus ProHash.h)
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public unsafe struct ProHash_Ctx
    {
        public fixed uint belt[16];
        public ulong count;
        public fixed byte buffer[64];
        public uint buf_idx;
    }

    public static unsafe class ProNative
    {
        // Bibliotheksnamen (entsprechen den Namen in den Makefiles)
        private const string LibProED   = "proed";
        private const string LibProHash = "prohash";
        private const string LibProKey  = "prokey";
        private const string LibProEDC  = "proedc";

        // --- ProED CORE (Verschlüsselung) ---
        // WICHTIG: Signatur angepasst auf IV Support (iv und iv_len)
        [DllImport(LibProED, CallingConvention = CallingConvention.Cdecl, EntryPoint = "proed_init")]
        public static extern void proed_init(ProED_Context* ctx, byte* key, UIntPtr key_len, byte* iv, UIntPtr iv_len, ProED_Mode mode);

        [DllImport(LibProED, CallingConvention = CallingConvention.Cdecl, EntryPoint = "proed_process")]
        public static extern void proed_process(ProED_Context* ctx, byte* data, UIntPtr len);


        // --- ProHash (Hashing) ---
        [DllImport(LibProHash, CallingConvention = CallingConvention.Cdecl)]
        public static extern void prohash_init(ProHash_Ctx* ctx);

        [DllImport(LibProHash, CallingConvention = CallingConvention.Cdecl)]
        public static extern void prohash_update(ProHash_Ctx* ctx, byte* data, UIntPtr len);

        [DllImport(LibProHash, CallingConvention = CallingConvention.Cdecl)]
        public static extern void prohash_final(ProHash_Ctx* ctx, byte* digest);


        // --- ProKey (Entropie / Zufall) ---
        [DllImport(LibProKey, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ProKey_Generate(byte* buffer, UIntPtr length);


        // --- ProEDC (High-Level CLI Logic / Profiling) ---
        [DllImport(LibProEDC, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ProEDC_Init();

        [DllImport(LibProEDC, CallingConvention = CallingConvention.Cdecl)]
        public static extern ProEDC_Status ProEDC_EncryptFile(string input, string output, string keyfile);

        [DllImport(LibProEDC, CallingConvention = CallingConvention.Cdecl)]
        public static extern ProEDC_Status ProEDC_DecryptFile(string input, string output, string keyfile);


        // --- HELPER FÜR SAFE CONTEXT ---
        public static ProED_Context CreateEncryptionContext()
        {
            return new ProED_Context();
        }

        public static ProHash_Ctx CreateHashContext()
        {
            return new ProHash_Ctx();
        }
    }
}
