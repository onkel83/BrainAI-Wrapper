package com.brainai.proedc;

import com.sun.jna.*;
import com.sun.jna.ptr.PointerByReference;
import java.util.Arrays;
import java.util.List;

public class ProNative {

    // --- ENUMS & KONSTANTEN ---
    public interface ProED_Mode {
        int ENCRYPT = 0;
        int DECRYPT = 1;
    }

    public interface ProEDC_Status {
        int SUCCESS = 0;
        int ERR_PARAM = -1;
        int ERR_FILE_IO = -2;
        int ERR_CRYPTO = -3;
        int ERR_HASH = -4;
        int ERR_KEYGEN = -5;
        int ERR_MEMORY = -6;
        int ERR_LIMIT_REACHED = -7;
    }

    // --- STRUKTUREN (C-Kompatibel) ---

    @Structure.FieldOrder({"state", "stream", "idx", "mode"})
    public static class ProED_Context extends Structure {
        public int[] state = new int[8];      // uint32_t state[8]
        public byte[] stream = new byte[32];  // uint8_t stream[32]
        public int idx;                       // uint32_t idx
        public int mode;                      // uint32_t mode (Enum)

        public ProED_Context() {
            super();
            setAlignType(ALIGN_GNUC); // 4-Byte Alignment
        }
    }

    @Structure.FieldOrder({"belt", "count", "buffer", "bufIdx"})
    public static class ProHash_Ctx extends Structure {
        public int[] belt = new int[16];      // uint32_t belt[16]
        public long count;                    // uint64_t count
        public byte[] buffer = new byte[64];  // uint8_t buffer[64]
        public int bufIdx;                    // uint32_t buf_idx

        public ProHash_Ctx() {
            super();
            setAlignType(ALIGN_DEFAULT); // 8-Byte Alignment für uint64_t
        }
    }

    // --- INTERFACE DEFINITIONEN ---

    public interface IProKey extends Library {
        IProKey INSTANCE = Native.load("prokey", IProKey.class);
        void ProKey_Generate(byte[] buffer, NativeSize length);
    }

    public interface IProHash extends Library {
        IProHash INSTANCE = Native.load("prohash", IProHash.class);
        void prohash_init(ProHash_Ctx ctx);
        void prohash_update(ProHash_Ctx ctx, byte[] data, NativeSize len);
        void prohash_final(ProHash_Ctx ctx, byte[] digest);
    }

    public interface IProED extends Library {
        IProED INSTANCE = Native.load("proed", IProED.class);
        void proed_init(ProED_Context ctx, byte[] key, NativeSize keyLen, byte[] iv, NativeSize ivLen, int mode);
        void proed_process(ProED_Context ctx, byte[] data, NativeSize len);
    }

    public interface IProEDC extends Library {
        IProEDC INSTANCE = Native.load("proedc", IProEDC.class);
        void ProEDC_Init();
        int ProEDC_EncryptFile(String inputFile, String outputFile, String keyFile);
        int ProEDC_DecryptFile(String inputFile, String outputFile, String keyFile);
        String ProEDC_GetVersion();
    }

    // --- HIGH LEVEL HELPER ---
    public static class Client {
        static {
            IProEDC.INSTANCE.ProEDC_Init();
        }

        public static byte[] generateKey(int bytes) {
            byte[] key = new byte[bytes];
            IProKey.INSTANCE.ProKey_Generate(key, new NativeSize(bytes));
            return key;
        }

        public static String calculateHash(byte[] data) {
            ProHash_Ctx ctx = new ProHash_Ctx();
            IProHash.INSTANCE.prohash_init(ctx);
            IProHash.INSTANCE.prohash_update(ctx, data, new NativeSize(data.length));
            byte[] digest = new byte[32];
            IProHash.INSTANCE.prohash_final(ctx, digest);
            
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02X", b));
            return sb.toString();
        }

        public static int encryptFile(String in, String out, String key) {
            return IProEDC.INSTANCE.ProEDC_EncryptFile(in, out, key);
        }
    }
}
