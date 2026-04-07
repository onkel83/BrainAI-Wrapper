package com.brainai.prohash;

import com.sun.jna.*;
import com.sun.jna.ptr.PointerByReference;
import java.util.Arrays;
import java.util.List;

/**
 * Java Wrapper für den ProHash-256 Algorithmus ("The Shredder").
 * Nutzt JNA zur Anbindung der nativen Core-Bibliothek.
 */
public class ProHash {

    private static final String LIB_NAME = "prohash";

    // --- Native Interface Definition ---
    public interface IProHash extends Library {
        IProHash INSTANCE = Native.load(LIB_NAME, IProHash.class);

        void prohash_init(ProHashCtx ctx);
        void prohash_update(ProHashCtx ctx, byte[] data, NativeSize len);
        void prohash_final(ProHashCtx ctx, byte[] digest);
        String prohash_get_version_info();
    }

    /**
     * Mapping der nativen ProHash_Ctx Struktur (136 Bytes).
     * Das Alignment ist auf 8-Byte gesetzt, um dem uint64_t count gerecht zu werden.
     */
    @Structure.FieldOrder({"belt", "count", "buffer", "bufIdx"})
    public static class ProHashCtx extends Structure {
        public int[] belt = new int[16];      // uint32_t belt[16] (512-bit internal state)
        public long count;                    // uint64_t count (Processed bytes)
        public byte[] buffer = new byte[64];  // uint8_t buffer[64] (Input buffer)
        public int bufIdx;                    // uint32_t buf_idx (Buffer position)

        public ProHashCtx() {
            super();
            setAlignType(Structure.ALIGN_DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("belt", "count", "buffer", "bufIdx");
        }
    }

    private final ProHashCtx ctx;
    private boolean finalized = false;

    public ProHash() {
        this.ctx = new ProHashCtx();
        IProHash.INSTANCE.prohash_init(this.ctx);
    }

    /**
     * Gibt die Versionsinformationen der nativen Library zurück.
     */
    public static String getVersion() {
        return IProHash.INSTANCE.prohash_get_version_info();
    }

    /**
     * Verarbeitet einen Datenblock.
     */
    public void update(byte[] data) {
        if (data == null || data.length == 0) return;
        if (finalized) throw new IllegalStateException("Hash already finalized.");
        
        IProHash.INSTANCE.prohash_update(this.ctx, data, new NativeSize(data.length));
    }

    /**
     * Schließt die Berechnung ab und gibt den 32-Byte Digest zurück.
     * Der interne Kontext wird danach sicher gelöscht.
     */
    public byte[] finalizeHash() {
        if (finalized) throw new IllegalStateException("Hash already finalized.");
        
        byte[] digest = new byte[32];
        IProHash.INSTANCE.prohash_final(this.ctx, digest);
        finalized = true;
        return digest;
    }

    /**
     * Hilfsmethode zur schnellen Berechnung eines Hex-Hashes für Byte-Arrays.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}