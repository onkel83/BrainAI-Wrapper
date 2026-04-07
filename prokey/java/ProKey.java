package com.brainai.prokey;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeSize;

/**
 * Java Wrapper für die native ProKey Engine (Hardware Entropie / RNG).
 */
public class ProKey {

    private static final String LIB_NAME = "prokey";

    // --- Native Interface Definition ---
    public interface IProKey extends Library {
        IProKey INSTANCE = Native.load(LIB_NAME, IProKey.class);

        String ProKey_GetVersion();
        void ProKey_Generate(byte[] buffer, NativeSize length);
        void ProKey_Fill256Bit(byte[] buffer);
    }

    /**
     * Vordefinierte Schlüssellängen in Bit.
     */
    public enum ProKeyBits {
        BIT_128(128),
        BIT_256(256),
        BIT_512(512),
        BIT_1024(1024);

        private final int bits;

        ProKeyBits(int bits) {
            this.bits = bits;
        }

        public int getBytes() {
            return this.bits / 8;
        }
    }

    // --- High-Level API ---

    /**
     * Gibt die Versions- und Entwicklerinformationen der Library zurück.
     * * @return Versionsstring.
     */
    public static String getVersion() {
        return IProKey.INSTANCE.ProKey_GetVersion();
    }

    /**
     * Generiert eine angegebene Menge an kryptografisch starkem Zufall in Bytes.
     * * @param lengthInBytes Die gewünschte Länge in Bytes.
     * @return Ein Byte-Array mit Entropie.
     */
    public static byte[] generateBytes(int lengthInBytes) {
        if (lengthInBytes <= 0) {
            throw new IllegalArgumentException("Length must be greater than zero.");
        }
        
        byte[] buffer = new byte[lengthInBytes];
        IProKey.INSTANCE.ProKey_Generate(buffer, new NativeSize(lengthInBytes));
        
        return buffer;
    }

    /**
     * Generiert kryptografisch starken Zufall basierend auf den vordefinierten Bit-Längen.
     * * @param bits Die gewünschte Schlüssellänge (z.B. BIT_256).
     * @return Ein Byte-Array mit Entropie.
     */
    public static byte[] generateKey(ProKeyBits bits) {
        return generateBytes(bits.getBytes());
    }

    /**
     * Convenience-Wrapper für genau 256 Bit (32 Byte), nutzt die optimierte C-Funktion.
     * * @return Ein 32-Byte Array mit Entropie.
     */
    public static byte[] generate256BitKey() {
        byte[] buffer = new byte[32];
        IProKey.INSTANCE.ProKey_Fill256Bit(buffer);
        return buffer;
    }

    /**
     * Hilfsmethode zur hexadezimalen Darstellung eines Byte-Arrays.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}