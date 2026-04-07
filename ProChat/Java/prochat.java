package com.brainai.prochat;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;

import java.util.Arrays;

public class ProChat {

    // --- KONSTANTEN & FEHLERCODES ---
    public interface Config {
        int PC_PKT_SIZE = 1024;    // Feste Paketgröße
        int PC_MAX_PAYLOAD = 988; // Maximale Nutzlast
    }

    public interface Status {
        int PC_OK = 0;
        int PC_ERR_PARAM = -1;    // Ungültige Parameter
        int PC_ERR_AUTH = -2;     // Authentifizierungsfehler
        int PC_ERR_REPLAY = -3;   // Replay-Attacke
        int PC_ERR_DESYNC = -4;   // Ratchet-Desynchronisation
    }

    // --- NATIVE INTERFACE ---
    public interface IProChat extends Library {
        // Lädt die Library plattformabhängig (prochat.dll oder libprochat.so)
        IProChat INSTANCE = Native.load("prochat", IProChat.class);

        // const char* pc_get_version_info(uint8_t* out_major, uint8_t* out_minor, uint8_t* out_patch)
        String pc_get_version_info(Pointer outMajor, Pointer outMinor, Pointer outPatch);

        // void pc_init(uint32_t uid, const uint8_t* seed)
        void pc_init(int uid, byte[] seed);

        // int pc_add_peer(uint32_t uid, const uint8_t* k)
        int pc_add_peer(int uid, byte[] k);

        // int pc_encrypt(uint32_t target, uint8_t type, const uint8_t* msg, size_t len, uint8_t* out)
        int pc_encrypt(int target, byte type, byte[] msg, NativeSize len, byte[] outPkt);

        // int pc_decrypt(uint8_t* pkt, uint32_t* out_sender, uint8_t* out_buf)
        int pc_decrypt(byte[] pkt, IntByReference outSender, byte[] outBuf);
    }

    // --- HIGH-LEVEL CLIENT KLASSE ---
    public static class Client {
        private final int myUid;

        /**
         * Initialisiert den ProChat Client.
         * @param uid Eigene User-ID.
         * @param seed 32-Byte Seed für den internen RAM-Schutz.
         */
        public Client(int uid, byte[] seed) {
            if (seed == null || seed.length != 32) {
                throw new IllegalArgumentException("Seed muss exakt 32 Bytes lang sein.");
            }
            this.myUid = uid;
            IProChat.INSTANCE.pc_init(uid, seed);
        }

        public String getVersionInfo() {
            Memory major = new Memory(1);
            Memory minor = new Memory(1);
            Memory patch = new Memory(1);
            return IProChat.INSTANCE.pc_get_version_info(major, minor, patch);
        }

        public boolean addPeer(int peerUid, byte[] key) {
            if (key == null || key.length != 32) {
                throw new IllegalArgumentException("Key muss exakt 32 Bytes lang sein.");
            }
            return IProChat.INSTANCE.pc_add_peer(peerUid, key) == Status.PC_OK;
        }

        public byte[] encryptMessage(int targetUid, byte type, byte[] message) {
            if (message.length > Config.PC_MAX_PAYLOAD) {
                throw new IllegalArgumentException("Nachricht zu lang.");
            }
            byte[] packet = new byte[Config.PC_PKT_SIZE];
            int res = IProChat.INSTANCE.pc_encrypt(targetUid, type, message, new NativeSize(message.length), packet);
            
            return (res == Status.PC_OK) ? packet : null;
        }

        public DecryptedMessage decryptPacket(byte[] packet) {
            if (packet.length != Config.PC_PKT_SIZE) return null;

            IntByReference senderUid = new IntByReference();
            byte[] outBuf = new byte[Config.PC_MAX_PAYLOAD];
            
            int bytesDone = IProChat.INSTANCE.pc_decrypt(packet, senderUid, outBuf);
            
            if (bytesDone < 0) return null;

            return new DecryptedMessage(senderUid.getValue(), Arrays.copyOf(outBuf, bytesDone));
        }
    }

    // Hilfsklasse für das Ergebnis der Entschlüsselung
    public static class DecryptedMessage {
        public final int senderUid;
        public final byte[] data;

        public DecryptedMessage(int senderUid, byte[] data) {
            this.senderUid = senderUid;
            this.data = data;
        }
    }
}
