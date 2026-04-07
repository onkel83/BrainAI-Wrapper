const ffi = require('ffi-napi');
const ref = require('ref-napi');

// --- DATENTYPEN & KONSTANTEN ---
const uint32 = ref.types.uint32;
const uint8 = ref.types.uint8;
const size_t = ref.types.size_t;

const PC_PKT_SIZE = 1024;    // Feste Paketgröße
const PC_MAX_PAYLOAD = 988;  // Maximale Nutzlast

// --- LIBRARY DEFINITION ---
const libName = process.platform === 'win32' ? 'prochat.dll' : 'libprochat.so';

const lib = ffi.Library(libName, {
    // const char* pc_get_version_info(uint8_t* out_major, uint8_t* out_minor, uint8_t* out_patch)
    'pc_get_version_info': ['string', ['pointer', 'pointer', 'pointer']],
    
    // void pc_init(uint32_t uid, const uint8_t* seed)
    'pc_init': ['void', [uint32, 'pointer']],
    
    // int pc_add_peer(uint32_t uid, const uint8_t* k)
    'pc_add_peer': ['int', [uint32, 'pointer']],
    
    // int pc_encrypt(uint32_t target, uint8_t type, const uint8_t* msg, size_t len, uint8_t* out)
    'pc_encrypt': ['int', [uint32, uint8, 'pointer', size_t, 'pointer']],
    
    // int pc_decrypt(uint8_t* pkt, uint32_t* out_sender, uint8_t* out_buf)
    'pc_decrypt': ['int', ['pointer', 'pointer', 'pointer']]
});

class ProChat {
    /**
     * @param {number} uid Eigene User-ID
     * @param {Buffer} seed 32-Byte Seed für RAM-Verschlüsselung
     */
    constructor(uid, seed) {
        if (!Buffer.isBuffer(seed) || seed.length !== 32) {
            throw new Error("Seed muss ein Buffer von 32 Bytes sein.");
        }
        this.uid = uid;
        lib.pc_init(uid, seed);
    }

    static getVersion() {
        const major = ref.alloc(uint8);
        const minor = ref.alloc(uint8);
        const patch = ref.alloc(uint8);
        const info = lib.pc_get_version_info(major, minor, patch);
        return {
            info,
            version: `${major.deref()}.${minor.deref()}.${patch.deref()}`
        };
    }

    addPeer(peerUid, key) {
        if (!Buffer.isBuffer(key) || key.length !== 32) {
            throw new Error("Key muss ein Buffer von 32 Bytes sein.");
        }
        return lib.pc_add_peer(peerUid, key) === 0;
    }

    encrypt(targetUid, type, message) {
        const msgBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
        if (msgBuffer.length > PC_MAX_PAYLOAD) {
            throw new Error(`Nachricht zu lang (Max: ${PC_MAX_PAYLOAD} Bytes).`);
        }

        const outPacket = Buffer.alloc(PC_PKT_SIZE);
        const res = lib.pc_encrypt(targetUid, type, msgBuffer, msgBuffer.length, outPacket);
        
        return res === 0 ? outPacket : null;
    }

    decrypt(packet) {
        if (!Buffer.isBuffer(packet) || packet.length !== PC_PKT_SIZE) {
            return null;
        }

        const senderUidPtr = ref.alloc(uint32);
        const outBuf = Buffer.alloc(PC_MAX_PAYLOAD);
        
        const bytesDone = lib.pc_decrypt(packet, senderUidPtr, outBuf);
        
        if (bytesDone < 0) return null;

        return {
            senderUid: senderUidPtr.deref(),
            payload: outBuf.slice(0, bytesDone)
        };
    }
}

module.exports = ProChat;
