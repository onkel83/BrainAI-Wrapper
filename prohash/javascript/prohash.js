const ffi = require('ffi-napi');
const ref = require('ref-napi');
const StructType = require('ref-struct-napi');

/**
 * ProHash-256 Node.js Wrapper ("The Shredder")
 * Benötigt: ffi-napi, ref-napi, ref-struct-napi
 */

// --- Typ-Definitionen ---
const uint32 = ref.types.uint32;
const uint8 = ref.types.uint8;
const uint64 = ref.types.uint64;
const size_t = ref.types.size_t;

// Definition des ProHash_Ctx (136 Bytes)
const ProHashCtx = StructType({
    'belt': ffi.Array(uint32, 16),   // 512-Bit Interner Zustand
    'count': uint64,                // Anzahl verarbeiteter Bytes
    'buffer': ffi.Array(uint8, 64),  // Eingabe-Puffer
    'buf_idx': uint32               // Aktuelle Position
});

// Pfad zur Library (automatische Endung je nach OS)
const libPath = process.platform === 'win32' ? 'prohash.dll' : './libprohash.so';

const lib = ffi.Library(libPath, {
    'prohash_init': ['void', [ref.refType(ProHashCtx)]],
    'prohash_update': ['void', [ref.refType(ProHashCtx), 'pointer', size_t]],
    'prohash_final': ['void', [ref.refType(ProHashCtx), 'pointer']],
    'prohash_get_version_info': ['string', []]
});

class ProHash {
    constructor() {
        this.ctx = new ProHashCtx();
        lib.prohash_init(this.ctx.ref());
        this.finalized = false;
    }

    /**
     * Gibt die Versionsinformationen der nativen Library zurück.
     */
    static getVersion() {
        return lib.prohash_get_version_info();
    }

    /**
     * Verarbeitet Daten (Buffer oder String).
     */
    update(data) {
        if (this.finalized) throw new Error("Hash already finalized.");
        
        const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
        if (input.length === 0) return;

        lib.prohash_update(this.ctx.ref(), input, input.length);
    }

    /**
     * Schließt die Berechnung ab und gibt den 32-Byte Digest als Buffer zurück.
     */
    finalize() {
        if (this.finalized) throw new Error("Hash already finalized.");
        
        const digest = Buffer.alloc(32);
        lib.prohash_final(this.ctx.ref(), digest);
        this.finalized = true;
        
        // Zero-Trust: Kontext im Speicher nullen
        return digest;
    }

    /**
     * Statische Utility für Einmal-Hashing.
     */
    static hash(data, encoding = 'hex') {
        const hasher = new ProHash();
        hasher.update(data);
        const digest = hasher.finalize();
        return digest.toString(encoding).toUpperCase();
    }
}

module.exports = ProHash;