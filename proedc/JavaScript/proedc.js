const ffi = require('ffi-napi');
const ref = require('ref-napi');
const StructType = require('ref-struct-napi');
const ArrayType = require('ref-array-napi');

// --- TYP-DEFINITIONEN ---
const uint32 = ref.types.uint32;
const uint8 = ref.types.uint8;
const uint64 = ref.types.uint64;
const size_t = ref.types.size_t; // Plattformabhängig (4 oder 8 Byte)

// Arrays für die Structs
const Uint32Array8 = ArrayType(uint32, 8);
const Uint32Array16 = ArrayType(uint32, 16);
const Uint8Array32 = ArrayType(uint8, 32);
const Uint8Array64 = ArrayType(uint8, 64);

// --- STRUCTS ---

// Entspricht ProED_Context (aus ProED_Interface.h)
const ProEDContext = StructType({
    'state': Uint32Array8,
    'stream': Uint8Array32,
    'idx': uint32,
    'mode': uint32
});

// Entspricht ProHash_Ctx
const ProHashCtx = StructType({
    'belt': Uint32Array16,
    'count': uint64,
    'buffer': Uint8Array64,
    'buf_idx': uint32
});

// --- LIBRARY LOADING ---
// Erkennt automatisch die Endung (.dll, .so) basierend auf dem OS
const libPath = (name) => process.platform === 'win32' ? name : `./lib${name}.so`;

const prokey = ffi.Library(libPath('prokey'), {
    'ProKey_Generate': ['void', ['pointer', size_t]]
});

const prohash = ffi.Library(libPath('prohash'), {
    'prohash_init': ['void', [ref.refType(ProHashCtx)]],
    'prohash_update': ['void', [ref.refType(ProHashCtx), 'pointer', size_t]],
    'prohash_final': ['void', [ref.refType(ProHashCtx), 'pointer']]
});

const proed = ffi.Library(libPath('proed'), {
    'proed_init': ['void', [ref.refType(ProEDContext), 'pointer', size_t, 'pointer', size_t, uint32]],
    'proed_process': ['void', [ref.refType(ProEDContext), 'pointer', size_t]]
});

const proedc = ffi.Library(libPath('proedc'), {
    'ProEDC_Init': ['void', []],
    'ProEDC_EncryptFile': ['int', ['string', 'string', 'string']],
    'ProEDC_DecryptFile': ['int', ['string', 'string', 'string']],
    'ProEDC_GetVersion': ['string', []]
});

// --- HIGH LEVEL API ---

class ProEDC {
    constructor() {
        proedc.ProEDC_Init();
    }

    getVersion() {
        return proedc.ProEDC_GetVersion();
    }

    /**
     * Erzeugt einen sicheren Zufallsschlüssel
     */
    generateKey(length = 32) {
        const buffer = Buffer.alloc(length);
        prokey.ProKey_Generate(buffer, length);
        return buffer;
    }

    /**
     * Berechnet den ProHash-256 Digest einer Datenmenge
     */
    calculateHash(data) {
        const ctx = new ProHashCtx();
        prohash.prohash_init(ctx.ref());

        const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
        prohash.prohash_update(ctx.ref(), input, input.length);

        const digest = Buffer.alloc(32);
        prohash.prohash_final(ctx.ref(), digest);
        return digest.toString('hex').toUpperCase();
    }

    /**
     * Verschlüsselt eine Datei (Status-Codes gemäß ProEDC.h)
     */
    encryptFile(inputFile, outputFile, keyFile) {
        return proedc.ProEDC_EncryptFile(inputFile, outputFile, keyFile);
    }
}

module.exports = new ProEDC();
