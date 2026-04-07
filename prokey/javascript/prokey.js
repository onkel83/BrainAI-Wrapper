const ffi = require('ffi-napi');
const ref = require('ref-napi');

/**
 * ProKey Node.js Wrapper (Hardware Entropie / RNG)
 * Benötigt: ffi-napi, ref-napi
 */

// --- Typ-Definitionen ---
const size_t = ref.types.size_t;

// Pfad zur Library (automatische Erkennung je nach Betriebssystem)
const libPath = process.platform === 'win32' ? 'prokey.dll' : './libprokey.so';

// --- Native Interface Definition ---
const lib = ffi.Library(libPath, {
    'ProKey_GetVersion': ['string', []],
    'ProKey_Generate': ['void', ['pointer', size_t]],
    'ProKey_Fill256Bit': ['void', ['pointer']]
});

// Vordefinierte Schlüssellängen in Bit
const ProKeyBits = {
    BIT_128: 128,
    BIT_256: 256,
    BIT_512: 512,
    BIT_1024: 1024
};

class ProKey {

    /**
     * Gibt die Versions- und Entwicklerinformationen der Library zurück.
     * @returns {string} Versionsstring
     */
    static getVersion() {
        return lib.ProKey_GetVersion();
    }

    /**
     * Generiert eine angegebene Menge an kryptografisch starkem Zufall.
     * @param {number} lengthInBytes Die gewünschte Länge in Bytes.
     * @returns {Buffer} Ein Node.js Buffer mit Entropie.
     */
    static generateBytes(lengthInBytes) {
        if (lengthInBytes <= 0) {
            throw new Error("Length must be greater than zero.");
        }

        // Direkte Speicherallokation in Node.js
        const buffer = Buffer.alloc(lengthInBytes);
        lib.ProKey_Generate(buffer, lengthInBytes);

        return buffer;
    }

    /**
     * Generiert kryptografisch starken Zufall basierend auf vordefinierten Bit-Längen.
     * @param {number} bits Die gewünschte Schlüssellänge (Nutze ProKeyBits).
     * @returns {Buffer} Ein Node.js Buffer mit Entropie.
     */
    static generateKey(bits) {
        const lengthInBytes = Math.floor(bits / 8);
        return this.generateBytes(lengthInBytes);
    }

    /**
     * Convenience-Wrapper für genau 256 Bit (32 Byte), nutzt die optimierte C-Funktion.
     * @returns {Buffer} Ein 32-Byte Buffer mit Entropie.
     */
    static generate256BitKey() {
        const buffer = Buffer.alloc(32);
        lib.ProKey_Fill256Bit(buffer);
        return buffer;
    }
}

// Exportiere die Klasse und die Konstanten
module.exports = {
    ProKey,
    ProKeyBits
};