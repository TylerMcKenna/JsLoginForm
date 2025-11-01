/// <reference types="node" />
type EncryptionData = string | Buffer;
interface EncryptionsOpts {
    iterations: number;
}
/**
 * Encrypts data using aes-256-gcm and a user-provided key.
 *
 * @param {string|Buffer} data - The data to be encrypted.
 * @param {string} encryptionKey - The key used for encryption.
 * @param {EncryptionOptions} [opts={ iterations: KEY_DERIVATION_ITERATIONS }] - Encryption options.
 * @param {number} [opts.iterations=KEY_DERIVATION_ITERATIONS] - The number of iterations for the PBKDF2 key derivation function.
 * @returns {string} - A hex-encoded string containing the salt, IV, authentication tag, and ciphertext.
 
 * @returns {string} - Hex-encoded string containing: salt, IV, auth tag, ciphertext.
 */
export declare function encrypt(data: EncryptionData, encryptionKey: string, opts?: EncryptionsOpts): string;
/**
 * Decrypts data previously encrypted with the `encrypt` function.
 *
 * @param {string} encryptedData - Hex-encoded data as produced by `encrypt`.
 * @param {string} encryptionKey - The same key used during encryption.
 * @param {EncryptionOptions} [opts={ iterations: KEY_DERIVATION_ITERATIONS }] - Encryption options.
 * @param {number} [opts.iterations=KEY_DERIVATION_ITERATIONS] - The number of iterations for the PBKDF2 key derivation function.
 * @returns {Buffer} - The decrypted data.
 */
export declare function decrypt(encryptedData: string, encryptionKey: string, opts?: EncryptionsOpts): Buffer;
export {};
//# sourceMappingURL=index.d.ts.map