"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = exports.encrypt = void 0;
const crypto = __importStar(require("crypto"));
const ALGORITHM = 'aes-256-gcm';
// Increase the iterations to enhance security
// but be aware that it will also increase the time it takes to encrypt and decrypt data
const KEY_DERIVATION_ITERATIONS = 100000;
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 64;
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
function encrypt(data, encryptionKey, opts = { iterations: KEY_DERIVATION_ITERATIONS }) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = crypto.pbkdf2Sync(encryptionKey, salt, opts.iterations, KEY_LENGTH, 'sha512');
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([salt, iv, tag, encrypted]).toString('hex');
}
exports.encrypt = encrypt;
/**
 * Decrypts data previously encrypted with the `encrypt` function.
 *
 * @param {string} encryptedData - Hex-encoded data as produced by `encrypt`.
 * @param {string} encryptionKey - The same key used during encryption.
 * @param {EncryptionOptions} [opts={ iterations: KEY_DERIVATION_ITERATIONS }] - Encryption options.
 * @param {number} [opts.iterations=KEY_DERIVATION_ITERATIONS] - The number of iterations for the PBKDF2 key derivation function.
 * @returns {Buffer} - The decrypted data.
 */
function decrypt(encryptedData, encryptionKey, opts = { iterations: KEY_DERIVATION_ITERATIONS }) {
    const data = Buffer.from(encryptedData, 'hex');
    const salt = data.subarray(0, SALT_LENGTH);
    const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag = data.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
    const text = data.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
    const key = crypto.pbkdf2Sync(encryptionKey, salt, opts.iterations, KEY_LENGTH, 'sha512');
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(text);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
}
exports.decrypt = decrypt;
