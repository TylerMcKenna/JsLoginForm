import assert from 'assert';
import fs from 'fs';
import 'mocha';

import { encrypt, decrypt } from './src/index';

const encryptionKey = 'mysecretkey1337';

describe('Encryption', () => {
    it('should encrypt and decrypt text', () => {
        const text = 'This will be encrypted';

        const encrypted = encrypt(text, encryptionKey);

        const decrypted = decrypt(encrypted, encryptionKey);

        assert(decrypted.toString() === text);
    });

    it('should encrypt and decrypt a buffer', () => {
        const text = 'This will be encrypted';

        const encrypted = encrypt(Buffer.from(text), encryptionKey);

        const decrypted = decrypt(encrypted, encryptionKey);

        assert(decrypted.toString() === text);
    });

    it('should encrypt and decrypt an image', () => {
        const image = fs.readFileSync('./shyguy.png');

        const imageHex = image.toString('hex');

        const encrypted = encrypt(image, encryptionKey);

        const decrypted = decrypt(encrypted, encryptionKey);

        assert(decrypted.toString('hex') === imageHex);
    });
});
