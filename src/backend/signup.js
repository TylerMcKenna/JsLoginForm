import express from 'express';
import path from 'path';
import bodyParser from 'body-parser';
import argon2 from 'argon2';
import { encrypt, decrypt } from 'node-encryption';
import sqlite3 from 'sqlite3';

const app = express();
const PORT = 8080;

app.use(bodyParser.urlencoded());

// At least 12 characters, one lowercase, one uppercase, one number, one special character
const regEx = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

// Key for encrypting/decrypting email
const encryptionKey = '61defe22ed4f30efea5dcb5e386fae95ed756ea686b3f6efdd4c8983c4cde1d1';

// Initialize sqlite3 database
const db = new sqlite3.Database(path.join(import.meta.dirname, '..', 'database', 'users.db'));
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS users ( email VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, password VARCHAR NOT NULL, phone VARCHAR )')
});


app.get('/', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, '..', 'frontend', 'mainpage.html'));
});

app.get('/signin', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, '..', 'frontend', 'signin.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, '..', 'frontend', 'signup.html'));
});

app.get('/forgotPassword', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, '..', 'frontend', 'forgotpassword.html'));
});

app.get('/resetConfirmation', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, '..', 'frontend', 'resetconfirmation.html'));
});


app.post('/signupForm', async (req, res) => {
    if (!req.body) {
        res.status(400).send('Missing some or all fields');
    }
    
    for (const element in req.body) {
        if (!req.body[element]) {
            res.status(400).send('Missing some or all fields');
        }
    }``
    
    const email = req.body.email;
    const name = encrypt(req.body.name, encryptionKey);
    const password = req.body.password;
    const passwordRepeat = req.body.passwordRepeat;
    const phone = req.body.phone;

    if (!(password === passwordRepeat)) {
        res.status(400).send('Passwords do not match');
    }
    
    if (!regEx.test(password)) {
        res.status(400).send('Password does not meet the requirements');
    }
    
    let hashedPass;
    try {
        hashedPass = await argon2.hash(password);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
    
    db.serialize(() => {
        db.run('INSERT INTO users (email, name, password, phone) VALUES (?,?,?,?)', email, name, hashedPass, phone);
        res.sendStatus(201);
    });
});

app.post('/signinForm', async (req, res) => {
    if (!req.body) {
        res.status(400).send('Missing some or all fields');
    }
    
    for (const element in req.body) {
        if (!req.body[element]) {
            res.status(400).send('Missing some or all fields');
        }
    }

    const email = req.body.email;
    const password = req.body.password;

    db.serialize(() => {
        db.get('SELECT * FROM users WHERE email = ?', email, async (error, row) => {
            if (error) {
                console.log(error);
                res.sendStatus(500);
            }

            if (!row) {
            return res.status(401).send('Invalid login!');
        }

            try {
                const valid = await argon2.verify(row.password, password); 
                
                if (valid) {
                    const phone = row.phone;
                    if (!phone) {
                        return res.status(500).send('Login successful, but no phone number for SMS MFA.');
                    }

                    const mfaSetupUrl = `https://wa-ocu-mfa-fre6d6guhve2afcw.centralus-01.azurewebsites.net/mfa/setup/sms/${phone}`;
                    
                    try {
                        const fetchResponse = await fetch(mfaSetupUrl);
                        if (!fetchResponse.ok) {
                            throw new Error(`SMS MFA setup failed with status: ${fetchResponse.status}`);
                        }

                        res.redirect(`/mfa?phone=${phone}`);

                    } catch (fetchError) {
                        console.error('SMS MFA Setup API Error:', fetchError);
                        res.status(500).send('Login successful, but SMS MFA setup failed.');
                    }

                } else {
                    res.status(401).send('Invalid login!');
                }
            } catch (error) {
                console.error(error);
                res.sendStatus(500);
            }
        });
    });
});

app.post('/verifyMfa', async (req, res) => {
    const phone = req.body.phone; 
    const code = req.body.code;

    if (!phone || !code) {
        return res.status(400).send('Missing phone number or MFA code.');
    }

    const verifyUrl = 'https://wa-ocu-mfa-fre6d6guhve2afcw.centralus-01.azurewebsites.net/mfa/verify/sms';
    const verificationData = {
        "id": phone,
        "code": code
    };

    try {
        const fetchResponse = await fetch(verifyUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(verificationData)
        });

        if (!fetchResponse.ok) {
            throw new Error(`SMS MFA verification API failed with status: ${fetchResponse.status}`);
        }

        const verificationResult = await fetchResponse.json();

        if (verificationResult) {
            res.send(`SMS MFA Verification Successful! Welcome back.`);
        } else {
            res.status(401).send('SMS MFA Verification Failed. Invalid code.');
        }

    } catch (error) {
        console.error('SMS MFA Verification Error:', error);
        res.status(500).send('An error occurred during SMS MFA verification.');
    }
});

app.get('/mfa', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, '..', 'frontend', 'mfa.html'));
});

app.post('/forgotPasswordForm', (req, res) => {
    const email = req.body.email;

    if (!email) {
        return res.status(400).send('Missing email address.');
    }

    db.get('SELECT email FROM users WHERE email = ?', email, (error, row) => {
        if (error) {
            console.error(error);
            return res.sendStatus(500);
        }

        if (row) {
            const resetLink = `http://localhost:8080/resetPassword?token=fake_token_for_${email}`;
            console.log(`[PASSWORD RESET]: Simulating email send to ${email} with link: ${resetLink}`);
        } else {
            console.log(`[PASSWORD RESET]: Request received for unknown email: ${email}`);
        }

        res.redirect('/resetConfirmation');
    });
});

app.listen(PORT, () => console.log(`server is listening on port ${PORT}`));