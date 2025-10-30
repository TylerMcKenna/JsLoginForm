import express from 'express';
import path from 'path';
import bodyParser from 'body-parser';

const app = express();
const PORT = 8080;

app.use(bodyParser.urlencoded());

app.get('/', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, '..', 'frontend', 'signup.html'));
});

app.post('/signupForm', (req, res) => {
    res.send(req.body.passwordRepeat);
});

app.listen(PORT, () => console.log(`server is listening on port ${PORT}`));