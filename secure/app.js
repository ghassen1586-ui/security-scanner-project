const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();

const app = express();

const db = mysql.createConnection({
    host: 'host.docker.internal',
    user: 'root',
    password: process.env.DB_PASSWORD,
    database: 'security_project'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Database connected');
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.get('/', (req, res) => {
    res.render('index');
});
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'secret123',
    resave: false,
    saveUninitialized: true
}));

// FIX 1 - prepared statement (no SQLi possible)
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    // SECURE - user input passed as data not as SQL code
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            // FIX 3 - bcrypt compare instead of plain text
            bcrypt.compare(password, results[0].password, (err, match) => {
                if (match) {
                    req.session.user = results[0];
                    res.redirect('/comments');
                } else {
                    res.render('login', { error: 'Invalid credentials' });
                }
            });
        } else {
            res.render('login', { error: 'Invalid credentials' });
        }
    });
});

app.get('/comments', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    db.query('SELECT * FROM comments', (err, comments) => {
        if (err) throw err;
        res.render('comments', { user: req.session.user, comments: comments });
    });
});

app.post('/comments', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    const comment = req.body.comment;

    // SECURE - prepared statement
    db.query('INSERT INTO comments (user_id, content) VALUES (?, ?)',
        [req.session.user.id, comment], (err) => {
            if (err) throw err;
            res.redirect('/comments');
        });
});

// GET account page - FIXED (ownership check prevents IDOR)
app.get('/account', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    const requestedId = req.query.id || req.session.user.id;

    // SECURE - verify the requested account belongs to the logged-in user
    if (parseInt(requestedId) !== req.session.user.id) {
        return res.status(403).send('Forbidden: you can only view your own account');
    }

    db.query('SELECT id, email FROM users WHERE id = ?', [requestedId], (err, results) => {
        if (err) return res.status(500).send(err.message);
        if (results.length === 0) return res.status(404).send('Account not found');
        res.render('account', { account: results[0] });
    });
});

app.listen(3001, () => {
    console.log('Secure app running on http://localhost:3001');
});