const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
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

// GET login page
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// POST login - VULNERABLE
app.post('/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
    console.log('Query executed:', query);

    db.query(query, (err, results) => {
        if (err) {
            return res.render('login', { error: err.message });
        }
        if (results.length > 0) {
            req.session.user = results[0];
            res.redirect('/comments');
        } else {
            res.render('login', { error: 'Invalid credentials' });
        }
    });
});

// GET comments page
app.get('/comments', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    db.query('SELECT * FROM comments', (err, comments) => {
        if (err) throw err;
        res.render('comments', { user: req.session.user, comments: comments });
    });
});

// POST comment - VULNERABLE
app.post('/comments', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    const comment = req.body.comment;

    db.query(`INSERT INTO comments (user_id, content) VALUES (${req.session.user.id}, ${db.escape(comment)})`, (err) => {
        if (err) throw err;
        res.redirect('/comments');
    });
});

app.get('/search', (req, res) => {
    const q = req.query.q;
    if (!q) return res.render('search', { results: [], query: '' });

    // VULNERABLE - direct concatenation
    const query = `SELECT id, title, content FROM articles WHERE title LIKE '%${q}%'`;
    console.log('Query:', query);

    db.query(query, (err, results) => {
        if (err) return res.render('search', { results: [], query: q, error: err.message });
        res.render('search', { results: results, query: q, error: null });
    });
});

// GET account page - VULNERABLE (IDOR)
app.get('/account', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    const requestedId = req.query.id || req.session.user.id;

    db.query('SELECT id, email FROM users WHERE id = ?', [requestedId], (err, results) => {
        if (err) return res.status(500).send(err.message);
        if (results.length === 0) return res.status(404).send('Account not found');
        res.render('account', { account: results[0] });
    });
});

app.listen(3000, () => {
    console.log('Vulnerable app running on http://localhost:3000');
});