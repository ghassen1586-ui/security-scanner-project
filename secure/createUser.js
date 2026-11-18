const bcrypt = require('bcrypt');
const mysql = require('mysql2');
require('dotenv').config();

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: process.env.DB_PASSWORD,
    database: 'security_project'
});

bcrypt.hash('admin123', 10, (err, hash) => {
    console.log('Hashed password:', hash);
    db.query(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        ['admin', 'admin@secure.com', hash],
        (err) => {
            if (err) throw err;
            console.log('Secure user created');
            db.end();
        }
    );
});