require('dotenv').config();
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const crypto = require('crypto');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const PORT = process.env.PORT;
const saltRounds = 10;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SESSION_SECRET = process.env.SESSION_SECRET;
app.use(session({
    store: new SQLiteStore({ db: 'sessions.db', dir: './' }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
}));

const db = new sqlite3.Database(path.join(__dirname, 'users.db')); // Opens connection to database

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// ------------------ ENCRYPTION ------------------
const ENC_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'base64'); // 32 bytes key
const IV = Buffer.from(process.env.ENCRYPTION_IV, 'base64'); // 16 bytes IV

// Encryption
function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, IV);
    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

// Decryption
function decrypt(encryptedText) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, IV);
    let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

const usernameRegex = /^[A-Za-z0-9_]{3,20}$/;
const emailRegex = /^[\w.-]+@[a-zA-Z\d.-]+\.[a-zA-Z]{2,150}$/;
const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{12,30}$/;

// ------------------ REGISTER ------------------
app.post('/register.html', (req, res) => {
    const { usr, email, password } = req.body;

    const sanitizedUsr = DOMPurify.sanitize(usr);
    const sanitizedEmail = DOMPurify.sanitize(email);

    if (!sanitizedUsr || !sanitizedEmail || !password) {
        return res.status(400).json({ message: 'Missing fields' });
    }

    if (!usernameRegex.test(sanitizedUsr)) {
        return res.status(400).json({ message: 'Invalid username format' });
    }

    if (!emailRegex.test(sanitizedEmail)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    if (!passwordRegex.test(password)) {
        return res.status(400).json({ message: 'Password must be at least 12 characters long and contain a letter and a number' });
    }

    const encryptedUsr = encrypt(sanitizedUsr);       // Encrypt username
    const encryptedEmail = encrypt(sanitizedEmail);   // Encrypt email

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.error("Hashing error:", err);
            return res.status(500).json({ message: 'Hashing error' });
        }

        const insertQuery = `INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`;
        db.run(insertQuery, [encryptedUsr, hash, encryptedEmail, encrypt("user")], function (error) {
            if (error) {
                console.error(error);
                return res.status(500).json({ message: 'Database error' });
            }

            console.log(`Inserted row into userdb with rowid ${this.lastID}`);
            res.status(200).json({ message: "success" });
        });
    });
});

// ------------------ LOGIN ------------------
app.post('/login.html', (req, res) => {
    const { usr, password } = req.body;
    const sanitizedUsr = DOMPurify.sanitize(usr);

    if (!sanitizedUsr || !password) {
        return res.status(400).json({ message: 'Missing fields' });
    }

    if (!usernameRegex.test(sanitizedUsr)) {
        return res.status(400).json({ message: 'Invalid username format' });
    }

    const encryptedUsr = encrypt(sanitizedUsr); // Encrypt username before search

    const searchQuery = `SELECT * FROM users WHERE username = ?`;
    db.get(searchQuery, [encryptedUsr], (err, row) => {
        if (err) {
            console.error('DB error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (!row) {
            return res.status(401).json({ message: 'fail' });
        }

        bcrypt.compare(password, row.password, (err, result) => {
            if (err) {
                console.error('Bcrypt compare error:', err);
                return res.status(500).json({ message: 'Internal error' });
            }

            if (result) {
                const decryptedUsr = decrypt(row.username);   // Decrypt username
                const decryptedEmail = decrypt(row.email);    // Decrypt email
                const decryptedRole = decrypt(row.role);      // Decrypt role

                req.session.user = {
                    username: decryptedUsr,
                    role: decryptedRole,
                    email: decryptedEmail
                };

                let redirect;
                if (decryptedRole == "admin")
                    redirect = "admin.html";
                else if (decryptedRole == "user")
                    redirect = "user.html";

                res.status(200).json({ message: 'success', redirect: redirect });
            } else {
                res.status(401).json({ message: "fail" });
            }
        });
    });
});

// ------------------ LOGOUT ------------------
app.post("/logout", (req, res) => {
    if (req.session.user) {
        req.session.destroy(err => {
            if (err)
                return res.status(500).json({ message: 'Logout error' });

            res.clearCookie('connect.sid');
            res.json({ message: "success" });
        });
    }
});

// ------------------ ROUTE PROTECTION ------------------
function requireRole(role) {
    return function (req, res, next) {
        if (req.session.user && req.session.user.role === role) {
            next();
        } else {
            res.status(404).sendFile(path.join(__dirname, 'error', '404.html'));
        }
    };
}

// ------------------ GET ROUTES ------------------
app.get('/admin.html', requireRole('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/user.html', requireRole('user'), (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'user.html'));
});

app.get('/login.html', (req, res) => {
    if (req.session.user) {
        let redirect = (req.session.user.role === 'admin') ? 'admin.html' : 'user.html';
        res.status(302).sendFile(path.join(__dirname, 'views', redirect));
    } else {
        res.status(200).sendFile(path.join(__dirname, 'views', 'login.html'));
    }
});

app.get('/register.html', (req, res) => {
    if (req.session.user) {
        let redirect = (req.session.user.role === 'admin') ? 'admin.html' : 'user.html';
        res.status(302).sendFile(path.join(__dirname, 'views', redirect));
    } else {
        res.status(200).sendFile(path.join(__dirname, 'views', 'register.html'));
    }
});

// Catch-all for 404
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'error', '404.html'));
});


db.run(`
    CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE, 
                password TEXT,
                email TEXT UNIQUE,
                role TEXT NOT NULL
        )`
        ,[], function (err) {
            if (err)
                return console.log("❌ Error creating database", err);
            console.log("✅ Database created successfully");

            // ------------------ ADMIN CREATION ------------------
            const ADMIN_USER = process.env.ADMIN_USER;
            const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
            const ADMIN_PASS = process.env.ADMIN_PASS;
            const adminRole = 'admin';

            // Check if admin exists, if not create it with encrypted username and email
            db.get(`SELECT * FROM users WHERE username = ?`, [encrypt(ADMIN_USER)], (err, row) => {
                if (err) {
                    return console.error("DB error while checking for admin:", err);
                }

                if (!row) {
                    bcrypt.hash(ADMIN_PASS, saltRounds, (err, hashedPassword) => {
                        if (err) return console.error("Hashing error:", err);

                        const encryptedUsr = encrypt(ADMIN_USER);
                        const encryptedEmail = encrypt(ADMIN_EMAIL);
                        db.run(`INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`,
                            [encryptedUsr, hashedPassword, encryptedEmail, encrypt(adminRole)],
                            function (err) {
                                if (err) return console.error("Error inserting admin user:", err);
                                console.log(`✅ Admin user created.`);
                            });
                    });
                } else {
                    console.log("🔒 Admin user already exists, skipping creation.");
                }
            });
    })
    



// ------------------ START SERVER ------------------
app.listen(PORT, () => {
console.log(` Server is running on port ${PORT}`);
});