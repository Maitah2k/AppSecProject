require('dotenv').config();
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

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

// Handles POST requests to register new user
app.post('/register.html', (req, res) => {
    const { usr, email, password } = req.body;

    const sanitizedUsr = DOMPurify.sanitize(usr);
    const sanitizedEmail = DOMPurify.sanitize(email);


    if (!sanitizedUsr || !sanitizedEmail || !password) {
        return res.status(400).json({ message: 'Missing fields' });
    }

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.error("Hashing error:", err);
            return res.status(500).json({ message: 'Hashing error' });
        }

        const insertQuery = `INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`;
        db.run(insertQuery, [sanitizedUsr, hash, sanitizedEmail, "user"], function (error) {
            if (error) {
                console.error(error);
                return res.status(500).json({ message: 'Database error' });
            }

            console.log(`Inserted row into userdb with rowid ${this.lastID}`);
            res.status(200).json({ message: "success" });
        });
    });
});

// Handles POST request to login
app.post('/login.html', (req, res) => {
    const { usr, password } = req.body;

    const sanitizedUsr = DOMPurify.sanitize(usr);

    if (!sanitizedUsr || !password) {
        return res.status(400).json({ message: 'Missing fields' });
    }

    const searchQuery = `SELECT * FROM users WHERE username = ?`;
    db.get(searchQuery, [sanitizedUsr], (err, row) => {
        if (err) {
            console.error('DB error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (!row) {
            return res.status(401).json({ message: 'Incorrect username or password' });
        }

        bcrypt.compare(password, row.password, (err, result) => {
            if (err) 
            {
                console.error('Bcrypt compare error:', err);
                return res.status(500).json({ message: 'Internal error' });
            }

            if (result) 
            {
                req.session.user = {
                    username: sanitizedUsr,
                    role: row.role
                };
                res.status(200).json({ message: 'Login successful' });
            } 
            else 
            {
                res.status(401).json({ message: "Incorrect username or password" });
            }
        });
    });
});

function requireRole(role) {
    return function (req, res, next) {
        if (req.session.user && req.session.user.role === role) {
            next();
        } else {
            res.status(403).json({ message: 'Forbidden: insufficient privileges' }); // ❌ block access
        }
    };
}

app.get('/admin.html', requireRole('admin'), (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/user.html', requireRole('user'), (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'user.html'));
});


const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASS = process.env.ADMIN_PASS;
const adminRole = 'admin';

const checkAdminQuery = `SELECT * FROM users WHERE username = ?`;
db.get(checkAdminQuery, [ADMIN_USER], (err, row) => {
    if (err) {
        return console.error("DB error while checking for admin:", err);
    }

    if (!row) {
        bcrypt.hash(ADMIN_PASS, saltRounds, (err, hashedPassword) => {
            if (err) {
                return console.error("Hashing error:", err);
            }

            const insertAdminQuery = `INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`;
            db.run(insertAdminQuery, [ADMIN_USER, hashedPassword, ADMIN_EMAIL, adminRole], function (err) {
                if (err) {
                    return console.error("Error inserting admin user:", err);
                }

                console.log(`✅ Admin user created.`);
            });
        });
    } else {
        console.log("🔒 Admin user already exists, skipping creation.");
    }
});


app.listen(PORT, () => {
    console.log("Server is running on port", PORT);
});
