const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 6960;
const saltRounds = 10;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database(path.join(__dirname, 'users.db')); // Opens connection to database

// Handles POST requests to register new user
app.post('/register.html', (req, res) => {
    const { usr, email, password } = req.body;
    
    if (!usr || !email || !password)
    {
        console.log(usr, email, password, req.body);
        return res.status(400).json({ message: 'Missing fields' });
    }
    // Hashes password
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err)
        {
            console.error("Hashing error:", err);
            return res.status(500).json({ message: 'Hashing error' });
        }

        const insertQuery = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`;
        db.run(insertQuery, [usr, hash, email], function (error) {
        if (error)
        {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        console.log(`Inserted row into userdb with rowid ${this.lastID}`);
        res.status(200).json({ message: "success" })
        })    
    })
})


// Handles POST request to login
app.post('/login.html', (req, res) => {
    const { usr, password } = req.body;

    if (!usr || !password)
    {
        console.log(usr, password, req.body);
        return res.status(400).json({ message: 'Missing fields' });
    }
    const searchQuery = `SELECT * FROM users WHERE username = ?`;
    db.get(searchQuery, [usr], (err, row) => {
        if (err)
        {
            console.error('DB error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (!row) 
        {
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
                // PUT IN SESSION THAT BIG MAN IS LOGGED IN
                res.status(200).json({ message: 'Login successful' });
            }
            else
            {
                res.status(401).json({ message: "Incorrect username or password" });
            }
        })
    })
})
app.listen(PORT, () => {
    console.log("Server is running on port", PORT);
})