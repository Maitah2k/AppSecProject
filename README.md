# Secure Web Application Project

## Description

This is a simple Node.js web application with the following features:
- User registration and login
- Session management using `express-session`
- Role-based access control (RBAC)
- Password hashing using `bcrypt`
- SQLite database for storing user data
- XSS protection with `DOMPurify`

## 📁 Project Structure

```
project/
├── public/     # Home page, CSS, client JS
├── views/      # HTML views not served statically
├── error/      # Pages served in case of errors
├── users.db    # SQLite database storing user info
├── .env        # Environment variables
├── server.js   # Main Express server
└── README.md
```
## ✅ Requirements

- Node.js (v16 or newer)
- npm

## ⚙️ Setup & Install

1. Clone the repo
2. Install dependencies:
    ```bash
    npm install
    ```
3. Create a .env file and copy contents from .ENV_EXAMPLE
4. Run the app:
    ```bash
    node server.js
    ```

## 🔐 Admin Account

At startup, a default admin account is automatically created (if not already present) with the credentials provided in the .env file

## ✏️ Notes

- Make sure to change the default admin credentials before deploying.
- This project does not include HTTPS, meaning that requests and responses will not be encrypted in transit. This is for demonstration purposes only.
