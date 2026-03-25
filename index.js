const express = require("express");
const fs = require("fs");
const path = require("path");
const argon2 = require("argon2");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const USERS_FILE = path.join(__dirname, "users.json");

// ensure file exists
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, "[]");
}

function readUsers() {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
}

function writeUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

//
// REGISTER
//
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Missing fields" });
    }

    const users = readUsers();

    if (users.find(u => u.username === username)) {
        return res.status(409).json({ error: "User already exists" });
    }

    try {
        const passwordHash = await argon2.hash(password);

        users.push({
            username,
            passwordHash
        });

        writeUsers(users);

        res.json({ message: "User registered" });
    } catch (err) {
        res.status(500).json({ error: "Hashing failed" });
    }
});

//
// LOGIN
//
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Missing fields" });
    }

    const users = readUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    try {
        const valid = await argon2.verify(user.passwordHash, password);

        if (!valid) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        res.json({ message: "Login success" });
    } catch (err) {
        res.status(500).json({ error: "Verification failed" });
    }
});

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});