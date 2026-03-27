const express = require("express");
const fs = require("fs");
const path = require("path");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const mysql = require("mysql2/promise");
require("dotenv").config();

["DB_HOST","DB_USER","DB_PASSWORD","DB_NAME","JWT_ACCESS_SECRET","JWT_REFRESH_SECRET"]
    .forEach(v => {
        if (!process.env[v]) {
            console.error(`Missing env: ${v}`);
            process.exit(1);
        }
    });

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

const app = express();
app.use(express.json());
app.use(cookieParser());

const USERS_FILE = path.join(__dirname, "users.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// ensure users file
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, "[]");
}

const readUsers = () => JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
const writeUsers = (u) => fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2));

//
// REGISTER
//
app.post("/register", async (req, res) => {
    const { username, password, token } = req.body;

    if (!username || !password || !token) {
        return res.status(400).json({ error: "Missing fields" });
    }

    try {
        // ✅ verify username + token match via shared id
        const [rows] = await db.execute(`
      SELECT pn.id
      FROM player_name pn
      JOIN player_token pt ON pn.id = pt.id
      WHERE pn.name = ? AND pt.token = ?
      LIMIT 1
    `, [username, token]);

        if (rows.length === 0) {
            return res.status(403).json({ error: "Invalid username/token pair" });
        }

        // check if already registered locally
        const users = readUsers();
        if (users.find(u => u.username === username)) {
            return res.status(409).json({ error: "User already exists" });
        }

        // hash password
        const passwordHash = await argon2.hash(password);

        users.push({
            username,
            passwordHash
        });

        writeUsers(users);

        res.json({ message: "Registered successfully" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error" });
    }
});

//
// LOGIN
//
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const users = readUsers();
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ error: "Invalid" });

    const valid = await argon2.verify(user.passwordHash, password);
    if (!valid) return res.status(401).json({ error: "Invalid" });

    const accessToken = jwt.sign({ username }, ACCESS_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ username }, REFRESH_SECRET, { expiresIn: "7d" });

    // store refresh in cookie
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        sameSite: "strict"
    });

    res.json({ accessToken });
});

//
// REFRESH
//
app.post("/refresh", (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) return res.sendStatus(401);

    try {
        const user = jwt.verify(token, REFRESH_SECRET);

        const newAccess = jwt.sign(
            { username: user.username },
            ACCESS_SECRET,
            { expiresIn: "15m" }
        );

        res.json({ accessToken: newAccess });
    } catch {
        res.sendStatus(403);
    }
});

//
// LOGOUT
//
app.post("/logout", (req, res) => {
    res.clearCookie("refreshToken");
    res.json({ message: "Logged out" });
});

//
// AUTH MIDDLEWARE
//
function auth(req, res, next) {
    const header = req.headers["authorization"];
    const token = header && header.split(" ")[1];
    if (!token) return res.sendStatus(401);

    try {
        req.user = jwt.verify(token, ACCESS_SECRET);
        next();
    } catch {
        res.sendStatus(403);
    }
}

//
// ROUTES
//
app.get("/", (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, "login.html"));
});

app.get("/drive", (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, "drive.html"));
});

app.get("/me", auth, (req, res) => {
    res.json({ user: req.user });
});

//
// static
//
app.use("/static", express.static(PUBLIC_DIR));

app.listen(3000, () => {
    console.log("http://localhost:3000");
});