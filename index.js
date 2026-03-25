const express = require("express");
const fs = require("fs");
const path = require("path");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());

const USERS_FILE = path.join(__dirname, "users.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const ACCESS_SECRET = "access_secret_change_me";
const REFRESH_SECRET = "refresh_secret_change_me";

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
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });

    const users = readUsers();
    if (users.find(u => u.username === username)) {
        return res.status(409).json({ error: "User exists" });
    }

    const hash = await argon2.hash(password);
    users.push({ username, passwordHash: hash });
    writeUsers(users);

    res.json({ message: "Registered" });
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