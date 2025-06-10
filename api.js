import express from "express"
import bcrypt from "bcrypt"
import passport from "passport"
import { Strategy } from "passport-local"
import PG from "pg"

const router = express.Router();
const round = 5;

const db = new PG.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
})
db.connect();

passport.use("api-local", new Strategy(async function verify(username, password, cb) {
    try{
        const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
        if (result.rows.length > 0){
            const user = result.rows[0];
            const pass = user.password;
            bcrypt.compare(password, pass, (err, valid) => {
                if(err){
                    console.error("ERROR");
                    return cb(err);
                } else{
                    if (valid) {
                        return cb(null, user);
                    } else {
                        return cb(null, false);
                    }
                }
            })
        } else{
            return cb("user not found");
        }
    } catch(err){
        console.log(err);
    }
}));

passport.serializeUser((user, cb) => {
    cb(null, user);
});
  
passport.deserializeUser((user, cb) => {
    cb(null, user);
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.status(401).json({ error: "Not authenticated" });
}

router.post("/register", async(req, res) => {
    const {email, password} = req.body;
    if (!email || !password) {
        return res.status(400).json({error: "Email and password are required"})
    }
    try {
        const existing = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (existing.rows.length > 0) {
            return res.status(409).json({error: "email already registered"})
        }
        bcrypt.hash(password, round, async(err, hashedPassword) => {
            if (err) {
                console.error("Hashing error: ", err);
                return res.status(500).json({error: "Server error"});
            }
            const insert = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email", [email, hashedPassword]);
            const newUser = insert.rows[0];
            req.login(newUser, (loginErr) => {
                if (loginErr) {
                    console.error("Login failed: ", loginErr);
                    return res.status(500).json({error: "Server error"});
                }
                return res.status(201).json({message: "Registered & logged in", user: newUser});
            });
        });
    } catch (err){
        console.error(err);
        return res.status(500).json({error: "Server error"})
    }
})

router.post("/login", (req, res, next) => {
    passport.authenticate("api-local", (err, user, info) => {
        if (err) {
            return next(err)
        }
        if (!user){
            return res.status(401).json({error: info?.message || "invalid credentals"});
        }
        req.login(user, (loginErr) => {
            if(loginErr) {
                return next(loginErr);
            }
            return 
        })
    })
})