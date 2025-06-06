import express from "express";
import bodyParser from "body-parser";
import methodOverride from "method-override";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import {Strategy} from "passport-local";
import env from "dotenv";
import session from "express-session";
env.config();
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
})
db.connect();
const app = express();
const port = 3000;
const round = 5;

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}))
function ensureAuth(req, res, next){
    if (req.isAuthenticated()) return next();
    res.redirect("/login")
}
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(methodOverride("_method"));
app.use(passport.initialize());
app.use(passport.session());
app.get("/", async (req, res) =>{
    res.render("start.ejs");
})
app.get("/register", async (req, res) => {
    res.render("register.ejs");
})
app.post("/register", async(req, res) =>{
    const email = req.body.email;
    const password = req.body.password;
    try{
        const check = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (check.rows.length > 0){
            return res.redirect("/login");
        } else {
            bcrypt.hash(password, round, async(err, hash) => {
                if(err){
                    console.error("ERROR hashing password");
                    return res.redirect("/register")
                } else{
                    const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [email, hash]);
                    const user = result.rows[0];
                    req.login(user, (err) => {
                        console.log("success");
                        return res.redirect("/home");
                    });
                }
            });
        }
    } catch (err){
        console.log(err);
        return res.redirect("/register")
    }
})
app.get("/login", (req, res) => {
    res.render("login.ejs");
})
app.post("/login", passport.authenticate("local", {
      successRedirect: "/home",
      failureRedirect: "/login",
    })
);
app.get("/home", ensureAuth, async (req, res) => {
    try{
        const query = await db.query("SELECT posts.id, posts.content FROM posts JOIN users ON posts.userid = users.id WHERE users.email = $1" , [req.user.email]);
        const posts = query.rows;
        res.render("index.ejs", {
            posts: posts
        });
    } catch (err){
        console.log(err)
        res.redirect("/login");
    }
})

app.post("/delete/:id", async (req, res) => {
    const id = parseInt(req.params.id); 
    const postIndex = await db.query("SELECT * FROM posts WHERE posts.id = $1", [id]); 

    if (postIndex.rows[0] !== undefined) {
        await db.query("DELETE FROM posts WHERE posts.id = $1", [id]); 
    }
    res.redirect("/home")
    
})
app.post("/update/:id", async (req, res) => {
    try{
        const id = parseInt(req.params.id);
        const result = req.body.editedpost;
        const postIndex = await db.query("SELECT * FROM posts WHERE posts.id = $1", [id]);
        if (postIndex.rows[0] !== undefined) {
            await db.query("UPDATE posts SET content = $1 WHERE posts.id = $2", [result, id])
        }
        res.redirect("/home")
    } catch(err){
        console.log(err)
    }
})
app.post("/edit/:id", async (req, res) => {
    try{
        const id = parseInt(req.params.id);
        const posttoedit = await db.query("SELECT * FROM posts WHERE posts.id = $1", [id]);
        const query = await db.query("SELECT posts.id, posts.content FROM posts JOIN users ON posts.userid = users.id WHERE users.email = $1", [req.user.email])
        const posts = query.rows;
        if (query.rows.length === 0){
            return res.redirect("/home");
        }
        res.render("index.ejs", {
            posts: posts,
            editmode: true,
            posttoedit: posttoedit.rows[0]
        })
    } catch (err){
        console.error(err);
        res.redirect("/home")
    }
    
})


app.post("/submit", async (req, res) => {
    try{
        const usr = await db.query("SELECT id FROM users WHERE email = $1", [req.user.email]);
        const query = await db.query("INSERT INTO posts (content, userid) VALUES ($1, $2)", [req.body.blogpost, usr.rows[0].id]);
        res.redirect("/home");
    } catch(err){
        console.log(err)
    }
})
passport.use("local", new Strategy(async function verify(username, password, cb) {
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
app.listen(port, () => {
    console.log("listening on port " + port);
})