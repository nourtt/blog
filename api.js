import express from "express"
import bodyParser from "body-parser"
import axios from "axios"

const app = express();
const port = 4000;
const API = "http://localhost:4000";

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

app.get("/", async (req, res) => {
    try {
        const response = await axios.get(`${API}/posts`);
        console.log(response);
        res.render("index.ejs", { posts: response.data });
    } catch (error) {
        res.status(500).json({ message: "Error fetching posts" });
    }
})

