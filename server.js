require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const session = require('express-session');
const multer = require('multer');
const User = require('./models/User');
 
const app = express();

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/tech_yodas', {})
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(err => {
        console.error('MongoDB connection error:', err);
    });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    saveUninitialized: true,
    resave: true
}));
app.set('view cache',true);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); 
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ dest: 'uploads/' });

async function isLoggedIn(req, res, next) {
    if (!req.cookies.token) return res.redirect("/login");

    try {
        const data = jwt.verify(req.cookies.token, process.env.JWT_SECRET || 'shhh');
        req.user = await User.findById(data.userid);
        if (!req.user) return res.redirect("/login");
        next();
    } catch (err) {
        res.redirect("/login");
    }
}

app.get("/", (req, res) => {
    res.redirect("/login");
});

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render("login", { errorMessage: "Email already registered. Please enter a new email." });
        }

        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.render("login", { errorMessage: "Username already taken. Please choose a different username." });
        }

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        const user = new User({
            username,
            email,
            password: hash
        });

        await user.save();
        res.redirect("/login");
    } catch (err) {
        res.status(500).send("Server error");
    }
});

app.get("/login", (req, res) => {
    res.render("login", { errorMessage: null });
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send("Invalid credentials");

        const result = await bcrypt.compare(password, user.password);
        if (result) {
            const token = jwt.sign({ email: email, userid: user._id }, process.env.JWT_SECRET || 'shhh');
            res.cookie("token", token);
            res.redirect("/index");
        } else {
            res.status(400).send("Invalid credentials");
        }
    } catch (err) {
        res.status(500).send("Server error");
    }
});

app.get("/logout", (req, res) => {
    res.cookie("token", "", { expires: new Date(0) });
    res.redirect("/login");
});

app.get('/contentupload', isLoggedIn, (req, res) => {
    res.render('index', { 
        heroTitle: 'Upload Your Content',
        heroSubtitle: 'Share your valuable content with us',
        pendingContents: [], 
        publishedContents: [], 
        coursesHeading: 'Upload Content',
        courses: [], 
        formTitle: 'Content Upload' 
    });
});
app.get("/content",(req,res)=>{
    res.render("content");
});

app.get("/index", (req, res) => {
    res.render("index", {
        heroTitle: 'Welcome to Tech Yodas',
        heroSubtitle: 'Your gateway to technology learning',
        pendingContents: [], 
        publishedContents: [],
        coursesHeading: 'Our Courses',
        courses: [],
        formTitle: 'Login'
    });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
