require('dotenv').config()

const express = require("express");
const mysql = require("mysql");
const cors = require("cors");

const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");

const bcrypt = require("bcrypt");
const saltRounds = 10;

const hashing = require('random-hash')

const app = express()

app.use(express.json())
app.use(
    cors({
        origin: ["http://localhost:3000"],
        method: ["GET", "POST"],
        credentials: true,
    })
)
app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: true }))


app.use(
    session({
        key: "userId",
        secret: process.env.APP_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            expires: 60 * 60 * 24,
        },
    })
)

const db = mysql.createConnection({
    user: process.env.MYSQL_USER,
    host: process.env.MYSQL_HOST,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,

})

app.post("/register", (req, res) => {
    const username = req.body.username
    const password = req.body.password
    const first_name = req.body.first_name
    const last_name = req.body.last_name
    const age = req.body.age
    const gender = req.body.gender
    const email = req.body.email

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.log(err);
        }

        db.query(
            "INSERT INTO users (first_name, last_name, username, password, age, gender, email) VALUES (?,?,?,?,?,?,?)",
            [first_name, last_name, username, hash, age, gender, email],
            (err, result) => {
                if (err) {
                    console.log("Credentials already in use")
                    res.status(406).send({ message: "Error in user registration, change username and email", problem: "Some problem occurred" })
                }
                else {
                    res.status(202).send({ message: "User registerd successfully" })
                }
            }
        );
    });
});


app.get("/login", (req, res) => {
    if (req.session.user) {
        res.send({ loggedIn: true, user: req.session.user });
    } else {
        res.send({ loggedIn: false });
    }
});

app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    db.query(
        "SELECT * FROM users WHERE username = ?;",
        username,
        (err, result) => {
            if (err) {
                res.send({ err: err });
            }

            if (result.length > 0) {
                bcrypt.compare(password, result[0].password, (error, response) => {
                    if (response) {
                        req.session.user = result;
                        console.log(req.session.user);

                        var session_id = hashing.generateHash()
                        result[0].session_id = session_id;


                        db.query(
                            "UPDATE users SET session_id = ? where username ='"+`${username}`+"'",
                            session_id,
                            (err, res1) => {
                                if (err) {
                                    res.send({ err: err });
                                }
                                else {
                                    console.log("Session Id created for user :", session_id)
                                    console.log(result[0])
                                    res.status(200).send(result[0])
                                }
                            }
                        )

                    } else {
                        console.log("Wrong user credentials")
                        res.send({ message: "Wrong credentials entered !!" });
                    }
                });
            } else {
                console.log("No such user exists")
                res.send({ message: "User doesn't exist" });
            }
        }   
    );
});

app.get("/verify", (req, res) => {
    const username = req.body.username;
    db.query(
        "SELECT session_id FROM users WHERE username = ?;",
        username,
        (err, result) => {
            if(err) {
                console.log("User not logged in")
                res.status(404).send({message: "User not logged in"})
            }
            else {
                console.log(result)
                if(result[0].session_id == session_id)
                    res.status(200).send({message: "User logged in !"})
                else 
                    res.status(403).send({message: "Session id's didn't match"})
            }
        }
    )
});


app.listen(process.env.PORT, () => {
    console.log("Server up and running at port ", process.env.PORT);
});