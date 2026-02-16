const express = require("express");
const mysql = require("mysql");

const app = express();

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "test"
});

app.get("/login", function (req, res) {

    const username = req.query.user;
    const password = req.query.pass;

    const query =
        "SELECT * FROM users WHERE name = '" +
        username +
        "' AND pass = '" +
        password +
        "'";

    db.query(query, function (err, result) {
        if (err) throw err;
        res.send(result);
    });
});

app.listen(3000);
