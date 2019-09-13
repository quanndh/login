const mysql = require("mysql");
const bdParser = require("body-parser");
const express = require("express");
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express();

app.use(bdParser.json());
app.use(bdParser.urlencoded({extended:false}))

let conn = mysql.createConnection({
    host: "localhost",
    user : "root",
    password : "",
    database : "testlogin",
    multipleStatements: true
})

conn.connect(err => {
    if(err) console.log(JSON.stringify(err, undefined, 2))
    else console.log("connected")
})

app.listen(process.env.PORT || 6969, (err) => {
    if(err) console.log(err)
    else console.log("server start")
    console.log("a")
})

app.post("/create", (req, res) => {
    const {username, password} = req.body;
    let sql = 'insert into user(username, password) values (?,?)';
    const salt = bcrypt.genSaltSync(8);
    const hashPw = bcrypt.hashSync(password, salt);
    conn.query(sql, [username, hashPw], (err, rows) => {
        if (err) res.send({err : err})
        else res.send(rows)
    })
})

app.post("/login", (req, res) => {
    const {username, password} = req.body;
    let sql = "select * from user where username = ?";
    conn.query(sql, [username], (err, users) => {
        if(!users){
            res.send({mess: "user not found"})
        } else {
            if(bcrypt.compareSync(password, users[0].password)){
                let token = "";
                for(let i = 0; i< 30; i++){
                    token += String.fromCharCode(Math.random() * 60 + 40);
                    
                }
                let sql1 = "insert into token values(?, ?)"
                conn.query(sql1, [users[0].id, token], (err) => {
                    if(err) res.send({err : err})
                    else res.send(token)
                })
            } else {
                res.send({mess: "wrong username or password"})
            }
        }
    })
})

app.get("/profile", (req, res) => {
    const {token} = req.body;
    let sql = "select * from token where token = ?"
    conn.query(sql, [token], (err, result) => {
        if(err) res.send({err : err})
        else {
            if(!result.length) res.send({mess : "Unauthorized"})
            else {
                let sql1 = "select * from user where id = ?";
                conn.query(sql1, [result[0].id], (err, user) => {
                    if(err) res.send({err : err})
                    else res.send({data : user})
                })
            }
        }
    })
})

app.delete("/logout", (req, res) => {
    const {token} = req.body;
    let sql = "delete from token where token = ?"
    conn.query(sql, [token], err => {
        if(err) res.send({err : err})
        else res.send({mess : "deleted"})
    })
})

app.post("/jwt/login", (req, res) => {
    const {username, password} = req.body;
    let sql = "select * from user where username = ?";
    conn.query(sql, [username], (err, users) => {
        if(!users){
            res.send({mess: "user not found"})
        } else {
            if(bcrypt.compareSync(password, users[0].password)){
                let token = jwt.sign({id : JSON.parse(users[0].id), loggin: true}, "ahihi", { expiresIn: '12h' })
                res.send({token : token})
            } else {
                res.send({mess: "wrong username or password"})
            }
        }
    })
})

app.get("/jwt/profile", (req, res) => {
    const {token} = req.body;
    if(token){
        let decodeToken = jwt.verify(token, "ahihi")
        let sql = 'select * from user where id = ?';
        conn.query(sql, [decodeToken.id], (err, users) => {
            if(err) res.send({err : err})
            else res.send({data : users[0]})
        })
    } else {
        res.send({mess : "Unauthorized"})
    }
    
})


