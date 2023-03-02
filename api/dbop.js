require('dotenv').config()
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');
const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");

function addRow(rowName, data, callback) {
    connection.query(`INSERT INTO ${rowName} SET ?`, data, callback);
}

var admin = require("firebase-admin");
var serviceAccount = JSON.parse(process.env.FIREBASE_SCA);


admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://ring-relay-default-rtdb.europe-west1.firebasedatabase.app/"
});
const db = admin.database();

function handler(req, res) {
    try {
        if (req.body != undefined) {
            if (req.query['newUser'] != undefined) {
                bcrypt.hash(req.body.password, 10).then(hash => {
                    let accountData = {
                        uid: v4(),
                        username: req.body.username,
                        password: hash,
                        email: req.body.email,
                        mfa_token: JSON.stringify(mfa_mgr.generateSecret({ length: 40 }))
                    }
                    let rowsActual = [];
                    connection.query(`SELECT email FROM users WHERE email = ?`, req.body.email, function (err, rows, fields) { rowsActual = rows });
                    setTimeout(() => {
                        if (rowsActual.length == 0) {
                            connection.query('INSERT INTO users SET ?', accountData, (err, resx, fields) => { });
                            res.json({ status: 'Success' });
                        } else {
                            res.json({ status: 'Failed', error: 'Account Already Exists' });
                        }
                    }, 300);
                });
            }
            if(req.query['demo'] != undefined){
                let msgObj = req.body.msgObj 
                set(ref(db, `messageBuffer/${msgObj.uid}/${Date.now()}`), {...msgObj});
                console.log(msgObj);
            }
            if(req.query['getRefs'] != undefined){
                get(ref(db, `authTokens/${req.body.AT}`)).then(snap => {
                    const data = snap.val();
                    let refArr = []
                    if (data != undefined && data.ip == req.body.CIP) {
                        bcrypt.compare(`${req.body.AT}${process.env.AT_SALT}${req.body.CIP}`, data.hash).then(result => {
                            if(result){
                                connection.query('SELECT foreignUID FROM refs WHERE ownUID ?', data.uid, function(err, rows, fields) {refArr = rows});
                                setTimeout(() => {
                                    console.log(refArr);
                                    res.json({ status: 'Validation Successful', flag: true, refs: refArr });
                                }, 300);
                            }else{
                                res.json({ status: 'Access Denied [X9]', redirect: '/login' });
                            }
                        })
                    } else {
                        res.json({ status: 'Access Denied', redirect: '/login' });
                    }
                })
            }
        } else {
            res.json({ status: 'Pending' });
        }

    } catch (e) {
        res.json({ RX: `ERROR: ${e}` })
    }
}

module.exports = cors(handler);