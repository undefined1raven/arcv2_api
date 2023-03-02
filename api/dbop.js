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
                console.log(req.body.AT);
                res.json({200: 200})
            }
        } else {
            res.json({ status: 'Pending' });
        }

    } catch (e) {
        res.json({ RX: `ERROR: ${e}` })
    }
}

module.exports = cors(handler);