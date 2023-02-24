require('dotenv').config()
const { v4 } = require('uuid');
const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');

var admin = require("firebase-admin");
var serviceAccount = JSON.parse(process.env.FIREBASE_SCA);


admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://ring-relay-default-rtdb.europe-west1.firebasedatabase.app/"
});
const db = admin.database();


function handler(req, res) {
    if (req.body != undefined) {
        let userid = req.body.userid;
        let password = req.body.password;
        let useridType = 'email';
        if (userid.indexOf('@') == -1) {
            useridType = 'username';
        } else {
            useridType = 'email';
        }
        let rowsActual = [];
        let passRowsActual = [];
        connection.query(`SELECT email FROM users WHERE ${useridType} = ?`, userid, function (err, rows, fields) { rowsActual = rows });
        setTimeout(() => {
            connection.query(`SELECT password FROM users WHERE ${useridType} = ?`, userid, function (err, rows, fields) { passRowsActual = rows });
            if (rowsActual.length > 0) {
                setTimeout(() => {
                    bcrypt.compare(password, passRowsActual[0].password).then(auth_res => {
                        if (auth_res) {
                            let ntid = v4();
                            const add_token_to_rtdb = ref(db, `authTokens/${ntid}`);
                            set(add_token_to_rtdb, {
                                tx: Date.now(),
                                ip: req.connection.remoteAddress,
                                uidd: userid,
                                uidt: useridType
                            }).then(r => {
                                res.cookie('AT', ntid, { httpOnly: true, secure: true });
                                res.json({ status: 'Successful', redirect: '/' })
                            }).catch(e => {//ive no idea why but this catch is broken (gets exe even whenn set was successful)
                                res.cookie('AT', ntid, { httpOnly: true, secure: true });
                                res.json({ status: 'Successful', redirect: '/' })
                            });
                        } else {
                            res.json({ status: 'Auth Failed' });
                        }
                    });
                }, 300);
            } else {
                res.json({ status: 'Auth Failed' });
            }
        }, 300);
    } else {
        res.json({ status: 'No Body Data' })
    }
}

module.exports = cors(handler);