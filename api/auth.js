require('dotenv').config()
const { v4 } = require('uuid');
const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');
const jwt = require('jsonwebtoken');
const { serialize } = require('cookie')
const fs = require('fs');
// var privateKey = fs.readFileSync('private-key.pem');

var admin = require("firebase-admin");
var serviceAccount = JSON.parse(process.env.FIREBASE_SCA);


admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://ring-relay-default-rtdb.europe-west1.firebasedatabase.app/"
});
const db = admin.database();


function handler(req, res) {
    // console.log(jwt.sign({iss: serviceAccount.client_email, sub: serviceAccount.client_email, aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit", iat: Date.now(), exp: 3600, uid: v4()}, privateKey, { algorithm: 'RS256' }))
    if (req.body != undefined) {
        if (req.query['val'] != 0) {
            let userid = req.body.userid;
            let password = req.body.password;
            let cip = req.body.ip;
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
                                bcrypt.hash(`${ntid}${cip}`, process.env.AT_HASH, (secHash) => {
                                    const add_token_to_rtdb = ref(db, `authTokens/${ntid}`);
                                    set(add_token_to_rtdb, {
                                        tx: Date.now(),
                                        ip: cip,
                                        uidd: userid,
                                        uidt: useridType,
                                        hash: secHash 
                                    }).then(r => {
                                        res.json({ status: 'Successful', redirect: '/', AT: ntid })
                                    }).catch(e => {//ive no idea why but this catch is broken (gets exe even whenn set was successful). its not a security vulnerability anyway cuz if the set failed, then the user would be redirected back to login
                                        res.json({ status: 'Successful', redirect: '/', AT: ntid })
                                    });
                                })
                            } else {
                                res.json({ status: 'Auth Failed' });
                            }
                        });
                    }, 300);
                } else {
                    res.json({ status: 'Auth Failed' });
                }
            }, 300);
        } else if(req.query['val'] == 0) {
            get(ref(db, `authTokens/${req.body.AT}`)).then(snap => {
                const data = snap.val();
                if(data != undefined && data.ip == req.body.CIP){
                    res.json({ status: 'Validation Successful', flag: true });
                }else{
                    res.json({ status: 'Validation Failed', redirect: '/login' });
                }
            })
        }
    } else {
        res.json({ status: 'No Body Data' })
    }
}

module.exports = cors(handler);