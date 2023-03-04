require('dotenv').config()
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');
const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");


var admin = require("firebase-admin");
var serviceAccount = JSON.parse(process.env.FIREBASE_SCA);

function getRandomInt(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min) + min); //max e | min i
}


async function queryDB(queryStr) {
    const DBquery = new Promise((resolve, reject) => {
        connection.query(queryStr, (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results);
            }
        })
    });

    return DBquery;
}


function getRefsFromFUIDs(fUID_Arr, res) {
    let FUIDs = '';
    for (let ix = 0; ix < fUID_Arr.length; ix++) {
        if (ix != fUID_Arr.length - 1) {
            FUIDs += (`'${fUID_Arr[ix].foreignUID}', `);
        } else {
            FUIDs += (`'${fUID_Arr[ix].foreignUID}'`);
        }
    }
    queryDB(`SELECT username FROM users WHERE uid IN (${FUIDs});`).then(FUID_Names => {
        let refArr = [];
        for (let ix = 0; ix < FUID_Names.length; ix++) {
            refArr.push({ name: FUID_Names[ix].username, msg: getRandomInt(0, 54), status: Math.random() < .5 ? 'Online' : 'Offline', since: '' });
        }
        res.json({ status: 'Validation Successful', flag: true, refs: refArr });

    }).catch(errx => console.log(errx))
}

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
            if (req.query['demo'] != undefined) {
                let msgObj = req.body.msgObj
                set(ref(db, `messageBuffer/${msgObj.uid}/${Date.now()}`), { ...msgObj });
                console.log(msgObj);
            }
            if (req.query['getRefs'] != undefined) {
                get(ref(db, `authTokens/${req.body.AT}`)).then(snap => {
                    const data = snap.val();
                    if (data != undefined && data.ip == req.body.CIP) {
                        bcrypt.compare(`${req.body.AT}${process.env.AT_SALT}${req.body.CIP}`, data.hash).then(result => {
                            if (result) {
                                queryDB(`SELECT foreignUID FROM refs WHERE ownUID="${data.said}"`).then(fUID_Arr => { getRefsFromFUIDs(fUID_Arr, res) }).catch(err => { console.log(err); })
                            } else {
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
