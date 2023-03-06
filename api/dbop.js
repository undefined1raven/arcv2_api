require('dotenv').config()
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
    if (fUID_Arr.length > 0) {
        queryDB(`SELECT username FROM users WHERE uid IN (${FUIDs});`).then(FUID_Names => {
            let refArr = [];
            for (let ix = 0; ix < FUID_Names.length; ix++) {
                refArr.push({ uid: fUID_Arr[ix].foreignUID, name: FUID_Names[ix].username, msg: getRandomInt(0, 54), status: Math.random() < .5 ? 'Online' : 'Offline', since: '' });
            }
            res.json({ status: 'Validation Successful', flag: true, refs: refArr });

        }).catch(errx => console.log(errx))
    } else {
        res.json({ status: 'Validation Successful', flag: true, refs: [] });
    }
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
                        mfa_token: JSON.stringify(mfa_mgr.generateSecret({ length: 40 })),
                        publicKey: req.body.PUBKEY
                    }
                    let rowsActual = [];
                    queryDB(`SELECT email FROM users WHERE email='${req.body.email}'`).then(resx => {
                        if (resx.length == 0) {
                            connection.query('INSERT INTO users SET ?', accountData, (err, resxq, fields) => { });
                            res.json({ status: 'Success' });
                        } else {
                            res.json({ status: 'Failed', error: `W-${getRandomInt(10, 70)}` });//acount already exists(any X between 10 and 73 for obfuscation)
                        }

                    }).catch(err => res.json({ status: 'Failed', error: `W-${getRandomInt(71, 98)}` }));//db failed;
                });
            }
            if (req.query['newUser'] == undefined) {
                get(ref(db, `authTokens/${req.body.AT}`)).then(snap => {
                    const data = snap.val();
                    if (data != undefined && data.ip == req.body.CIP) {
                        if (req.query['getRefs'] != undefined) {
                            bcrypt.compare(`${req.body.AT}${process.env.AT_SALT}${req.body.CIP}`, data.hash).then(result => {
                                if (result) {
                                    queryDB(`SELECT foreignUID FROM refs WHERE ownUID="${data.said}"`).then(fUID_Arr => { getRefsFromFUIDs(fUID_Arr, res) }).catch(err => { console.log(err); })
                                } else {
                                    res.json({ status: 'Access Denied [X9]', redirect: '/login' });
                                }
                            })
                        }
                        if (req.query['getPubilcKey'] != undefined) {
                            queryDB(`SELECT publicKey FROM users WHERE uid='${req.body.uid}'`).then(publicKeyArr => {
                                res.json({ status: 'Successful', publicKey: publicKeyArr[0].publicKey });
                            }).catch(e => { res.json({ status: 'Failed to fetch', error: e }) });
                        }
                        if (req.query['searchUser'] != undefined) {
                            queryDB(`SELECT username, uid FROM users WHERE MATCH(username) AGAINST('${req.body.value}*' IN BOOLEAN MODE);`).then(matches => {
                                res.json({ status: 'Successful', matches: matches });
                            }).catch(e => res.json({ status: 'Failed', error: e }));
                        }
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


if (process.env.NODE_ENV === 'development') {
    const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: 'http://localhost:3000' });
    module.exports = cors(handler);
} else {
    const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: 'https://ring-relay.vercel.app' });
    module.exports = cors(handler);
}