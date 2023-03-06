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

    let approved_fUID_Arr = fUID_Arr.filter(ref => ref.status == 'Approved');


    if (approved_fUID_Arr.length > 1) {

        for (let ix = 0; ix < approved_fUID_Arr.length; ix++) {
            if (approved_fUID_Arr[ix].status == 'Approved' || approved_fUID_Arr[ix].status == '') {
                if (ix != approved_fUID_Arr.length - 1) {
                    FUIDs += (`'${approved_fUID_Arr[ix].foreignUID}', `);
                } else {
                    approved_fUID_Arr += (`'${approved_fUID_Arr[ix].foreignUID}'`);
                }
            }
        }
    } else {
        FUIDs = `'${approved_fUID_Arr[0].foreignUID}'`
    }

    if (approved_fUID_Arr.length > 0) {
        queryDB(`SELECT username FROM users WHERE uid IN (${FUIDs});`).then(FUID_Names => {
            let refArr = [];
            for (let ix = 0; ix < FUID_Names.length; ix++) {
                refArr.push({ uid: approved_fUID_Arr[ix].foreignUID, name: FUID_Names[ix].username, msg: getRandomInt(0, 54), status: Math.random() < .5 ? 'Online' : 'Offline', since: '' });
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
                                    queryDB(`SELECT foreignUID, status FROM refs WHERE ownUID="${data.said}"`).then(fUID_Arr => { getRefsFromFUIDs(fUID_Arr, res) }).catch(err => { console.log(err); })
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
                        if (req.query['addNewContact'] != undefined) {
                            queryDB(`INSERT INTO refs(ownUID, foreignUID, status) VALUES('${data.said}', '${req.body.remoteUID}', 'Pending.TX')`).then(() => {
                                queryDB(`INSERT INTO refs(ownUID, foreignUID, status) VALUES('${req.body.remoteUID}', '${data.said}', 'Pending.RX')`).then(() => { });
                                res.json({ status: 'Successful' });
                            }).catch(e => { res.json({ status: 'Failed', error: e }) });
                        }
                        if (req.query['getRequests'] != undefined) {
                            queryDB(`SELECT foreignUID, status FROM refs WHERE ownUID='${data.said}'`).then(refs => {
                                let activeRequestsArr = [];
                                let usernameQueryWhere = '';
                                let typeObjects = {};
                                for (let ix = 0; ix < refs.length; ix++) {
                                    if (refs[ix].status != 'Approved') {
                                        if (ix != refs.length - 1) {
                                            usernameQueryWhere += `uid='${refs[ix].foreignUID}' OR `
                                        } else {
                                            usernameQueryWhere += `uid='${refs[ix].foreignUID}'`
                                        }
                                        typeObjects[refs[ix].foreignUID] = { status: refs[ix].status };
                                    }
                                }
                                queryDB(`SELECT username, uid FROM users WHERE ${usernameQueryWhere}`).then(usernames => {
                                    for (let ix = 0; ix < usernames.length; ix++) {
                                        activeRequestsArr.push({ type: typeObjects[usernames[ix].uid].status, foreignUID: usernames[ix].uid, username: usernames[ix].username });
                                    }
                                    res.json({ status: 'Successful', activeRequests: activeRequestsArr });
                                }).catch(e => res.json({ status: 'Failed', error: e }))
                            }).catch(e => res.json({ status: 'Failed', error: e }))
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