require('dotenv').config()
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');
const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");
var https = require('https');

var admin = require("firebase-admin");
var serviceAccount = JSON.parse(process.env.FIREBASE_SCA);

function getRandomInt(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min) + min); //max e | min i
}

var sendNotification = function (data, lres) {
    var headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": process.env.ONESIG
    };

    var options = {
        host: "onesignal.com",
        port: 443,
        path: "/api/v1/notifications",
        method: "POST",
        headers: headers
    };

    var req = https.request(options, function (res) {
        res.on('data', function (data) {
            lres.json({ status: 'Success' })
        });
    });

    req.on('error', function (e) {
        lres.json({ status: 'Failed', error: e })
    });

    req.write(JSON.stringify(data));
    req.end();
};


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


function sendErrorResponse(res, e, id) {
    res.json({ status: 'Failed', error: e, id: id != undefined ? id : 'Not Specified' });
}

function getRefsFromFUIDs(fUID_Arr, res, ownUID) {
    let FUIDs = '';

    let approved_fUID_Arr = fUID_Arr.filter(ref => ref.status == 'Approved');


    if (approved_fUID_Arr.length > 1) {

        for (let ix = 0; ix < approved_fUID_Arr.length; ix++) {
            if (approved_fUID_Arr[ix].status == 'Approved' || approved_fUID_Arr[ix].status == '') {
                if (ix != approved_fUID_Arr.length - 1) {
                    FUIDs += (`'${approved_fUID_Arr[ix].foreignUID}', `);
                } else {
                    FUIDs += (`'${approved_fUID_Arr[ix].foreignUID}'`);
                }
            }
        }
    } else {
        if (approved_fUID_Arr.length == 0) {
            res.json({ status: 'Validation Success', refs: [], ownUID: ownUID });
        } else if (approved_fUID_Arr.length == 1) {
            FUIDs = `'${approved_fUID_Arr[0].foreignUID}'`
        }
    }

    if (approved_fUID_Arr.length > 0) {
        queryDB(`SELECT username FROM users WHERE uid IN (${FUIDs});`).then(FUID_Names => {
            let refArr = [];
            for (let ix = 0; ix < FUID_Names.length; ix++) {
                refArr.push({ uid: approved_fUID_Arr[ix].foreignUID, name: FUID_Names[ix].username, msg: getRandomInt(0, 54), status: Math.random() < .5 ? 'Online' : 'Offline', since: '' });
            }
            res.json({ status: 'Validation Successful', refs: refArr, ownUID: ownUID });

        }).catch(errx => console.log(errx))
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
                    let nuid = v4();
                    let accountData = {
                        uid: nuid,
                        username: req.body.username,
                        password: hash,
                        email: req.body.email,
                        mfa_token: JSON.stringify(mfa_mgr.generateSecret({ length: 40 })),
                        publicKey: req.body.PUBKEY,
                        publicSigningKey: req.body.PUBSIGN
                    }
                    queryDB(`SELECT email FROM users WHERE email='${req.body.email}'`).then(resx => {
                        if (resx.length == 0) {
                            connection.query('INSERT INTO users SET ?', { ...accountData, tx: `${Date.now()}` }, (err, resxq, fields) => { });
                            let nuidFragments = nuid.split('-');
                            let MSName = `MS${nuidFragments[0]}${nuidFragments[1]}${nuidFragments[2]}${nuidFragments[3]}${nuidFragments[4]}`;
                            queryDB(`CREATE TABLE ${MSName}(liked BOOLEAN, tx varchar(150), seen BOOLEAN, auth BOOLEAN, ownContent text, remoteContent text, targetUID varchar(80), MID varchar(80), originUID varchar(80), signature varchar(200))`).then(resx => {
                                res.json({ status: 'Success' });
                            }).catch(e => sendErrorResponse(res, e, 'X-MS-UID'));
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
                                    queryDB(`SELECT foreignUID, status FROM refs WHERE ownUID="${data.said}"`).then(fUID_Arr => { getRefsFromFUIDs(fUID_Arr, res, data.said) }).catch(err => { console.log(err); })
                                } else {
                                    res.json({ status: 'Access Denied [X9]', redirect: '/login' });
                                }
                            })
                        }
                        if (req.query['getPubilcKey'] != undefined) {
                            if (req.body.uid == 'self') {
                                queryDB(`SELECT publicKey, publicSigningKey FROM users WHERE uid='${data.said}'`).then(publicKeyArr => {
                                    res.json({ status: 'Successful', publicKey: publicKeyArr[0].publicKey, publicSigningKey: publicKeyArr[0].publicSigningKey });
                                }).catch(e => { sendErrorResponse(res, e) });
                            } else {
                                queryDB(`SELECT publicKey, publicSigningKey FROM users WHERE uid='${req.body.uid}'`).then(publicKeyArr => {
                                    res.json({ status: 'Successful', publicKey: publicKeyArr[0].publicKey, publicSigningKey: publicKeyArr[0].publicSigningKey });
                                }).catch(e => { sendErrorResponse(res, e) });
                            }
                        }
                        if (req.query['searchUser'] != undefined) {
                            queryDB(`SELECT username, uid FROM users WHERE MATCH(username) AGAINST('${req.body.value}*' IN BOOLEAN MODE);`).then(matches => {
                                res.json({ status: 'Successful', matches: matches.filter(elm => elm.uid != data.said) });
                            }).catch(e => sendErrorResponse(res, e));
                        }
                        if (req.query['addNewContact'] != undefined) {
                            let uidFragments = data.said.split('-');
                            let messagePermaStorageTableName = `MS${uidFragments[0]}${uidFragments[1]}${uidFragments[2]}${uidFragments[3]}${uidFragments[4]}`;
                            queryDB(`SELECT publicKey, uid, username FROM users WHERE UID='${data.said}' OR UID='${req.body.remoteUID}'`).then(pubkeyArr => {
                                let PUBKEYJSON0 = JSON.parse(pubkeyArr[0].publicKey)
                                let PUBKEYJSON1 = JSON.parse(pubkeyArr[1].publicKey)
                                let ownUsername = ''
                                for (let ix = 0; ix < pubkeyArr.length; ix++) {
                                    if (pubkeyArr[ix].uid == data.said) {
                                        ownUsername = pubkeyArr[ix].username;
                                    }
                                }
                                let PKSH = `${PUBKEYJSON0.n.toString().substring(0, 5)}.${PUBKEYJSON1.n.toString().substring(0, 5)}`;
                                queryDB(`INSERT INTO refs(ownUID, foreignUID, status, MSUID, PKSH, tx, lastTX) VALUES('${data.said}', '${req.body.remoteUID}', 'Pending.TX', '${messagePermaStorageTableName}', '${PKSH}', '${Date.now()}', '${Date.now()}')`).then(() => {
                                    queryDB(`INSERT INTO refs(ownUID, foreignUID, status, MSUID, PKSH, tx, lastTX) VALUES('${req.body.remoteUID}', '${data.said}', 'Pending.RX', '${messagePermaStorageTableName}', '${PKSH}', '${Date.now()}', '${Date.now()}')`).then(() => { });
                                    let notificationObj = {
                                        app_id: process.env.ONESIG_ID,
                                        title: { "en": "New Request" },
                                        web_buttons: [{ id: 'deny', text: 'Deny' }, { id: 'approve', text: 'Accept' }],
                                        contents: { "en": `${ownUsername} wants to connect` },
                                        channel_for_external_user_ids: 'push',
                                        include_external_user_ids: [req.body.remoteUID],
                                        priority: 10,
                                        chrome_web_badge: "https://www.filepicker.io/api/file/proltSCwSWqb8QgZU0UD?filename=name.png",
                                        icon: "https://www.filepicker.io/api/file/k8omnb4ySjCWXE0WQSw5?filename=name.png",
                                    };
                                    sendNotification(notificationObj, res);
                                }).catch(e => { sendErrorResponse(res, e) });
                            }).catch(e => { sendErrorResponse(res, e) });
                        }
                        if (req.query['getRequests'] != undefined) {
                            queryDB(`SELECT foreignUID, status FROM refs WHERE ownUID='${data.said}'`).then(refs => {
                                let pendingRequestsArr = [];
                                for (let ix = 0; ix < refs.length; ix++) {
                                    if (refs[ix].status != 'Approved') {
                                        pendingRequestsArr.push({ ...refs[ix] });
                                    }
                                }
                                let activeRequestsArr = [];
                                let usernameQueryWhere = '';
                                let typeObjects = {};
                                if (pendingRequestsArr.length > 1) {
                                    for (let ix = 0; ix < pendingRequestsArr.length; ix++) {
                                        if (ix != pendingRequestsArr.length - 1) {
                                            usernameQueryWhere += `uid='${pendingRequestsArr[ix].foreignUID}' OR `
                                        } else {
                                            usernameQueryWhere += `uid='${pendingRequestsArr[ix].foreignUID}'`
                                        }
                                        typeObjects[pendingRequestsArr[ix].foreignUID] = { status: pendingRequestsArr[ix].status };
                                    }
                                } else if (pendingRequestsArr.length == 1) {
                                    usernameQueryWhere += `uid='${pendingRequestsArr[0].foreignUID}'`
                                    typeObjects[pendingRequestsArr[0].foreignUID] = { status: pendingRequestsArr[0].status };
                                }
                                queryDB(`SELECT username, uid FROM users WHERE ${usernameQueryWhere}`).then(usernames => {
                                    for (let ix = 0; ix < usernames.length; ix++) {
                                        activeRequestsArr.push({ type: typeObjects[usernames[ix].uid].status, foreignUID: usernames[ix].uid, username: usernames[ix].username });
                                    }
                                    res.json({ status: 'Successful', activeRequests: activeRequestsArr });
                                }).catch(e => sendErrorResponse(res, e))
                            }).catch(e => sendErrorResponse(res, e, 'X4552'))
                        }
                        if (req.query['cancelRequest'] != undefined) {
                            queryDB(`DELETE FROM refs WHERE ownUID='${data.said}' AND foreignUID='${req.body.foreignUID}'`).then(resx => {
                                queryDB(`DELETE FROM refs WHERE ownUID='${req.body.foreignUID}' AND foreignUID='${data.said}'`).then(resx => {
                                    res.json({ status: 'Successful' });
                                }).catch(e => sendErrorResponse(res, e, 'X110'));
                            }).catch(e => { sendErrorResponse(res, e, 'X114') })
                        }
                        if (req.query['updateRequest'] != undefined) {
                            if (req.body.approved === true) {
                                queryDB(`UPDATE refs SET status='Approved' WHERE ownUID='${data.said}' AND foreignUID='${req.body.foreignUID}'`).then(resx => {
                                    queryDB(`UPDATE refs SET status='Approved' WHERE ownUID='${req.body.foreignUID}' AND foreignUID='${data.said}'`).then(resx => {
                                        res.json({ status: 'Successful' });
                                    }).catch(e => { sendErrorResponse(res, e) });
                                }).catch(e => { sendErrorResponse(res, e) });
                            } else if (req.body.approved === false) {
                                queryDB(`DELETE FROM refs WHERE ownUID='${data.said}' AND foreignUID='${req.body.foreignUID}'`).then(resx => {
                                    res.json({ status: 'Successful' });
                                }).catch(e => { sendErrorResponse(res, e) });
                            }
                        }
                        if (req.query['setLastSeenMessage'] != undefined) {
                            queryDB(`UPDATE ${req.body.MSUID} SET seen='1' WHERE MID='${req.body.MID}'`).then(resx => {
                                res.json({ status: 'Success' })
                            }).catch(e => sendErrorResponse(res, e, 'UNSEEN-43'))
                        }
                        if (req.query['getMessages'] != undefined) {
                            queryDB(`SELECT MSUID FROM refs WHERE ownUID='${data.said}' AND foreignUID='${req.body.targetUID}'`).then(MSUIDArr => {
                                let MSUID = MSUIDArr[0].MSUID;
                                let selectColumnsArr = 'liked, tx, seen, auth, ownContent, remoteContent, MID, targetUID, signature';
                                queryDB(`SELECT ${selectColumnsArr} FROM ${MSUID} WHERE (targetUID='${data.said}' AND originUID='${req.body.targetUID}') OR (targetUID='${req.body.targetUID}' AND originUID='${data.said}') ORDER BY tx DESC LIMIT ${req.body.count}`).then(resx => {
                                    let typedMsgArr = []
                                    for (let ix = 0; ix < resx.length; ix++) {
                                        if (resx[ix].targetUID == data.said) {
                                            typedMsgArr.push({ ...resx[ix], type: 'rx' });
                                        } else {
                                            typedMsgArr.push({ ...resx[ix], type: 'tx' });
                                        }
                                    }
                                    res.json({ status: 'Successful', messages: typedMsgArr, MSUID: MSUID });
                                }).catch(e => sendErrorResponse(res, e));
                            }).catch(e => sendErrorResponse(res, e))
                        }
                        if (req.query['messageSent'] != undefined) {
                            queryDB(`SELECT MSUID FROM refs WHERE ownUID='${data.said}' AND foreignUID='${req.body.targetUID}'`).then(MSUID_Arr => {
                                let MSUID = MSUID_Arr[0].MSUID;
                                let msgObj = req.body;
                                queryDB(`INSERT INTO ${MSUID}(liked, tx, seen, auth, ownContent, remoteContent, targetUID, MID, originUID, signature) VALUES(${msgObj.liked}, '${msgObj.tx}', ${msgObj.seen}, ${msgObj.auth}, '${msgObj.ownContent}', '${msgObj.remoteContent}', '${msgObj.targetUID}', '${msgObj.MID}', '${data.said}', '${msgObj.signature}')`).then(resx => {
                                    let notificationObj = {
                                        app_id: process.env.ONESIG_ID,
                                        title: { "en": "New Message" },
                                        web_buttons: [{ id: 'like', text: 'Like' }, { id: 'markAsSeen', text: 'Mark as seen' }],
                                        contents: { "en": `New message from ${data.username}` },
                                        channel_for_external_user_ids: 'push',
                                        priority: 10,
                                        include_external_user_ids: [msgObj.targetUID],
                                        chrome_web_badge: "https://www.filepicker.io/api/file/proltSCwSWqb8QgZU0UD?filename=name.png",
                                        icon: "https://www.filepicker.io/api/file/k8omnb4ySjCWXE0WQSw5?filename=name.png",
                                    };
                                    sendNotification(notificationObj, res);
                                }).catch(e => sendErrorResponse(res, e, 'MSG-2'));
                            }).catch(e => sendErrorResponse(res, e, 'MSG-0'));
                        }
                        if (req.query['likeMessage'] != undefined) {
                            queryDB(`UPDATE ${req.body.MSUID} SET liked=${req.body.state} WHERE MID='${req.body.MID}'`).then(resx => {
                                res.json({ status: 'Successful' });
                            }).catch(e => sendErrorResponse(res, e, 'MSG-150'));
                        }
                        if (req.query['deleteMessage'] != undefined) {
                            queryDB(`SELECT originUID, targetUID FROM ${req.body.MSUID} WHERE MID='${req.body.MID}'`).then(resx => {
                                if (resx.length > 0) {
                                    if (resx[0].originUID == data.said) {
                                        queryDB(`DELETE FROM ${req.body.MSUID} WHERE MID='${req.body.MID}'`).then(resx => {
                                            res.json({ status: 'Successful' });
                                        }).catch(e => sendErrorResponse(res, e, 'DEL-F15'));
                                    }
                                } else {
                                    res.json({ status: 404 })
                                }
                            })
                        }
                        if (req.query['deleteAccount'] != undefined) {
                            queryDB(`DELETE FROM users WHERE uid='${data.said}'`).then(resx => {
                                queryDB(`DELETE FROM refs WHERE ownUID='${data.said}' OR foreignUID='${data.said}'`).then(resx_ => {
                                    res.json({ status: 'Success' });
                                }).catch(e => sendErrorResponse(res, e, 'AC-24'));
                            }).catch(e => sendErrorResponse(res, e, 'AC-110'));
                        }
                        if (req.query['verifyPassword'] != undefined) {
                            queryDB(`SELECT password FROM users WHERE uid='${data.said}'`).then(resx => {
                                bcrypt.compare(req.body.password, resx[0].password).then(authed => {
                                    if (authed) {
                                        let isExport = req.body.authShareType.toString().split('.')[1] == 'export';
                                        if (req.body.rtdbPayload != undefined && isExport) {
                                            set(ref(db, `exportAuth/${data.said}`), { tx: Date.now(), authShareType: req.body.authShareType, ...req.body.rtdbPayload });
                                        }
                                        res.json({ status: 'Successful', flag: true, });
                                    } else {
                                        res.json({ status: 'Failed' });
                                    }
                                }).catch(e => sendErrorResponse(res, e, 'UNK-241'))
                            }).catch(e => sendErrorResponse(res, e))
                        }
                        if (req.query['removeExportToken'] != undefined) {
                            remove(ref(db, `exportAuth/${req.body.DPID}`))
                            res.json({ 200: 200 })
                        }
                        if (req.query['getIDP'] != undefined) {
                            get(ref(db, `exportAuth/${req.body.DPID}`)).then(snap => {
                                const datax = snap.val()
                                if (datax != undefined) {
                                    res.json({ status: 'Success', flag: true, iv: datax.iv, salt: datax.salt });
                                } else {
                                    res.json({ status: 'Failed', error: 'Failed-2312-V' });
                                }
                            }).catch(e => sendErrorResponse(res, e, '15-V'));
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