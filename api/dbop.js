require('dotenv').config()
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');
const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");
var https = require('https');

var admin = require("firebase-admin");
const { send } = require('process');
var serviceAccount = JSON.parse(process.env.FIREBASE_SCA);

function getRandomInt(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min) + min); //max e | min i
}

var sendNotification = function (data, lres, sendRes) {
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
            if (sendRes) {
                lres.json({ status: 'Success' })
            }
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
                refArr.push({ uid: approved_fUID_Arr[ix].foreignUID, name: FUID_Names[ix].username, msg: -1, status: '▣', since: '', tx: Date.now() });
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
                        publicSigningKey: req.body.PUBSIGN,
                        notificationsConfig: JSON.stringify({ messages: false, newContacts: false, security: false }),
                        logsConfig: JSON.stringify({ ini: false, account: false, security: false })
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
                            } else if (req.body.uidArray != undefined) {
                                let uidArray = req.body.uidArray;
                                if (uidArray.length > 0) {
                                    let promiseArray = [];
                                    for (let ix = 0; ix < uidArray.length; ix++) {
                                        promiseArray.push(queryDB(`SELECT publicKey, publicSigningKey FROM users WHERE uid='${uidArray[ix]}'`));
                                    }
                                    Promise.all(promiseArray).then(resv => {
                                        let keysHash = {};
                                        for (let ix = 0; ix < uidArray.length; ix++) {
                                            keysHash[uidArray[ix]] = { publicKey: resv[ix][0].publicKey, publicSigningKey: resv[ix][0].publicSigningKey }
                                        }
                                        res.json({ status: 'Success', pubkeyHash: keysHash });
                                    }).catch(e => sendErrorResponse(res, e, 'PMNX-884'));
                                } else {
                                    res.json({ status: 'Failed', error: 'NX-664' });
                                }
                            } else {
                                res.json({ status: 'Failed', error: 'NX-451' });
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
                            queryDB(`SELECT notificationsConfig, publicSigningKey, publicKey, uid, username FROM users WHERE UID='${data.said}' OR UID='${req.body.remoteUID}'`).then(pubkeyArr => {
                                let PUBKEYJSON0 = JSON.parse(pubkeyArr[0].publicKey);
                                let PUBKEYJSON1 = JSON.parse(pubkeyArr[1].publicKey);
                                let SIGNINGPUBKEYJSON0 = JSON.parse(pubkeyArr[0].publicSigningKey);
                                let SIGNINGPUBKEYJSON1 = JSON.parse(pubkeyArr[1].publicSigningKey);
                                let notificationsConfig = 0;
                                let ownUsername = ''
                                for (let ix = 0; ix < pubkeyArr.length; ix++) {
                                    if (pubkeyArr[ix].uid == data.said) {
                                        ownUsername = pubkeyArr[ix].username;
                                    } else {
                                        notificationsConfig = JSON.parse(pubkeyArr[ix].notificationsConfig);
                                    }
                                }
                                let SPKSH = `${SIGNINGPUBKEYJSON0.x.toString().substring(0, 5)}.${SIGNINGPUBKEYJSON1.y.toString().substring(0, 5)}`;
                                let PKSH = `${PUBKEYJSON0.n.toString().substring(0, 5)}.${PUBKEYJSON1.n.toString().substring(0, 5)}`;
                                queryDB(`INSERT INTO refs(ownUID, foreignUID, status, MSUID, PKSH, tx, lastTX, SPKSH) VALUES('${data.said}', '${req.body.remoteUID}', 'Pending.TX', '${messagePermaStorageTableName}', '${PKSH}', '${Date.now()}', '${Date.now()}', '${SPKSH}')`).then(() => {
                                    queryDB(`INSERT INTO refs(ownUID, foreignUID, status, MSUID, PKSH, tx, lastTX, SPKSH) VALUES('${req.body.remoteUID}', '${data.said}', 'Pending.RX', '${messagePermaStorageTableName}', '${PKSH}', '${Date.now()}', '${Date.now()}', '${SPKSH}')`).then(() => { });
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
                                    if (notificationsConfig != 0) {
                                        if (notificationsConfig.newContacts == true) {
                                            sendNotification(notificationObj, res, true);
                                        }
                                    }
                                }).catch(e => { sendErrorResponse(res, e) });
                            }).catch(e => { sendErrorResponse(res, e) });
                        }
                        if (req.query['getLogs'] != undefined) {
                            queryDB(`SELECT tx, severity, type, subtype, ip, location, details FROM Logs WHERE uid='${data.said}' ORDER BY tx DESC LIMIT ${req.body.count}`).then(resx => {
                                if (resx.length > 0) {
                                    res.json({ status: 'Success', logs: resx });
                                } else {
                                    res.json({ status: 'Success', logs: [] });
                                }
                            }).catch(e => sendErrorResponse(res, e, 'LF-3356'))
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
                        if (req.query['getNewMessagesCount'] != undefined) {
                            let messageCountsHash = {};
                            for (let ixx = 0; ixx < req.body.refs.length; ixx++) {
                                queryDB(`SELECT MSUID FROM refs WHERE ownUID='${data.said}' AND foreignUID='${req.body.refs[ixx].uid}'`).then(MSUIDArr => {
                                    let MSUID = MSUIDArr[0].MSUID;
                                    let selectColumnsArr = 'targetUID, seen, originUID, tx';
                                    queryDB(`SELECT ${selectColumnsArr} FROM ${MSUID} WHERE (targetUID='${data.said}' AND originUID='${req.body.refs[ixx].uid}') ORDER BY tx DESC LIMIT 10`).then(resx => {
                                        var rawMsgArr = resx

                                        rawMsgArr.sort((a, b) => { return parseInt(a.tx) - parseInt(b.tx) })

                                        let seenFlag = { state: false, ix: 0 };
                                        if (resx.length > 0) {
                                            for (let ix = 0; ix < resx.length; ix++) {
                                                if (resx[ix].seen == 1 && (!seenFlag.state || seenFlag.ix <= ix)) {
                                                    seenFlag = { state: true, ix: ix }
                                                }
                                            }
                                            if (seenFlag.state) {
                                                if (seenFlag.state && seenFlag.ix != resx.length - 1) {
                                                    messageCountsHash[req.body.refs[ixx].uid] = { msg: resx.length - (seenFlag.ix + 1) };
                                                } else if (seenFlag.ix == resx.length - 1) {
                                                    messageCountsHash[req.body.refs[ixx].uid] = { msg: 0 };
                                                }

                                            } else {
                                                messageCountsHash[req.body.refs[ixx].uid] = { msg: resx.length };
                                            }
                                            if (ixx == req.body.refs.length - 1) {
                                                res.json({ status: 'Success', messageCountsHash: messageCountsHash });
                                            }
                                        } else {
                                            messageCountsHash[req.body.refs[ixx].uid] = { msg: 0 };
                                            if (ixx == req.body.refs.length - 1) {
                                                res.json({ status: 'Success', messageCountsHash: { messageCountsHash } });
                                            }
                                        }
                                    })//.catch(e => sendErrorResponse(res, e, 'GMC-105'));;
                                }).catch(e => sendErrorResponse(res, e, 'GMC-155'));
                            }
                        }
                        if (req.query['getMessages'] != undefined) {
                            queryDB(`SELECT MSUID, PKSH, SPKSH, lastTX FROM refs WHERE ownUID='${data.said}' AND foreignUID='${req.body.targetUID}'`).then(MSUIDArr => {
                                let MSUID = MSUIDArr[0].MSUID;
                                let PKSH = MSUIDArr[0].PKSH;
                                let SPKSH = MSUIDArr[0].SPKSH;
                                let selectColumnsArr = 'liked, tx, seen, auth, ownContent, remoteContent, MID, targetUID, signature';
                                queryDB(`SELECT COUNT(*) FROM ${MSUID}`).then(countx => {
                                    var count = countx[0]['count(*)']
                                    if (req.body.offset) {
                                        const offset = count - req.body.offset;
                                        if (offset >= 0) {
                                            queryDB(`SELECT ${selectColumnsArr} FROM ${MSUID} WHERE (targetUID='${data.said}' AND originUID='${req.body.targetUID}') OR (targetUID='${req.body.targetUID}' AND originUID='${data.said}') ORDER BY tx ASC LIMIT ${offset}, ${30}`).then(resx => {
                                                let typedMsgArr = []
                                                for (let ix = 0; ix < resx.length; ix++) {
                                                    if (resx[ix].targetUID == data.said) {
                                                        typedMsgArr.push({ ...resx[ix], type: 'rx' });
                                                    } else {
                                                        typedMsgArr.push({ ...resx[ix], type: 'tx' });
                                                    }
                                                }
                                                res.json({ status: 'Successful', messages: typedMsgArr, MSUID: MSUID, lastTX: MSUIDArr[0].lastTX, PKSH: PKSH, SPKSH: SPKSH, prepend: true });
                                            }).catch(e => sendErrorResponse(res, e, 'MF-915'));;
                                        } else {
                                            let countunderflow = offset * -1;
                                            let fetchCount = count % 30;//if more messages are requested than the db has, return the first chunk of messages since conversation start has been reached 
                                            if (countunderflow <= 30) {
                                                queryDB(`SELECT ${selectColumnsArr} FROM ${MSUID} WHERE (targetUID='${data.said}' AND originUID='${req.body.targetUID}') OR (targetUID='${req.body.targetUID}' AND originUID='${data.said}') ORDER BY tx ASC LIMIT ${0}, ${fetchCount}`).then(resx => {
                                                    let typedMsgArr = []
                                                    for (let ix = 0; ix < resx.length; ix++) {
                                                        if (resx[ix].targetUID == data.said) {
                                                            typedMsgArr.push({ ...resx[ix], type: 'rx' });
                                                        } else {
                                                            typedMsgArr.push({ ...resx[ix], type: 'tx' });
                                                        }
                                                    }
                                                    res.json({ status: 'Successful', messages: typedMsgArr, MSUID: MSUID, lastTX: MSUIDArr[0].lastTX, PKSH: PKSH, SPKSH: SPKSH, start: true });
                                                }).catch(e => sendErrorResponse(res, e, 'MF-182'));;
                                            } else {
                                                res.json({ status: 'Successful', messages: [], MSUID: MSUID, lastTX: MSUIDArr[0].lastTX, PKSH: PKSH, SPKSH: SPKSH, start: true });
                                            }
                                        }
                                    } else {
                                        queryDB(`SELECT ${selectColumnsArr} FROM ${MSUID} WHERE (targetUID='${data.said}' AND originUID='${req.body.targetUID}') OR (targetUID='${req.body.targetUID}' AND originUID='${data.said}') ORDER BY tx DESC LIMIT ${30}`).then(resx => {
                                            let typedMsgArr = []
                                            for (let ix = 0; ix < resx.length; ix++) {
                                                if (resx[ix].targetUID == data.said) {
                                                    typedMsgArr.push({ ...resx[ix], type: 'rx' });
                                                } else {
                                                    typedMsgArr.push({ ...resx[ix], type: 'tx' });
                                                }
                                            }

                                            if (typedMsgArr.length < 30) {
                                                res.json({ status: 'Successful', messages: typedMsgArr, lastTX: MSUIDArr[0].lastTX, MSUID: MSUID, PKSH: PKSH, SPKSH: SPKSH, start: true });
                                            } else {
                                                res.json({ status: 'Successful', messages: typedMsgArr, lastTX: MSUIDArr[0].lastTX, MSUID: MSUID, PKSH: PKSH, SPKSH: SPKSH, });
                                            }
                                        }).catch(e => sendErrorResponse(res, e, 'MF-442'));
                                    }
                                })
                            }).catch(e => sendErrorResponse(res, e))
                        }
                        if (req.query['updateConvoSig'] != undefined) {
                            queryDB(`SELECT publicSigningKey, publicKey, uid, username FROM users WHERE UID='${data.said}' OR UID='${req.body.remoteUID}'`).then(resx => {
                                queryDB(`SELECT PKSH, SPKSH FROM refs WHERE ownUID='${data.said}' AND foreignUID='${req.body.remoteUID}'`).then(sigsArray => {
                                    try {
                                        const sigs = sigsArray[0];
                                        var pubKeysHash = {};
                                        pubKeysHash[resx[0].uid] = { publicSigningKey: resx[0].publicSigningKey, publicKey: resx[0].publicKey, username: resx[0].username };
                                        pubKeysHash[resx[1].uid] = { publicSigningKey: resx[1].publicSigningKey, publicKey: resx[1].publicKey, username: resx[1].username };

                                        const ownPubKeySIGFragment = JSON.parse(pubKeysHash[data.said].publicKey)?.n?.toString().substring(0, 5);
                                        const ownSigningPubKeyJWK = JSON.parse(pubKeysHash[data.said].publicSigningKey);
                                        const ownSigningPubKeySIGFragments = { x: ownSigningPubKeyJWK.x?.toString().substring(0, 5), y: ownSigningPubKeyJWK.y.toString().substring(0, 5) };


                                        if (sigs.PKSH.toString().includes(ownPubKeySIGFragment) && (sigs.SPKSH.toString().includes(ownSigningPubKeySIGFragments.x) || sigs.SPKSH.toString().includes(ownSigningPubKeySIGFragments.y))) {
                                            pubKeysHash[data.said] = { ...pubKeysHash[data.said], verified: true };
                                        } else {
                                            pubKeysHash[data.said] = { ...pubKeysHash[data.said], verified: false };
                                        }

                                        const remotePubKeySIGFragment = JSON.parse(pubKeysHash[req.body.remoteUID].publicKey)?.n?.toString().substring(0, 5);
                                        const remoteSigningPubKeyJWK = JSON.parse(pubKeysHash[req.body.remoteUID].publicSigningKey);
                                        const remoteSigningPubKeySIGFragments = { x: remoteSigningPubKeyJWK.x?.toString().substring(0, 5), y: remoteSigningPubKeyJWK.y.toString().substring(0, 5) };

                                        if (sigs.PKSH.toString().includes(remotePubKeySIGFragment) && (sigs.SPKSH.toString().includes(remoteSigningPubKeySIGFragments.x) || sigs.SPKSH.toString().includes(remoteSigningPubKeySIGFragments.y))) {
                                            pubKeysHash[req.body.remoteUID] = { ...pubKeysHash[req.body.remoteUID], verified: true };
                                        } else {
                                            pubKeysHash[req.body.remoteUID] = { ...pubKeysHash[req.body.remoteUID], verified: false };
                                        }

                                        let ownSIGStatus = pubKeysHash[data.said].verified;
                                        let remoteSIGStatus = pubKeysHash[req.body.remoteUID].verified;
                                        if (ownSIGStatus && remoteSIGStatus) {
                                            res.json({ status: 'Failed', reason: 'No Sig Mismatches' });
                                        }
                                        if (ownSIGStatus && !remoteSIGStatus) {
                                            let SPKSH = `${ownSigningPubKeySIGFragments.x}.${remoteSigningPubKeySIGFragments.y}`;
                                            let PKSH = `${ownPubKeySIGFragment}.${remotePubKeySIGFragment}`;
                                            queryDB(`UPDATE refs SET PKSH='${PKSH}', SPKSH='${SPKSH}' WHERE (ownUID='${data.said}' AND foreignUID='${req.body.remoteUID}') OR ownUID='${req.body.remoteUID}' AND foreignUID='${data.said}'`).then(() => {
                                                res.json({ status: 'Success' });
                                            }).catch(e => sendErrorResponse(res, e, 'SUF-951'));
                                        }
                                        if (!ownSIGStatus && remoteSIGStatus) {
                                            res.json({ status: 'Failed', reason: 'Own SIG Mismatch' });
                                        }
                                        if (!ownSIGStatus && !remoteSIGStatus) {
                                            let SPKSH = `${ownSigningPubKeySIGFragments.x}.${remoteSigningPubKeySIGFragments.y}`;
                                            let PKSH = `${ownPubKeySIGFragment}.${remotePubKeySIGFragment}`;
                                            queryDB(`UPDATE refs SET PKSH='${PKSH}', SPKSH='${SPKSH}' WHERE (ownUID='${data.said}' AND foreignUID='${req.body.remoteUID}') OR ownUID='${req.body.remoteUID}' AND foreignUID='${data.said}'`).then(() => {
                                                res.json({ status: 'Success' });
                                            }).catch(e => sendErrorResponse(res, e, 'SUF-933'));
                                        }
                                    } catch (e) {
                                        sendErrorResponse(res, { error: 'PE-2RR4' }, 'PRS-345');
                                    }
                                }).catch(e => sendErrorResponse(res, e, 'UCS-141'));
                            }).catch(e => sendErrorResponse(res, e, 'UCS-235'));
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
                                    get(ref(db, `activeUIDs/${msgObj.targetUID}`)).then(snap => {
                                        let heartbeat = snap.val();
                                        if (heartbeat) {
                                            if (Date.now() - heartbeat.tx > 5020) {
                                                sendNotification(notificationObj, res, true);
                                            }
                                        } else {
                                            sendNotification(notificationObj, res, true);
                                        }
                                    })
                                }).catch(e => sendErrorResponse(res, e, 'MSG-2'));
                            }).catch(e => sendErrorResponse(res, e, 'MSG-0'));
                        }
                        if (req.query['likeMessage'] != undefined) {
                            queryDB(`UPDATE ${req.body.MSUID} SET liked=${req.body.state} WHERE MID='${req.body.MID}'`).then(resx => {
                                res.json({ status: 'Successful' });
                            }).catch(e => sendErrorResponse(res, e, 'MSG-150'));
                        }
                        if (req.query['changePassword'] != undefined || req.query['changeUsername'] != undefined) {
                            let changePasswordMode = -1;
                            if (req.query['changePassword'] != undefined && req.query['changeUsername'] == undefined && req.body.newPassword != undefined && !req.body.newPassword.toString().match(/^(.{0,7}|[^0-9]*|[^A-Z]*|[^a-z]*|[a-zA-Z0-9]*)$/)) {
                                changePasswordMode = true;
                            }
                            if (req.query['changePassword'] == undefined && req.query['changeUsername'] != undefined && req.body.newUsername != undefined && req.body.newUsername.length > 2) {
                                changePasswordMode = false;
                            }
                            if (changePasswordMode == -1) {
                                res.json({ status: 'Error', id: 'REQMLF' });
                            } else {
                                queryDB(`SELECT password, logsConfig FROM users WHERE uid='${data.said}'`).then(resx => {
                                    bcrypt.compare(req.body.currentPassword, resx[0].password).then(match => {
                                        if (match) {
                                            var logsConfig = 0;
                                            try { logsConfig = JSON.parse(resx[0].logsConfig) } catch (e) { }
                                            if (changePasswordMode == true) {
                                                bcrypt.hash(req.body.newPassword, 11).then(hash => {
                                                    if (logsConfig != 0 && logsConfig.security == true) {
                                                        queryDB(`INSERT INTO Logs SET tx='${Date.now()}', uid='${data.said}', severity='important', type='Security', subtype='Password Changed', ip='${data.ip}', location='${req.body.location}', details='${req.body.details}'`).then().catch(e => { })
                                                    }
                                                    queryDB(`UPDATE users SET password='${hash}' WHERE uid='${data.said}'`).then(() => {
                                                        remove(ref(db, `authTokens/${req.body.AT}`)).then(() => {
                                                            res.json({ status: 'Success', flag: true });
                                                        });
                                                    }).catch(e => sendErrorResponse(res, e, 'DR-105'));
                                                }).catch(e => sendErrorResponse(res, e, 'HS-532'))
                                            } else if (changePasswordMode == false) {
                                                if (logsConfig != 0 && logsConfig.account == true) {
                                                    queryDB(`INSERT INTO Logs SET tx='${Date.now()}', uid='${data.said}', severity='info', type='Account', subtype='Username Changed', ip='${data.ip}', location='${req.body.location}', details='${req.body.details}'`).then().catch(e => { })
                                                }
                                                queryDB(`UPDATE users SET username='${req.body.newUsername.toString()}' WHERE uid='${data.said}'`).then(() => {
                                                    update(ref(db, `authTokens/${req.body.AT}`), { username: req.body.newUsername.toString() }).then(() => {
                                                        res.json({ status: 'Success', flag: true });
                                                    });
                                                }).catch(e => sendErrorResponse(res, e, 'DR-142'));
                                            }
                                        } else {
                                            res.json({ status: 'Failed', flag: false });
                                        }
                                    }).catch(e => sendErrorResponse(res, e, 'HM-89'));
                                }).catch(e => sendErrorResponse(res, e, 'DR-192'));;
                            }
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

                        if (req.query['getLogsConfig'] != undefined) {
                            queryDB(`SELECT logsConfig FROM users WHERE uid='${data.said}'`).then(resx => {
                                if (resx.length > 0) {
                                    res.json({ status: 'Success', logsConfig: resx[0].logsConfig });
                                } else {
                                    sendErrorResponse(res, e, 'LCF-881')

                                }
                            }).catch(e => sendErrorResponse(res, e, 'GNPF-995'))
                        }

                        if (req.query['getNotificationsConfig'] != undefined) {
                            queryDB(`SELECT notificationsConfig FROM users WHERE uid='${data.said}'`).then(resx => {
                                if (resx.length > 0) {
                                    res.json({ status: 'Success', notificationsConfig: resx[0].notificationsConfig });
                                } else {
                                    sendErrorResponse(res, e, 'GNPF-057')

                                }
                            }).catch(e => sendErrorResponse(res, e, 'GNPF-995'))
                        }

                        if (req.query['updateLogsConfig'] != undefined) {
                            if (req.body.newPrefs) {
                                try {
                                    let prefs = JSON.parse(req.body.newPrefs)
                                    if (prefs.security != undefined && prefs.ini != undefined && prefs.account != undefined) {
                                        queryDB(`UPDATE users SET logsConfig='${JSON.stringify(prefs)}' WHERE uid='${data.said}'`).then(() => {
                                            res.json({ status: 'Success' });
                                        }).catch(e => sendErrorResponse(res, e, 'LPU-554'));
                                    } else {
                                        sendErrorResponse(res, e, 'LPU-083')
                                    }
                                } catch (e) {
                                    sendErrorResponse(res, e, 'LPU-991')
                                }
                            } else if (req.body.deleteAll) {
                                queryDB(`DELETE FROM Logs WHERE uid='${data.said}'`).then(() => {
                                    res.json({ status: 'Success' });
                                }).catch(e => sendErrorResponse(res, e, 'DAL-2511'));
                            } else {
                                sendErrorResponse(res, { error: {} }, 'ULCMC-331')
                            }
                        }
                        if (req.query['updateNotificationsConfig'] != undefined) {
                            if (req.body.newPrefs) {
                                try {
                                    let prefs = JSON.parse(req.body.newPrefs)
                                    if (prefs.security != undefined && prefs.newContacts != undefined && prefs.messages != undefined) {
                                        queryDB(`UPDATE users SET notificationsConfig='${JSON.stringify(prefs)}' WHERE uid='${data.said}'`).then(() => {
                                            res.json({ status: 'Success' });
                                        }).catch(e => sendErrorResponse(res, e, 'UNPF-141'));
                                    } else {
                                        sendErrorResponse(res, e, 'UNPF-223')
                                    }
                                } catch (e) {
                                    sendErrorResponse(res, e, 'UNPF-523')
                                }
                            }
                        }
                        if (req.query['verifyPassword'] != undefined) {
                            queryDB(`SELECT password, logsConfig FROM users WHERE uid='${data.said}'`).then(resx => {
                                bcrypt.compare(req.body.password, resx[0].password).then(authed => {
                                    if (authed) {
                                        var isExport = 0;
                                        if (req.body.authShareType != undefined) {
                                            isExport = req.body.authShareType.toString().split('.')[1] == 'export';
                                        }
                                        var logsConfig = 0;
                                        try { logsConfig = JSON.parse(resx[0].logsConfig) } catch (e) { sendErrorResponse(res, e, 'JPF-231') }
                                        if (logsConfig != 0 && logsConfig.security == true) {
                                            if (req.body.authShareType != undefined && req.body.rtdbPayload != undefined) {
                                                let typeHash = { 'file.export': 'Keys Export', 'scan.export': 'Keys Export', 'scan.import': 'Keys Import', 'file.import': 'Keys Import' };
                                                queryDB(`INSERT INTO Logs SET tx='${Date.now()}', uid='${data.said}', severity='critical', type='Security', subtype='${typeHash[req.body.authShareType]}', ip='${data.ip}', location='${req.body.location != false ? req.body.location : { name: 'Unknown', coords: { lat: 0, long: 0 } }}', details='${req.body.details}'`).then().catch(e => { sendErrorResponse(res, e, 'LRF-339') })
                                            }
                                            if (req.body.regenKeys != undefined) {
                                                queryDB(`INSERT INTO Logs SET tx='${Date.now()}', uid='${data.said}', severity='critical', type='Security', subtype='Keys Regen', ip='${data.ip}', location='${req.body.location != false ? req.body.location : { name: 'Unknown', coords: { lat: 0, long: 0 } }}', details='${req.body.details}'`).then().catch(e => { sendErrorResponse(res, e, 'LRF-339') })
                                            }
                                        }
                                        if (req.body.rtdbPayload != undefined && isExport != 0) {
                                            set(ref(db, `exportAuth/${data.said}`), { tx: Date.now(), authShareType: req.body.authShareType, ...req.body.rtdbPayload });
                                            res.json({ status: 'Successful', flag: true, });
                                        }
                                        if (!isExport) {
                                            res.json({ status: 'Successful', flag: true, });
                                        }
                                        if (req.body.regenKeys == true) {
                                            try {
                                                let signingPukKeyJWK = JSON.parse(req.body.signingPubKey);
                                                let pubKeyJWK = JSON.parse(req.body.pubkey);
                                                if (signingPukKeyJWK.x && signingPukKeyJWK.y && pubKeyJWK.n) {
                                                    queryDB(`UPDATE users SET publicKey='${req.body.pubkey}', publicSigningKey='${req.body.signingPubKey}' WHERE uid='${data.said}'`).then(() => {
                                                        res.json({ status: 'Successful', updatePrivateKeys: true });
                                                    }).catch(e => sendErrorResponse(res, e, 'KPUF-332'));
                                                } else {
                                                    sendErrorResponse(res, { error: 'KPF-545' }, 'KPF-545');
                                                }
                                            } catch (e) { sendErrorResponse(res, e, 'KPF-331') }
                                        }
                                    } else {
                                        res.json({ status: 'Failed' });
                                    }
                                }).catch(e => sendErrorResponse(res, e, 'UNK-241'))
                            }).catch(e => sendErrorResponse(res, e))
                        }
                        if (req.query['deleteConversation'] != undefined) {
                            queryDB(`SELECT MSUID FROM refs WHERE ownUID='${data.said}' AND foreignUID='${req.body.remoteUID}'`).then(MSUIDArr => {
                                if (MSUIDArr.length > 0) {
                                    const MSUID = MSUIDArr[0].MSUID;
                                    queryDB(`DELETE FROM ${MSUID} WHERE (originUID='${data.said}' AND targetUID='${req.body.remoteUID}') OR (originUID='${req.body.remoteUID}' AND targetUID='${data.said}')`).then(() => {
                                        res.json({ status: 'Success' });
                                    }).catch(e => sendErrorResponse(res, e, 'DXA-085'));
                                } else {
                                    sendErrorResponse(res, { error: 'DXS-205' }, 'DXS-205')
                                }
                            }).catch(e => sendErrorResponse(res, e, 'DCX-110'));
                        }
                        if (req.query['removeContact'] != undefined) {
                            queryDB(`DELETE FROM refs WHERE (ownUID='${data.said}' AND foreignUID='${req.body.remoteUID}') OR (ownUID='${req.body.remoteUID}' AND foreignUID='${data.said}')`).then(() => {
                                res.json({ status: 'Success' });
                            }).catch(e => sendErrorResponse(res, e, 'RMC-388'));
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
    const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: 'https://www.ring-relay.live' });
    module.exports = cors(handler);
}