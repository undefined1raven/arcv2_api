
require('dotenv').config()
const { v4 } = require('uuid');
const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');
const jwt = require('jsonwebtoken');
const { serialize } = require('cookie')
const fs = require('fs');
var https = require('https');

var admin = require("firebase-admin");
var serviceAccount = JSON.parse(process.env.FIREBASE_SCA);



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





admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://ring-relay-default-rtdb.europe-west1.firebasedatabase.app/"
});
const db = admin.database();


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

function handler(req, res) {

    if (req.body != undefined) {
        get(ref(db, `authTokens/${req.body.AT}`)).then(snap => {
            const data = snap.val();
            if (data != undefined && data.ip == req.body.CIP) {
                bcrypt.compare(`${req.body.AT}${process.env.AT_SALT}${req.body.CIP}`, data.hash).then(result => {
                    if (result) {
                        if (req.query['newMessage'] != undefined) {
                            queryDB(`SELECT username FROM users WHERE uid='${req.body.targetUID}'`).then(resx => {
                                let notificationObj = {
                                    app_id: process.env.ONESIG_ID,
                                    title: { "en": "Ring Relay" },
                                    web_buttons: [{ id: 'like', text: 'Like' }, { id: 'markAsSeen', text: 'Mark as seen' }],
                                    contents: { "en": `New message from ${resx[0].username}` },
                                    channel_for_external_user_ids: 'push',
                                    include_external_user_ids: [data.said],
                                    chrome_web_badge: "https://www.filepicker.io/api/file/proltSCwSWqb8QgZU0UD?filename=name.png",
                                    icon: "https://www.filepicker.io/api/file/k8omnb4ySjCWXE0WQSw5?filename=name.png",
                                };
                                sendNotification(notificationObj, res);

                            }).catch(e => res.json({ status: 'Failed', error: e, id: 'MSG-NOTF-24' }))
                        }
                    }
                })
            }
        })
    }
}

if (process.env.NODE_ENV === 'development') {
    const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: 'http://localhost:3000' });
    module.exports = cors(handler);
} else {
    const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: 'https://ring-relay.vercel.app' });
    module.exports = cors(handler);
}