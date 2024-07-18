require('dotenv').config()
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');
const jwt = require('jsonwebtoken');
const { serialize } = require('cookie')
const fs = require('fs');
// var privateKey = fs.readFileSync('private-key.pem');

const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");
var admin = require("firebase-admin");
// var serviceAccount = JSON.parse(process.env.FIREBASE_SCA);



admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: ""
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
    // console.log(jwt.sign({iss: serviceAccount.client_email, sub: serviceAccount.client_email, aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit", iat: Date.now(), exp: 3600, uid: v4()}, privateKey, { algorithm: 'RS256' }))
    if (req.body != undefined) {
       
    } else {
        res.json({ status: 'No Body Data' })
    }
}

if (process.env.NODE_ENV === 'development') {
    const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: 'http://localhost:3000' });
    module.exports = cors(handler);
} else {
    const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: 'https://www.ring-relay.live' });
    module.exports = cors(handler);
}