require('dotenv').config()
const { v4 } = require('uuid');
const { getDatabase, get, once, increment, remove, query, limitToLast, update, push, set, ref, onValue } = require("firebase/database");
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');

var admin = require("firebase-admin");
var serviceAccount = {
    "type": "service_account",
    "project_id": "spidereyes-74fc6",
    "private_key_id": "f1090c234cbc1f1018402d0f53055827c7c9f241",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCiHflcULQn0wwv\n19fStyPNTsGyAOiZyElTqKMRrnpcwOmHkdKhcCPXeWWfsNGUkQPUXUZqwS0+ONsI\nb6Nm62uydyTgxOWdplFk0abIv3NaixtLyEgu9Ox1kDeNwsHVm/juH1EJGGzdh1Kr\nXOqO2uVs3/fKuBf8mxnTSv/oGmHtwK/mLHPqLJNzEdhGXV79eyaJq9QgrhOyS+c1\ndOxSXwuBFhrqJccPQiN2wFUZ5ZM950Yw17UjnFeE4DBhuqMhHd26dZFNM3e8QRP4\nkYV7qwQXU0iHclKwZbiQEPuWi9r3v5UYm9U2daz2USxbGQPNJxlKzNbxsMzmNAug\nu4pVDYyNAgMBAAECggEADvLzIdFaT3rNWqMNZoOXRFERGOQvDrEym8mG4fREGcX7\nMtJeSR8xWub5mUBhjxDRONWyDtmJ3b0561z6BR1L1MzaRHS7lK43vrN7bPMEhNKj\nfXk2OMhCfrPB/6s4GwWzLmgKXauYLFRUafNbOLmUItZDP/j6U0ONHdgCYYl/QsBW\nabt2aDnqOGKQXyaCFqfrfYxRNu02RoaWldw2SlMllZ/utRoEG6g2tQOIYSnHtUbz\n1xsYPUo9tNGuGcMGoLZpCfsg1Hf20Y3t77yomzCamEC1WWQzpszFWe5BH6kUQv22\nydUOCafegI3K9K2pHfuX4/HQpKXIsnpUqNAE8g6q2QKBgQDgLLr2R8mA8oXO4idB\nmvwwQ/UO8hvk6b2uh4oCXwL6y+J2uRVfj6kKkiiG3Li15JF34xgWJzDHPKPiFC/Q\nwP2QvmQ3hUX0seRkNsWaMM4B1EkYyiWvD2I1xRrd8lhXPUR7fGHVEq8qtYF4yOLA\n5fM+OxINqc5sq8GTSQjIyNmtVQKBgQC5IdvPzqmADpVCtTNiCO7lQ/7xWrxdta3D\n6Z+3Vn+UFywQ2NObX4RTJATWar/PlvbOP49roLgnK62i6VeBd0Oxi153hmy7XqEf\nI5geLL8BRb+odFG7Nqs+pWdS96JCy9F5N8COYU8mLGxM21VPbOg5ls+n9GH0HHRD\nvrPrru8iWQKBgGPJBV/jDHrteUphuH+ncWI6nbaNZoU61kf95RyxFi502tVmBXGI\nDQK7lHaTgVTV7TqkR3B0+W12PKzBt5cAkN4BIbLlDAKjvLou9z5vQwPlbrQuJyAJ\nhPnSRudMnK4Yg4dEEng53Obx7DPLl8Otl9y3ho22bEBLI9tfwx086kgRAoGATBlB\n3KLLg8r6ycfoDiUz5ePUWOt+QFrcyYovz9HrcTkxMN+f498YaoCEyIpqu+8HFnKE\nBq6y488NecjG4n3ewo1SUHleGorkWgNslQK5pNFB3gGqUvU+4OpmlXEbLq/PNC+Z\npC0VttBN2C3UXGic8IcwZo6K8Sf9Fpe+J2PqAkkCgYAZMggZP8tFTPqqj4UVK6d4\nw2XTzwXroxAnHflGMTYqa3qBnd75qa+RZdKmRqUrHV5WPsXz3bhxe5VzLKzVtj9t\nBup3r9d3sDb6cdJj9lp005l4U15zEc9d2c9Up+A/kq/wGhirQTlra4/U5DRk4wBZ\nBROZu69MPnhugm/Tv87IgQ==\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-f41jy@spidereyes-74fc6.iam.gserviceaccount.com",
    "client_id": "105246159122698673324",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-f41jy%40spidereyes-74fc6.iam.gserviceaccount.com"
};;

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://spidereyes-74fc6-default-rtdb.europe-west1.firebasedatabase.app/"
});
const db = admin.database();


function handler(req, res) {
    if (req.body != undefined) {
        let userid = req.body.userid;
        let password = req.body.password;
        let useridType = 'email';
        if (userid.indexOf('@') == -1) {
            useridType = 'username';
        }else{
            useridType = 'email';
        }
        let rowsActual = [];
        let passRowsActual = [];
        connection.query(`SELECT email FROM users WHERE ${useridType} = ?`, userid, function (err, rows, fields) { rowsActual = rows });
        setTimeout(() => {
            connection.query(`SELECT password FROM users WHERE ${useridType} = ?`, userid, function (err, rows, fields) { passRowsActual = rows });
            if (rowsActual.length > 0) {
                setTimeout(() => {
                    bcrypt.compare(req.body.password, passRowsActual[0].password).then(auth_res => {
                        if (auth_res) {
                            res.json({ status: 'Successful', redirect: '/' });
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
        res.json({ 200: 200 })
    }
}

module.exports = cors(handler);