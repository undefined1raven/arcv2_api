require('dotenv').config()
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)
const mfa_mgr = require('speakeasy');

function addRow(rowName, data, callback) {
    connection.query(`INSERT INTO ${rowName} SET ?`, data, callback);
}

function handler(req, res) {
    try {
        // connection.query('CREATE TABLE users ()', (err, resx, fields) => {
        //     res.json({ DAX: 'got it', RX: resx, AVG: parseFloat(s / resx.length).toFixed(2) })
        // });
        if (req.query['newUser'] != undefined && req.body != undefined) {
            bcrypt.hash(req.body.password, 10).then(hash => {
                // addRow('users', {
                //     uid: v4(),
                //     username: req.body.username,
                //     password: hash,
                //     email: req.body.email,
                //     mfa_token: mfa_mgr.generateSecret({ length: 40 })
                // }, (err, resx, fields) => {
                //     console.log(resx);
                //     console.log(err);
                // });
                let accountData = {
                    uid: v4(),
                    username: req.body.username,
                    password: hash,
                    email: req.body.email,
                    mfa_token: JSON.stringify(mfa_mgr.generateSecret({ length: 40 }))
                }
                connection.query('INSERT INTO users SET ?', accountData, (err, resx, fields) => {
                    console.log(resx)
                });
                
                connection.query('SELECT * FROM unn', (err, resa, fields) => {
                    console.log(resa)
                });

                res.json({ status: 'Success' });
            });
        } else {
            res.json({ status: 'Pending' });
        }
    } catch (e) {
        res.json({ RX: `ERROR: ${e}` })
    }
}

module.exports = cors(handler);