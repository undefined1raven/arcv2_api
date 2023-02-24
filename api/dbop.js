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
                console.log(hash);
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
                connection.query('INSERT INTO users SET ?', {
                    uid: v4(),
                    username: req.body.username,
                    password: hash,
                    email: req.body.email,
                    mfa_token: mfa_mgr.generateSecret({ length: 40 })
                }, (err, resx) => { console.log(resx) })

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