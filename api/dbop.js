require('dotenv').config()
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)

function handler(req, res) {
    try{
        connection.query('SELECT * FROM unn;', (err, resx, fields) => {        
            res.json({DAX: 'got it', RX: resx})
        });    
    }catch(e){
        res.json({DAX: 'got it', RX: `ERROR: ${e}`})
    }
}

module.exports = cors(handler);