require('dotenv').config()
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DB_KEY)

function handler(req, res) {
    connection.query('CREATE TABLE users(username varchar(255));');    
    if(process.env.DB_KEY != undefined){
        res.json({DAX: 'got it'})
    }else{
        res.json({DAX: 'not really'})
    }
}

module.exports = cors(handler);