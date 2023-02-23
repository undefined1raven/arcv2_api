require('dotenv').config()
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DATABASE_URL)

function handler(req, res) {
    connection.execute('CREATE TABLE users(username varchar(255))');    
    if(process.env.PLANETSCALE_DB_USERNAME != undefined){
        res.json({DAX: 'got it'})
    }else{
        res.json({DAX: 'not really'})
    }
}

module.exports = cors(handler);