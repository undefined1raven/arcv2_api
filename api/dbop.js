require('dotenv').config()
const cors = require('micro-cors')({ allowMethods: ['GET', 'POST'], origin: '*' });
const { v4 } = require('uuid');
const bcrypt = require('bcrypt')
const mysql = require('mysql2')

function handler(req, res) {
    if(process.env.PLANETSCALE_DB_USERNAME != undefined){
        res.json({DAX: 'got it'})
    }else{
        res.json({DAX: 'not really'})
    }
}

module.exports = cors(handler);