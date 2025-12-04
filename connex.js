const mysql = require("mysql2");
require("dotenv").config();

const { DB_HOST, DB_USER, DB_PASSWORD, DB_PORT, DB_NAME, DB_CONN_LIMIT = 10 } = process.env;

if (!DB_HOST || !DB_USER || !DB_PORT || !DB_NAME) {
    throw new Error("Faltan variables de entorno: DB_HOST, DB_USER, DB_PORT, DB_NAME");
}

const pool = mysql.createPool({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    port: Number(DB_PORT),
    connectionLimit: Number(DB_CONN_LIMIT),
    waitForConnections: true,
    queueLimit: 0
});

module.exports = pool.promise();
