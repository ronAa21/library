const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const oracledb = require('oracledb');

const router = express.Router();
const dbConfig = {
    user: 'your_oracle_username',
    password: 'your_oracle_password',
    connectionString: 'your_oracle_connection_string',
    poolMin: 0,
    poolMax: 5,
    poolIncrement: 1,
    poolTimeout: 0
};
const jwtSecret = 'your-secret-key';
const saltRounds = 10;

async function init() {
    try {
        await oracledb.createPool(dbConfig);
        console.log('Connection pool started');
    } catch (err) {
        console.error('Error initializing connection pool:', err);
        process.exit(1);
    }
}

router.post('/signup', async (req, res) => {
    const { userName, middleName, lastName, firstName, emailAddress, password } = req.body; // Added middleName
    let connection;

    try {
        if (!userName || !lastName || !firstName || !emailAddress || !password) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        connection = await oracledb.getConnection();

        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const insertUserQuery = `INSERT INTO Users (USER_NAME, MIDDLE_NAME, LAST_NAME, FIRST_NAME, EMAIL_ADDRESS, PASSWORD, ROLE, STATUS)
                                 VALUES (:userName, :middleName, :lastName, :firstName, :emailAddress, :hashedPassword, 'user', 'active')`; // Added middleName
        const bindVars = {
            userName,
            middleName, // Added middleName
            lastName,
            firstName,
            emailAddress,
            hashedPassword
        };
        await connection.execute(insertUserQuery, bindVars);
        await connection.commit();

        res.status(201).json({ message: 'Signup successful!' });

    } catch (err) {
        console.error('Error during signup:', err);
        res.status(500).json({ error: 'Signup failed. Please check the server logs.' });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
});

router.post('/login', async (req, res) => {
    const { identifier, password } = req.body;
    let connection;

    try {
        if (!identifier || !password) {
            return res.status(400).json({ error: 'Username/email and password are required.' });
        }

        connection = await oracledb.getConnection();

        const getUserQuery = `SELECT USER_ID, USER_NAME, ROLE FROM Users
                             WHERE USER_NAME = :identifier OR EMAIL_ADDRESS = :identifier`;
        const userResult = await connection.execute(getUserQuery, { identifier });
        const user = userResult.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { userId: user[0], userName: user[1], role: user[2] },
            jwtSecret,
            { expiresIn: '1h' }
        );

        res.status(200).json({ message: 'Login successful!', token });

    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Login failed. Please check the server logs.' });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
});

init().then(() => {
    module.exports = router;
});
