require('dotenv').config()
const User = require("./model/user");
const auth = require("./middleware/auth");
require("./config/database").connect();
const express = require("express");
const jwt = require('jsonwebtoken')

const bcrypt = require('bcryptjs');
// const bcrypt = require('bcrypt');

const app = express()

app.use(express.json());

// Register Route
app.post('/register', async (req, res) => {
    try {
        // getting user input
        const { first_name, last_name, email, password } = req.body
        console.log(req.body);

        // validating user input
        if(!(email && password && first_name && last_name)) {
            res.status(400).send("All input is required")
        }

        // checking if user already exists and validating if user already exists in our database
        const oldUser = await User.findOne({ email })

        if(oldUser) {
            return res.status(409).send("User already exists. Please Login Again")
        }

        // Encrypting user password with bcrypt
        encryptedPassword = await bcrypt.hash(password, 10)
        
        // creating user in our database
        const user = await User.create({
            first_name: first_name,
            last_name: last_name , 
            email: email,
            password: encryptedPassword
        })

        // creating token 
        const token = jwt.sign(
            { user_id: user._id, email }, 
            process.env.TOKEN_KEY,
            { 
                expiresIn: "2h"
            }
        )
        // saving user token
        user.token = token
        console.log(user);

        // returning new user
        res.status(201).json(user)
    } catch(err) {
        console.log(err);
    }
})

// Login Route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body

        // validating user input
        if(!(email && password)) {
            res.status(400).send("All input is required")
        }

        // validating if user exists in our database
        const user = await User.findOne({ email })

        if(user && (await bcrypt.compare(password, user.password))) {
            // creating token
            const token = jwt.sign(
                { user_id: user.id, email },
                process.env.TOKEN_KEY,
                {
                    expiresIn: "2h"
                }
            )
            // saving the token 
            user.token = token

            return res.status(200).json(user);
        }
        res.status(400).send("Invalid Credentials")
    } catch (err) {
        console.log(err)
    }
})

// Home Route
app.post('/welcome', auth, (req, res) => {
    res.status(200).send("Welcome Home!")
})


module.exports = app;
