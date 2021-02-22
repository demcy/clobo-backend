require('dotenv').config()

//const http = require('http');
const https = require('https');
const fs = require('fs');

const { URLSearchParams } = require('url');
const hostname = 'localhost';
const port = 4000;
const options = {
    key: fs.readFileSync('clobo-key.pem'),
    cert: fs.readFileSync('clobo-cert.pem')
};

const bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');


sgMail.setApiKey(process.env.SENDGRID_API_KEY)

const users = []

const msg = {
    to: 'demcy.meizu@gmail.com', // Change to your recipient
    from: 'demcy.meizu@gmail.com', // Change to your verified sender
    subject: 'Clobo Register confirmation',
    html: '<strong>and easy to do anywhere, even with Node.js</strong>',
}

const server = https.createServer(options, (req, res) => {
    //const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', true);

    //res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Origin', 'https://localhost:3000');
    //res.setHeader('Access-Control-Allow-Origin', 'https://clobo.ga');
    res.setHeader('Access-Control-Allow-Methods', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Content-Security-Policy', 'default-src https://localhost:3000');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(self "https://localhost:3000"), microphone=()');
    console.log(req.url + req.method)
    switch (req.method) {
        case 'GET': {
            switch (req.url) {
                case '/': {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Index D\n');
                    break;
                }
                case '/vercel': {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Vercel\n');
                    break;
                }
                case '/app/vercel': {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Vercel APP\n');
                    break;
                }
                case '/api/app/vercel': {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Vercel API APP\n');
                    break;
                }
                case '/users': {
                    if (req.headers.cookie == null) {
                        res.statusCode = 401
                        res.setHeader('Content-Type', 'text/plain');
                        res.end()
                        break
                    }
                    console.log(req.headers.cookie)
                    console.log(req.headers.cookie.split('=')[1])
                    const tokenUser = jwt.verify(req.headers.cookie.split('=')[1], process.env.ACCESS_TOKEN)
                    const v = users.find(user => user.email === tokenUser.email && user.password === tokenUser.password)
                    console.log(v)
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify(users));
                    res.end()
                    break;
                }
                default: {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Index\n');
                    break;
                }
            }
            break;
        }
        case 'POST': {
            switch (req.url) {
                case '/register': {
                    req.on('data', chunk => {
                        const existUser = users.find(user => user.email === JSON.parse(chunk).email)
                        if (existUser == null) {
                            const user = {
                                email: JSON.parse(chunk).email,
                                password: bcrypt.hashSync(JSON.parse(chunk).password, 10),
                                isConfirmed: false
                            }
                            users.push(user)
                            const token = jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: 60 * 60 })
                            confirmMessage(token)
                            res.statusCode = 201;
                            res.setHeader('Content-Type', 'application/json');
                            res.end('User created a new account with password');
                        } else {
                            res.statusCode = 409;
                            res.setHeader('Content-Type', 'application/json');
                            res.end('User email is already in use');
                        }
                    });
                    break;
                }
                case '/confirm': {
                    req.on('data', chunk => {
                        try {
                            const confirmUser = jwt.verify(JSON.parse(chunk).token, process.env.ACCESS_TOKEN)
                            const user = users.find(user => user.email === confirmUser.email && user.password === confirmUser.password)
                            if (user != null) {
                                user.isConfirmed = true
                                res.statusCode = 200;
                                res.end('Thank you for confirming your email')
                            } else {
                                res.statusCode = 404;
                                res.end('User not found')
                            }
                        } catch (err) {
                            res.statusCode = 403;
                            if (err.name === 'TokenExpiredError') {
                                var decoded = jwt.decode(JSON.parse(chunk).token);
                                const user = users.find(user => user.email === decoded.email && user.password === decoded.password)
                                if (user != null) {
                                    if (user.isConfirmed) {
                                        res.end('User email is already verified')
                                    } else {
                                        res.statusCode = 401;
                                        const token = jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: 60 * 60 })
                                        confirmMessage(token)
                                        res.write('Email confirmation link is expired. ')
                                        res.end('Please check your email to confirm your account')
                                    }
                                }
                                else {
                                    res.statusCode = 404;
                                    res.end('User not found')
                                }
                            } else {
                                res.end('Error confirming your email')
                            }
                        }
                    });
                    break;
                }
                case '/login': {
                    var token = ''
                    req.on('data', chunk => {
                        const user = users.find(user => user.email === JSON.parse(chunk).email)
                        if (user != null) {
                            if (user.isConfirmed) {
                                const result = bcrypt.compareSync(JSON.parse(chunk).password, user.password);
                                if (result) {
                                    token = jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: 60 * 60 })
                                    res.statusCode = 200;
                                    res.setHeader("SET-COOKIE", "ACCESS_TOKEN=" + token + "; SameSite = Strict; Secure; HttpOnly")
                                    res.end();
                                } else {
                                    res.statusCode = 403;
                                    res.end('Your password is incorrect');
                                }
                            } else {
                                res.statusCode = 403;
                                res.end('Please check your email to confirm your account')
                            }
                        } else {
                            res.statusCode = 404;
                            res.end('User not found');
                        }
                    });
                    break;
                }

                default: {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Index\n');
                    break;
                }
            }
            break;
        }
        default: {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'text/plain');
            res.end(token);
            break;
        }
    }
    // if (url === '/info' && req.method === 'GET' && authencticateToken) {
    //     console.log(req.user)
    //     res.end(JSON.stringify(users.filter(user => user.name == req.user.name)));
    // }
    // else if (url === '/users' && req.method === 'POST') {

    //     req.on('data', chunk => {
    //         bcrypt.hash(JSON.parse(chunk).password, 10, function (err, hash) {
    //             const user = { name: JSON.parse(chunk).name, password: hash }
    //             users.push(user)
    //         });
    //     })

    // }
    // else if (url === '/users/login' && req.method === 'POST') {
    //     req.on('data', chunk => {
    //         const user = users.find(user => user.name = JSON.parse(chunk).name)
    //         if (bcrypt.compare(JSON.parse(chunk).password, user.password)) {
    //             console.log('in')
    //             const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
    //             res.end(JSON.stringify({ accessToken: accessToken }))
    //         }
    //     })
    // }
    // else {
    //     res.statusCode = 200;
    //     res.setHeader('Content-Type', 'text/plain');

    //     res.end('Hello World');
    // }


});

// function authencticateToken(req, res) {
//     console.log('hi')
//     const authHeader = req.headers['authorization']
//     const token = authHeader && authHeader.split(' ')[1]
//     if (token == null) return res.setHeader(401)

//     jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
//         if (err) return res.setHeader(403)
//         //console.log(req.user)
//         req.user = user
//         //console.log(req.user)
//         return true
//     })
// };

server.listen(port, hostname, () => {
    console.log(`Server running at https://${hostname}:${port}/`);
});

function confirmMessage(token) {
    msg.html = `<div style="display: inline-block">
                <img alt="logo" src="https://clobo.ga/logo.jpg"></img>
                <a style="background-color: #4c2b00; color: white; padding: 15px 25px; text-align: center; text-decoration: none; display: block; border-radius: 5px" 
                href="https://localhost:3000/Confirm?
                token=${token}">Confirm your email</a></div>`
    sgMail
        .send(msg)
        .then(() => {
            console.log('Email sent')
        })
        .catch((error) => {
            console.error(error)
        })
}

module.exports = https