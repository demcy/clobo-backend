require('dotenv').config()
//const https = require('https');
//const fs = require('fs');
// const options = {
//     key: fs.readFileSync('clobo-key.pem'),
//     cert: fs.readFileSync('clobo-cert.pem')
// };
//const server = https.createServer(options, (req, res) => {
const http = require('http');
//var url = require('url');

const hostname = 'localhost';
const port = 4000;

const bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
const { URLSearchParams } = require('url');
sgMail.setApiKey(process.env.SENDGRID_API_KEY)

const users = []

const msg = {
    to: 'demcy@mail.com', // Change to your recipient
    from: 'demcy.meizu@gmail.com', // Change to your verified sender
    subject: 'Clobo Register confirmation',
    text: 'Confirm your email',
    html: '<strong>and easy to do anywhere, even with Node.js</strong>',
}


const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', true);

    //res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Origin', 'https://localhost:3000');
    //res.setHeader('Access-Control-Allow-Origin', 'https://clobo.ga');
    res.setHeader('Access-Control-Allow-Methods', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Content-Security-Policy','default-src https://localhost:3000');
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
                        const user = {
                            email: JSON.parse(chunk).email,
                            password: bcrypt.hashSync(JSON.parse(chunk).password, 10),
                            isConfirmed: false
                        }
                        users.push(user)
                        const token = jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: 1 })
                        msg.html = `<a href="https://localhost:3000/Confirm?
                        token=${token}">Link</a>`
                    });
                    req.on('end', () => {
                        sgMail
                            .send(msg)
                            .then(() => {
                                console.log('Email sent')
                            })
                            .catch((error) => {
                                console.error(error)
                            })
                        res.statusCode = 201;
                        res.setHeader('Content-Type', 'application/json');
                        res.end('success');
                    })
                    break;
                }
                case '/login': {
                    var token = ''
                    req.on('data', chunk => {
                        const result = bcrypt.compareSync(JSON.parse(chunk).password,
                            users.find(user => user.email === JSON.parse(chunk).email).password);
                        if (result) {
                            token = jwt.sign(users.find(user => user.email === JSON.parse(chunk).email), process.env.ACCESS_TOKEN)
                            console.log(result)
                        }
                    });
                    req.on('end', () => {
                        res.statusCode = 200;
                        res.setHeader('Content-Type', 'text/plain');
                        res.setHeader("SET-COOKIE", "ACCESS_TOKEN=" + token + "; SameSite = Strict; Secure; HttpOnly")
                        res.end(token);
                    })
                    break;
                }
                case '/confirm': {
                    req.on('data', chunk => {
                        try {
                            const confirmUser = jwt.verify(JSON.parse(chunk).token, process.env.ACCESS_TOKEN)
                            const user = users.find(user => user.email === confirmUser.email && user.password === confirmUser.password)
                            if (user != null) {
                                user.isConfirmed = true
                            }
                            res.statusCode = 200;
                            res.end()
                        } catch (err) {
                            res.statusCode = 403;
                            if(err.name === 'TokenExpiredError'){
                                var decoded = jwt.decode(JSON.parse(chunk).token);
                                const user = users.find(user => user.email === decoded.email && user.password === decoded.password)
                                if (user != null) {
                                    users.pop(user)
                                }
                                res.statusCode = 401;
                            }
                            res.end()
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
    console.log(`Server running at http://${hostname}:${port}/`);
});

module.exports = http