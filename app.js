require('dotenv').config()

const http = require('http');

const hostname = 'localhost';
const port = 4000;

const bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');

const users = [{email: 'aaaa',password: 'aaaa'}]

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
    switch (req.method) {
        case 'GET': {
            switch (req.url) {
                case '/': {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Index\n');
                    break;
                }
                case '/users': {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end(JSON.stringify(users));
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
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Index\n');
                    break;
                }
                case '/login': {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'text/plain');
                    res.end('Index\n');
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

function authencticateToken(req, res) {
    console.log('hi')
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.setHeader(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.setHeader(403)
        //console.log(req.user)
        req.user = user
        //console.log(req.user)
        return true
    })
};

server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});