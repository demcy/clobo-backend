require('dotenv').config()

const http = require('http');

const hostname = 'localhost';
const port = 4000;

const bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');

const users = []

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', true);
    
    //res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Methods', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
    console.log(req.url + req.method)
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
                    if(req.headers.cookie == null){
                        res.statusCode = 401
                        res.setHeader('Content-Type', 'text/plain');
                        res.end()
                        break
                    }
                    console.log(req.headers.cookie)
                    console.log(req.headers.cookie.split('=')[1])
                    const tokenUser = jwt.verify(req.headers.cookie.split('=')[1], process.env.TOKEN_SECRET)
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
                        const hash = bcrypt.hashSync(JSON.parse(chunk).password, 10);
                        users.push({ email: JSON.parse(chunk).email, password: hash })

                    });
                    req.on('end', () => {
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
                            token = jwt.sign(users.find(user => user.email === JSON.parse(chunk).email), process.env.TOKEN_SECRET)
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