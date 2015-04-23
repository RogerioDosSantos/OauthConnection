﻿var http = require('http');
var port = process.env.port || 1337;

http.createServer(function (req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Welcome to the Oauth Connection Service\n');
}).listen(port);