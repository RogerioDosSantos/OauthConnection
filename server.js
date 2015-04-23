var http = require('http');
var port = process.env.port || 1337;

http.createServer(function (req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Welcome to the Oauth Connection Service\n');
}).listen(port);

//var express = require('express');
//var app = express();

//app.set('port', (process.env.PORT || 5000));
//app.use(express.static(__dirname + '/public'));

//app.get('/', function (request, response) {
//    response.send('Hello World!');
//});

//app.listen(app.get('port'), function () {
//    console.log("Node app is running at localhost:" + app.get('port'));
//});