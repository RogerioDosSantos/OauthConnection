﻿//var http = require('http');
//var qs = require('querystring');
//// var OAuth = require('oauth'), OAuth2 = OAuth.OAuth2;
//var OAuth2 = require('./ThirdParty/node-oauth/oauth2.js').OAuth2;

//var clientID = "04c56461b9d1392277dd";
//var clientSecret = "a681efffcfb1e60c05661b8d9769ab201dde4c75";
//var port = process.env.port || 8080;
//var redirectUri = "https://oauth-connection.herokuapp.com";
//redirectUri += ":" + port;
//redirectUri += "/code"

//var oauth2 = new OAuth2(clientID,
//                        clientSecret,
//                        'https://github.com/',
//                        'login/oauth/authorize',
//                        'login/oauth/access_token',
//                        null); /** Custom headers */

//http.createServer(function (req, res) {
//    var p = req.url.split('/');
//    pLen = p.length;

//    /**
//     * Authorised url as per github docs:
//     * https://developer.github.com/v3/oauth/#redirect-users-to-request-github-access
//     * 
//     * getAuthorizedUrl: https://github.com/ciaranj/node-oauth/blob/master/lib/oauth2.js#L148
//     * Adding params to authorize url with fields as mentioned in github docs
//     *
//     */
//    var authURL = oauth2.getAuthorizeUrl({
//        redirect_uri: redirectUri,
//        scope: ['repo', 'user'],
//        state: 'some random string to protect against cross-site request forgery attacks'
//    });


//    /**
//     * Creating an anchor with authURL as href and sending as response
//     */
//    var body = "redirectUri = " + redirectUri;
//    body += "<br /><br />";
//    body += "<a href='" + authURL + "'> Get Code </a>";
//    if (pLen === 2 && p[1] === '') {
//        res.writeHead(200, {
//            'Content-Length': body.length,
//            'Content-Type': 'text/html'
//        });
//        res.end(body);
//    } else if (pLen === 2 && p[1].indexOf('code') === 0) {

//        /** Github sends auth code so that access_token can be obtained */
//        var qsObj = {};

//        /** To obtain and parse code='...' from code?code='...' */
//        qsObj = qs.parse(p[1].split('?')[1]);

//        /** Obtaining access_token */
//        oauth2.getOAuthAccessToken(
//            qsObj.code,
//            { 'redirect_uri': redirectUri },
//            function (e, access_token, refresh_token, results) {
//                if (e) {
//                    console.log(e);
//                    res.end(e);
//                } else if (results.error) {
//                    console.log(results);
//                    res.end(JSON.stringify(results));
//                }
//                else {
//                    console.log('Obtained access_token: ', access_token);
//                    res.end(access_token);
//                }
//            });

//    } else {
//        // Unhandled url
//    }

//}).listen(port);


var port = process.env.PORT || 8080;
var http = require("http");

var clientID = process.env.GITHUB_CLIENT || "Invalid Github Client";
var clientSecret = process.env.GITHUB_SECRET || "Invalid Github Secret";

http.createServer(function (request, response) {
    response.writeHead(200, { "Content-Type": "text/plain" });
    response.write("Hello World");
    response.write("\n- " + clientID);
    response.write("\n- " + clientSecret);
    response.end();

    console.log("I am working");
}).listen(port);