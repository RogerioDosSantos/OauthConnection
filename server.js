var Http = require("http");
var URL = require("url");
var QueryString = require('querystring');
var Request = require('request');
var Map = require("collections/map");
//var _oauth = require('oauth'), OAuth2 = OAuth.OAuth2;
var Oauth2 = require('./ThirdParty/node-oauth/oauth2.js').OAuth2;

var _port = process.env.PORT || 8080;
var _githubClient = process.env.GITHUB_CLIENT || "04c56461b9d1392277dd";
var _githubSecret = process.env.GITHUB_SECRET || "db3bd6e7393d2910b9f62bbb5c845e9b767ab784";
var _redirectUri = "https://oauth-connection.herokuapp.com";

var _githubOauth = new Oauth2(_githubClient, _githubSecret, "https://github.com/",
    "login/oauth/authorize", "login/oauth/access_token", null /** Custom headers */);
var _responseByID = new Map({});

function urlQueryToJson(query) {
    if (query == null)
        return "";

    var pairs = query.split("&");
    var result = {};
    pairs.forEach(function (pair) {
        pair = pair.split("=");
        if (pair[0] == "")
            return;

        result[pair[0]] = decodeURIComponent(pair[1] || "");
    });

    return JSON.parse(JSON.stringify(result));
}

function queryStringToJson(request) {
    var url = URL.parse(request.url);
    return urlQueryToJson(url.query);
    //var queryString = QueryString.parse(url.query);
    //console.log(queryString);
    //return {};

    //return JSON.parse(queryString.jsonData);
}

function requestAuthentication(id, response) {
    if (id == null)
        return false;

    var authURL = _githubOauth.getAuthorizeUrl({
        redirect_uri: _redirectUri,
        scope: ['repo', 'user'],
        state: id
    });

    _responseByID[id] = response;
    Request(authURL, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var resp = _responseByID[id];
            resp.end(body);

            //console.log(body) // Show the HTML for the Google homepage.
        }
    });

    return true;
}

function sendResponse(response, result) {
    var resp = JSON.stringify(result);
    console.log("Response: " + resp);
    response.writeHead(200, { "Content-Type": "text/html" });
    response.write(resp);
    response.end();
}

function sendError(response, errorCode, errorDescription) {
    sendResponse(response, {
        error: {
            code: errorCode,
            descripton: errorDescription
        }
    });
}

function getPath(request, index) {
    index = index || 1;

    var path = request.url.split("/");
    if (path.length < index)
        return "";

    path = path[index];
    if (path == "" || path.charAt(0) == "?")
        return ""

    path = path.split("?");
    return path[0];
}

function test(id, response) {
    if(id == null)
        return false;

    /**
     * Creating an anchor with authURL as href and sending as response
     */
    var body = "redirectUri = " + _redirectUri;
    var authURL = _githubOauth.getAuthorizeUrl({
        redirect_uri: _redirectUri,
        scope: ['repo', 'user'],
        state: id
    });
    body += "<br /><br />";
    body += "<a href='" + authURL + "'> Get Code </a>";
    response.writeHead(200, {
        'Content-Length': body.length,
        'Content-Type': 'text/html'
    });
    response.end(body);
    return true;
}

function requestAuthenticationPhase1(id, authCode) {
    if (id == null || authCode == null)
        return false;

    /** Obtaining access token */
    oauth2.getOAuthAccessToken(
        authCode,
        { 'redirect_uri': _redirectUri },
        function (error, accessToken, refresh_token, results) {
            var response = _responseByID[id];
            if (response == null){
                console.log("Could not find response: id = " + id);
                return;
            }

            if (error) {
                sendError(response, -2, error);
                return;
            }

            if (results.error) {
                sendResponse(response, results);
            }

            //console.log('Obtained accessToken: ', accessToken);
            sendResponse(response, {
                accessToken: accessToken
            });
        });

    return true;
}

Http.createServer(function (request, response) {

    if (request.method == "POST") {
        var body = "";
        request.on('data', function (data) {           
            body += data;
        });

        var options = null;
        request.on('end', function () {
            options = urlQueryToJson(body);

            requestAuthentication(options.id, response);
        });

        return;
    }

    var path = getPath(request);
    var options = queryStringToJson(request);
    var result = {};
    var error = false;
    switch (path) {
        case "Authenticate":
            error = !requestAuthentication(options.id, response);
            break;

        case "code":
            error = !requestAuthenticationPhase1(options.id, options.code);
            break;

        case "Test":
            error = !test(options.id, response);
            break;


        default:
            result["path"] = path;
            result["options"] = options;
            sendResponse(response, result);
            break;
    }
    
    if (error) {
        sendError(response, -1, "Error to execute " + path);
        return;
    }

    return;

    ///**
    // * Creating an anchor with authURL as href and sending as response
    // */
    //var body = "redirectUri = " + redirectUri;
    //body += "<br /><br />";
    //body += "<a href='" + authURL + "'> Get Code </a>";
    //if (pLen === 2 && p[1] === '') {
    //    res.writeHead(200, {
    //        'Content-Length': body.length,
    //        'Content-Type': 'text/html'
    //    });
    //    res.end(body);
    //} else if (pLen === 2 && p[1].indexOf('code') === 0) {

    //    /** Github sends auth code so that access_token can be obtained */
    //    var qsObj = {};

    //    /** To obtain and parse code='...' from code?code='...' */
    //    qsObj = qs.parse(p[1].split('?')[1]);

    //    /** Obtaining access_token */
    //    oauth2.getOAuthAccessToken(
    //        qsObj.code,
    //        { 'redirect_uri': redirectUri },
    //        function (e, access_token, refresh_token, results) {
    //            if (e) {
    //                console.log(e);
    //                res.end(e);
    //            } else if (results.error) {
    //                console.log(results);
    //                res.end(JSON.stringify(results));
    //            }
    //            else {
    //                console.log('Obtained access_token: ', access_token);
    //                res.end(access_token);
    //            }
    //        });

    //} else {

    //}
   
}).listen(_port);

console.log("Server Running - Port: " + _port);










//var port = process.env.PORT || 8080;
//var GithubClient = process.env.GITHUB_CLIENT || "Invalid Github Client";
//var GithubSecret = process.env.GITHUB_SECRET || "Invalid Github Secret";

//var http = require('http');
//var qs = require('querystring');
//// var OAuth = require('oauth'), OAuth2 = OAuth.OAuth2;
//var OAuth2 = require('./ThirdParty/node-oauth/oauth2.js').OAuth2;

//var clientID = GithubClient;
//var clientSecret = GithubSecret;
//var redirectUri = "https://oauth-connection.herokuapp.com";
////redirectUri += ":" + port;
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
        
//    }

//}).listen(port);
