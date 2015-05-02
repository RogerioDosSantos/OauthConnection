var Http = require("http");
var URL = require("url");
var QueryString = require("querystring");
var Map = require("collections/map");
var Q = require("q");
//var Oauth1 = require("./ThirdParty/node-oauth/oauth.js").OAuth;
var Oauth2 = require("./ThirdParty/node-oauth/oauth2.js").OAuth2;
var Evernote = require('evernote').Evernote;

//Server Environment Variables
var PORT = process.env.PORT || 8080;
var SERVER_URL = process.env.SERVER_URL || "http://localhost:" + PORT;  //TODO: Put the SERVER_URL to be https://oauth-connection.herokuapp.com
var GITHUB_CLIENT = process.env.GITHUB_CLIENT || "Your client";
var GITHUB_SECRET = process.env.GITHUB_SECRET || "Your secret";
var EVERNOTE_CLIENT = process.env.EVERNOTE_CLIENT || "Your client";
var EVERNOTE_SECRET = process.env.EVERNOTE_SECRET || "Your secret";
var EVERNOTE_USESANDBOX = process.env.EVERNOTE_USESANDBOX || false;

var _providerConfigByType = new Map({});
var _userConfigByAppNameIdKey = new Map({})
var _tokenById = new Map({});
var _returnUrlById = new Map({});
var _debugOptions = {};

var LogType = {
    error: 0,
    warning: 1,
    info: 2,
    rankLast: 3
};

var ProviderType = {
    github: 0,
    evernote: 1,
    rankLast: 2
}

function log(logType, level, description, caller) {
    if (_debugOptions.enableLog == 0)
        return;

    var enabled = true;
    if (_debugOptions.verbose == 0) {
        switch (logType) {
            case LogType.error:
                enabled = _debugOptions.errorLevel != 0 && _debugOptions.errorLevel >= level;
                break;

            case LogType.warning:
                enabled = _debugOptions.warningLevel != 0 && _debugOptions.warningLevel >= level;
                break;

            case LogType.info:
                enabled = _debugOptions.infoLevel != 0 && _debugOptions.infoLevel >= level;
                break;

            default:
                enabled = false;
                break;
        }
    }

    if (!enabled)
        return;

    if (caller == null)
        caller = log.caller;

    var functionName = caller.name || "Unknown";
    var message = "[Type: " + logType + ", Level: " + level + ", Function: " + functionName + "] - " + description;
    if (_debugOptions.console > 0) {
        console.log(message);
    }
}

function UserConfig(applicationName, id) {
    this.applicationName = applicationName;
    this.id = id;

    UserConfig.prototype.getTokenId = function (providerType) {
        if (providerType == null || ProviderType.rankLast <= providerType)
            return "";

        return providerType + "-" + id;
    }
}

function Error(level, description) {
    var caller = Error.caller;
    this.functionName = caller.name || "Unknown";
    this.description = description;
    this.name = "UserException";
    this.level = level;

    log(LogType.error, level, description, caller);
}

function toEnumerator(enumaratorType, value) {
    var tempValue = value || enumaratorType.rankLast;
    tempValue = parseInt(tempValue, 10);
    if (tempValue > enumaratorType.rankLast || tempValue < 0)
        tempValue = enumaratorType.rankLast;

    var values = Object.values(enumaratorType);
    return values[tempValue];
}

function populateApplicationConfig() {
    _providerConfigByType.set(ProviderType.github, {
        name: "github",
        user: GITHUB_CLIENT,
        secret: GITHUB_SECRET,
        redirectUri: SERVER_URL + "/Github",
        oauth2: new Oauth2(GITHUB_CLIENT, GITHUB_SECRET, "https://github.com/",
        "login/oauth/authorize", "login/oauth/access_token", null /** Custom headers */)
    })

    _providerConfigByType.set(ProviderType.evernote, {
        name: "evernote",
        user: EVERNOTE_CLIENT,
        secret: EVERNOTE_SECRET,
        redirectUri: SERVER_URL + "/Evernote",
        envernoteClient: new Evernote.Client({
            consumerKey: EVERNOTE_CLIENT,
            consumerSecret: EVERNOTE_SECRET,
            sandbox: EVERNOTE_USESANDBOX
        })
    }); 
}

function setToken(tokenId, token) {
    if (tokenId == null || tokenId == "") {
        throw new Error(1, "Invalid Token id");
    }

    tokenId = tokenId.toString();
    if (_tokenById.length > 10000) {
        log(LogType.warning, 1, "Token by id is consuming too much memory.");
        _tokenById.clear();
    }

    log(LogType.info, 5, "Added new token: id= " + tokenId);
    _tokenById.set(tokenId, token);
}

function getToken(tokenId) {
    var id = tokenId || "";
    id = id.toString();
    if (!_tokenById.has(id)) {
        log(LogType.info, 5, "Could not find token: id= " + id);
        return "";
    }

    return _tokenById.get(id);
}

function setReturnUrl(tokenId, returnUrl) {
    if (tokenId == null) {
        throw new Error(1, "Invalid Token id");
    }

    returnUrl = returnUrl || "";
    tokenId = tokenId.toString();
    if (_returnUrlById.length > 10000) {
        log(LogType.warning, 1, "Return Url by id is consuming too much memory.");
        _returnUrlById.clear();
    }

    log(LogType.info, 5, "Added new return Url: id= " + tokenId);
    _returnUrlById.set(tokenId, returnUrl);
}

function getReturnUrl(tokenId) {
    var id = tokenId || "";
    id = id.toString();
    if (!_returnUrlById.has(id)) {
        log(LogType.info, 5, "Could not find return Url: id= " + id);
        return "";
    }

    return _returnUrlById.get(id);
}


function getProviderConfig(providerType) {
    if (providerType == null || ProviderType.rankLast <= providerType) {
        log(LogType.error, 1, "Invalid provider type");
        return null;
    }

    providerType = parseInt(providerType);
    return _providerConfigByType.get(providerType);
}

function getAuthorizeUrl(providerType, id) {
    var deferred = Q.defer();
    var providerConfig = getProviderConfig(providerType);
    if (providerConfig == null) {
        deferred.reject(new Error(5, "Could not get provider configuration"));        
        return deferred.promise;
    }

    if (id == null) {
        deferred.reject(new Error(1, "Invalid id"));
        return deferred.promise;
    }

    switch (providerType) {
        case ProviderType.evernote:
            providerConfig.envernoteClient.getRequestToken(providerConfig.redirectUri + "?state=" + id,
                function (error, oauthToken, oauthTokenSecret, results) {
                    //We are using the token by id map to hold the temporary token secret.
                    setToken(id, oauthTokenSecret);                    
                    var url = providerConfig.envernoteClient.getAuthorizeUrl(oauthToken);
                    deferred.resolve({
                        url: url
                    });
                });

            break;

        case ProviderType.github:
            deferred.resolve({
                url: providerConfig.oauth2.getAuthorizeUrl({
                    redirect_uri: providerConfig.redirectUri,
                    scope: "user,repo",
                    state: id
                })
            });

            break;

        default:
            log(LogType.error, 1, "Invalid provider");
            break;
    }

    return deferred.promise;
}

function handleAccessCodeAnswer(deferred, error, accessToken, tempToken, results) {
    if (error) {
        deferred.reject(new Error(2, error));
        return;
    }

    if (results.error) {
        deferred.reject(new Error(2, results));
        return;
    }

    deferred.resolve({
        result: results,
        accessToken: accessToken
    });

    log(LogType.info, 1, "Obtained accessToken: " + accessToken);
}

function getAccessToken(providerType, tempToken, tempSecret, authenticationCode) {
    var deferred = Q.defer();
    var providerConfig = getProviderConfig(providerType);
    if (providerConfig == null) {
        deferred.reject(new Error(5, "Could not get provider configuration"));
        return deferred.promise;
    }

    if (authenticationCode == null) {
        deferred.reject(new Error(1, "Invalid authentication code."));
        return deferred.promise;
    }

    switch (providerType) {
        case ProviderType.evernote:
            providerConfig.envernoteClient.getAccessToken(tempToken, tempSecret, authenticationCode,
                function (error, accessToken, refresh_token, results) {
                    handleAccessCodeAnswer(deferred, error, accessToken, refresh_token, results);
                });
            break;

        case ProviderType.github:
            providerConfig.oauth2.getOAuthAccessToken(authenticationCode,
                { 'redirect_uri': providerConfig.redirectUri },
                function (error, accessToken, refresh_token, results) {
                    handleAccessCodeAnswer(deferred, error, accessToken, refresh_token, results);
                });


            //providerConfig.oauth2.getOAuthAccessToken(
            //    authenticationCode,
            //    { 'redirect_uri': providerConfig.redirectUri },
            //    function (error, accessToken, refresh_token, results) {
            //        if (error) {
            //            deferred.reject(new Error(2, error));
            //            return;
            //        }

            //        if (results.error) {
            //            deferred.reject(new Error(2, results));
            //            return;
            //        }

            //        deferred.resolve({
            //            result: results,
            //            accessToken: accessToken
            //        });

            //        log(LogType.info, 1, "Obtained accessToken: " + accessToken);
            //    });

            break;

        default:
            deferred.reject(new Error(1, "Invalid provider"));
            break;
    }


    return deferred.promise;
}

function getUserConfig(applicationName, id) {
    if (id == null) {
        log(LogType.error, 1, "Invalid id");
        return null;
    }

    if (applicationName == null) {
        log(LogType.error, 1, "Invalid application name");
        return null;
    }

    applicationName = applicationName.toLowerCase();

    var appNameIdKey = applicationName + "-" + id;
    var userConfig = _userConfigByAppNameIdKey.get(appNameIdKey);
    if (userConfig == null) {
        userConfig = new UserConfig(applicationName, id);
        if (_userConfigByAppNameIdKey.length > 10000) {
            log(LogType.warning, 1, "User config by app name is consuming too much memory.");
            _userConfigByAppNameIdKey.clear();
        }

        _userConfigByAppNameIdKey.set(appNameIdKey, userConfig);
        log(LogType.info, 1, "New user configuration: " + JSON.stringify(userConfig));
    }

    return userConfig;
}

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
}

function sendError(response, errorCode, errorDescription) {
    sendResponse(response, {
        error: {
            code: errorCode,
            description: errorDescription
        }
    });
}

function sendResponse(response, result) {
    var resp = JSON.stringify(result);
    log(LogType.info, 5, "Response: " + resp);
    response.writeHead(200, { "Content-Type": "text/html" });
    response.write(resp);
    response.end();
}

function requestToken(options, response) {
    options = options || {};
    var providerType = toEnumerator(ProviderType, options.providerType);
    if (providerType >= ProviderType.rankLast) {
        log(LogType.error, 1, "Invalid provider");
        return false;
    }

    var userConfig = getUserConfig(options.applicationName, options.id);
    if (userConfig == null) {
        log(LogType.error, 5, "Could not get user config");
        return false;
    }
    
    var tokenId = userConfig.getTokenId(providerType);
    if (tokenId == "") {
        log(LogType.error, 1, "Provider not supported. Provider: " + providerType);
        return false;
    }

    var token = getToken(tokenId);
    var needAuthentication = token == "";

    sendResponse(response, {
        token: token,
        needAuthentication: needAuthentication
    });
    return true;
}

function sendRedirection(response, url) {

    log(LogType.info, 5, "Redirecting to: " + url);

    var body = "<script type='text/javascript'>";
    body += "window.location.href = '" + url + "'";
    body += "</script>";
    response.writeHead(200, {
        'Content-Length': body.length,
        'Content-Type': 'text/html'
    });
    response.end(body);
}

function requestAuthenticationPhase0(options, response) {
    options = options || {};
    var userConfig = getUserConfig(options.applicationName, options.id);
    if (userConfig == null) {
        log(LogType.error, 5, "Could not get user config");
        return false;
    }

    var providerType = toEnumerator(ProviderType, options.providerType);
    var id = userConfig.getTokenId(providerType);
    if (id == "") {
        log(LogType.error, 1, "Could not get token id. Provider: " + providerType);
        return false;
    }

    setReturnUrl(id, options.returnUrl);

    getAuthorizeUrl(providerType, id)
    .then(function (result) {
        if (!result.url) {
            log(LogType.error, 1, "Could not get authentication URL. Detail: " + error);
            return;
        }

        sendRedirection(response, result.url);
    })
    .fail(function (error) {
        log(LogType.error, 1, "Could not get authentication URL. Detail: " + error);
    });

    return true;
}

function parseValue(value, defaultValue) {
    var resp = parseInt(value);
    if (isNaN(resp))
        return defaultValue;

    return resp;
}

function debugOptions(options, response) {
    options = options || {};
    _debugOptions["enableLog"] = parseValue(options.enableLog, _debugOptions.enableLog || 0);
    _debugOptions["verbose"] = parseValue(options.verbose, _debugOptions.verbose || 0);

    _debugOptions["console"] = parseValue(options.console, _debugOptions.console || 1);

    _debugOptions["errorLevel"] = parseValue(options.errorLevel, _debugOptions.errorLevel || 0);
    _debugOptions["warningLevel"] = parseValue(options.warningLevel, _debugOptions.warningLevel || 0);
    _debugOptions["infoLevel"] = parseValue(options.infoLevel, _debugOptions.infoLevel || 0);

    if (_debugOptions.errorLevel == 0 && options.errorLevel == null && options.enableLog != null && options.enableLog)
        _debugOptions.errorLevel = 1;

    if (response != null)
        sendResponse(response, _debugOptions);
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

function requestAuthenticationPhase1(options, response, providerType) {
    if (options == null) {
        log(LogType.error, 1, "Invalid options");
        return false;
    }

    if (providerType >= ProviderType.rankLast) {
        log(LogType.error, 1, "Could not find provider type!");
        return false;
    }

    var id = options.state;
    if (id == null) {
        log(LogType.error, 1, "Invalid id");
        return false;
    }

    if (response == null) {
        log(LogType.error, 1, "Could not find response: id = " + id);
        return false;
    }

    var returnUrl = getReturnUrl(id);
    if (returnUrl == "") {
        //log(LogType.error, 1, "Could not find the return URL!");
        //return false;
    }

    var tempToken = null;
    var tempSecret = null;
    var authenticationCode = null;
    switch (providerType) {
        case ProviderType.evernote:
            authenticationCode = options.oauth_verifier;
            tempToken = options.oauth_token;
            if (tempToken == null) {
                log(LogType.error, 1, "Could not find temp token!");
                return false;
            }

            tempSecret = getToken(id);
            if (tempToken == null) {
                log(LogType.error, 1, "Could not find temp token secret!");
                return false;
            }

            break;

        case ProviderType.github:
            authenticationCode = options.code;
            break;
        default:
            log(LogType.error, 1, "Invalid Provider Type!");
            return false;
    }

    if (authenticationCode == null) {
        log(LogType.error, 1, "Could not find authentication code!");
        return true;
    }

    getAccessToken(providerType, tempToken, tempSecret, authenticationCode)
        .then(function (result) {
            setToken(id, result.accessToken);
            if (returnUrl != "") {
                sendRedirection(response, returnUrl);
                return;
            }

            sendResponse(response, {
                accessToken: result.accessToken
            });


        })
        .fail(function (error) {
            if (returnUrl != "") {
                sendRedirection(response, returnUrl);
                return;
            }

            sendError(response, -2, error);
        });

    return true;
}

//var _tempToken = "";
//var _tempSecret = "";
function test(options, response) {

    //console.log(options);
    var providerType = toEnumerator(ProviderType, options.providerType);
    //var keys = Object.keys(ProviderType);
    //var values = Object.values(ProviderType);
    //console.log("Keys = " + keys);
    //console.log("values = " + values);
    //providerType = parseInt(providerType, 10);
    //console.log("providerType = " + providerType);


    //providerType = keys[providerType];
    //providerType = values[providerType];
    console.log("providerType = " + providerType);

    switch (providerType) {
        case ProviderType.github:
            sendResponse(response, {
                provider: "Github"
            });
            break;

        case ProviderType.evernote:
            sendResponse(response, {
                provider: "Evernote"
            });
            break;

        default:
            sendResponse(response, {
                provider: "Invalid Provider"
            });
            break;
    }

    //var state = options.state || "0";
    //console.log("Test - State: " + state);

    //if (_envernoteClient == null) {
    //    _envernoteClient = new Evernote.Client({
    //        consumerKey: "roger-3576",
    //        consumerSecret: "aadb5fffc9cf4617",
    //        sandbox: true
    //    });
    //}
    
    //switch (state) {
    //    case "0":           
    //        _envernoteClient.getRequestToken("http://localhost:8080/Test?state=1",
    //            function (error, oauthToken, oauthTokenSecret, results) {
    //                // store tokens in the session
    //                _tempToken = oauthToken;
    //                _tempSecret = oauthTokenSecret;
    //                // and then redirect to client.getAuthorizeUrl(oauthToken)
    //                var url = _envernoteClient.getAuthorizeUrl(oauthToken);
    //                sendRedirection(response, url);
    //            });
    //        break;

    //    case "1":
    //        console.log("Temp Token: " + _tempToken);
    //        console.log("Temp Secret: " + _tempSecret);
    //        console.log("Oauth Token:" + options.oauth_token);
    //        console.log("Oauth Verifier:" + options.oauth_verifier);

    //        _envernoteClient.getAccessToken(_tempToken, _tempSecret, options.oauth_verifier,
    //            function (error, oauthAccessToken, oauthAccessTokenSecret, results) {
    //                sendResponse(response, {
    //                    token: oauthAccessToken,
    //                    oauthAccessTokenSecret: oauthAccessTokenSecret,
    //                });
    //            });                
    //        break;

    //    default:
    //        sendError(response, -1, "Invalid State");

    //}


    //var providerConfig = getProviderConfig(ProviderType.evernote);
    //if (providerConfig == null) {
    //    log(LogType.error, 5, "Could not get provider configuration");
    //    return "";
    //}


    ////this._performSecureRequest(oauth_token, oauth_token_secret, "GET", url, null, "", null, callback);  
    ////function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback )

    //https://sandbox.evernote.com/oauth?oauth_callback=http://www.foo.com&oauth_consumer_key=sample-api-key-4121&oauth_nonce=3166905818410889691&oauth_signature=T0+xCYjTiyz7GZiElg1uQaHGQ6I=&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1429565574&oauth_version=1.0

    //providerConfig.oauth1.get(
    //  "https://sandbox.evernote.com/oauth",
    //  providerConfig.user,
    //  providerConfig.secret,
    //  function (e, data, res){
    //      if (e) {
    //          sendResponse(response, {
    //              error: e
    //          });
    //          return;
    //      }
    //      var token = require('util').inspect(data);
    //      sendResponse(response, {
    //          token: token
    //      });
    //  });


    return true;
}

Http.createServer(function (request, response) {

    //if (request.method == "POST") {
    //    var body = "";
    //    request.on('data', function (data) {           
    //        body += data;
    //    });

    //    var options = null;
    //    request.on('end', function () {
    //        options = urlQueryToJson(body);

    //        requestAuthenticationPhase0(options, response);
    //    });

    //    return;
    //}

    var path = getPath(request);
    log(LogType.info, 5, "Received command for Path: " + path);

    var options = queryStringToJson(request);
    var result = {};
    var error = false;
    switch (path) {
        case "Token":
            error = !requestToken(options, response);
            break;

        case "Authenticate":
            error = !requestAuthenticationPhase0(options, response);
            break;

        case "Github":
            error = !requestAuthenticationPhase1(options, response, ProviderType.github);
            break;

        case "Evernote":
            error = !requestAuthenticationPhase1(options, response, ProviderType.evernote);
            break;

        case "DebugOptions":
            error = !debugOptions(options, response);
            break;

        case "Test":
            error = !test(options, response);
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

}).listen(PORT);

populateApplicationConfig();
debugOptions(null, null);
console.log("Server Running - Url: " + SERVER_URL);
