var Http = require("http");
var URL = require("url");
var QueryString = require('querystring');
//var Request = require('request');
var Map = require("collections/map");
var Q = require("q");
//var _oauth = require('oauth'), OAuth2 = OAuth.OAuth2;
var Oauth2 = require('./ThirdParty/node-oauth/oauth2.js').OAuth2;

var _port = process.env.PORT || 8080;
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

function populateApplicationConfig() {
    var githubClient = process.env.GITHUB_CLIENT || "04c56461b9d1392277dd";
    var githubSecret = process.env.GITHUB_SECRET || "db3bd6e7393d2910b9f62bbb5c845e9b767ab784";
    _providerConfigByType.set(ProviderType.github, {
        name: "github",
        user: githubClient,
        secret: githubSecret,
        redirectUri: "https://oauth-connection.herokuapp.com/Github",
        oauth2: new Oauth2(githubClient, githubSecret, "https://github.com/",
        "login/oauth/authorize", "login/oauth/access_token", null /** Custom headers */)
    })
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
    var id = tokenId.toString() || "";
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
    var id = tokenId.toString() || "";
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
    var providerConfig = getProviderConfig(providerType);
    if (providerConfig == null) {
        log(LogType.error, 5, "Could not get provider configuration");
        return "";
    }

    if (id == null) {
        log(LogType.error, 1, "Invalid id");
        return "";
    }

    return providerConfig.oauth2.getAuthorizeUrl({
        redirect_uri: providerConfig.redirectUri,
        scope: ['repo', 'user'],
        state: id        
    });
}

function getAccessToken(providerType, authenticationCode) {
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

    if (providerConfig.oauth2 == null) {
        deferred.reject(new Error(-1, "Invalid provider config."));
        return deferred.promise;
    }

    providerConfig.oauth2.getOAuthAccessToken(
        authenticationCode,
        { 'redirect_uri': providerConfig.redirectUri },
        function (error, accessToken, refresh_token, results) {
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
        });

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

function test(options, response) {


    sendResponse(response, {
        provider: getProviderConfig("0")
    });

    return true;
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
    if (options.providerType == null) {
        log(LogType.error, 1, "Invalid provider");
        return false;
    }

    var userConfig = getUserConfig(options.applicationName, options.id);
    if (userConfig == null) {
        log(LogType.error, 5, "Could not get user config");
        return false;
    }

    var tokenId = userConfig.getTokenId(options.providerType);
    if (tokenId == "") {
        log(LogType.error, 1, "Provider not supported. Provider: " + options.providerType);
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

function sendRedirection(url, response) {
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

    var id = userConfig.getTokenId(options.providerType);
    if (id == "") {
        log(LogType.error, 1, "Could not get token id. Provider: " + options.providerType);
        return false;
    }

    setReturnUrl(options.returnUrl);

    var authURL = getAuthorizeUrl(options.providerType, id);
    if (!authURL) {
        log(LogType.error, 5, "Could not get authentication URL.");
        return false;
    }

    sendRedirection(authURL, response);
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

function requestAuthenticationPhase1(options, response) {
    if (options == null) {
        log(LogType.error, 1, "Invalid options");
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

    var authCode = options.code;
    if (authCode == null) {
        sendError(response, -3, "Could not find authentication code!");
        return true;
    }

    var returnUrl = getReturnUrl(id);
    getAccessToken(ProviderType.github, authCode)
        .then(function (result) {
            setToken(id, result.accessToken);
            if (returnUrl != "") {
                sendRedirection(returnUrl, response);
                return;
            }

            sendResponse(response, {
                accessToken: result.accessToken
            });


        })
        .fail(function (error) {
            if (returnUrl != "") {
                sendRedirection(returnUrl, response);
                return;
            }

            sendError(response, -2, error);
        });

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
            error = !requestAuthenticationPhase1(options, response);
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

}).listen(_port);

populateApplicationConfig();
debugOptions(null, null);
console.log("Server Running - Port: " + _port);
