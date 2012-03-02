dojo.require("dojo.cookie");

var oauth_version = '1.0';
var oauth_signature_method = "HMAC-SHA1";

function get_by_url(e) {
    e.preventDefault();

    var parameters = dojo.fromJson(dojo.byId('params').value);
    var use_auth = dojo.byId('use_auth').checked
    var host = dojo.byId('host').value
    var req_url = host + dojo.byId('url').value;
    var headers = {}
    var method = dojo.byId('method').value;

    if (use_auth) {
        //формирую Authorization Header
        //для get параметры должны идти как обычно, для post и put в raw формате
        var params = {}

        if (method != 'put') for (param in parameters) params[param] = parameters[param];

        params.oauth_token = dojo.byId('access_token').value;
        params.oauth_timestamp = OAuth.timestamp();
        params.oauth_nonce = OAuth.nonce(11);
        params.oauth_consumer_key = dojo.byId('access_consumer_key').value;
        params.oauth_version = oauth_version;
        params.oauth_signature_method = oauth_signature_method;

        var realm = OAuth.SignatureMethod.normalizeUrl(req_url);

        var access_token_secret = dojo.byId('access_token_secret').value;

        var req_method = method.toUpperCase();
        var consumer_secret = dojo.byId('access_consumer_secret').value;

        var message = {
            method: req_method,
            action: req_url,
            parameters: params
        };

        baseString = OAuth.SignatureMethod.getBaseString(message);

        console.log(consumer_secret + '&' + access_token_secret + ' ' + baseString);

        b64pad = '=';
        var signature = b64_hmac_sha1(consumer_secret + '&' + access_token_secret, baseString);

        params.oauth_signature = signature;
        console.log(signature);

        header = OAuth.getAuthorizationHeader("API", params);

        headers['Authorization'] = header
    }

    xhrArgs = {
        url: req_url,
        content: parameters,
        headers: headers,
        load: function(response) {
            dojo.byId('response').value = response;
        },
        error: function(error) {
            dojo.byId('response').value = error;
        }
    }

    if (method == 'get') dojo.xhrGet(xhrArgs);
    else if (method == 'post') {
        dojo.xhrPost(xhrArgs);
    } else if (method == 'put') {
        dojo.xhrPut(xhrArgs);
    } else if (method == 'delete') dojo.xhrDelete(xhrArgs);

    return false;
}

function authorize(e) {
    e.preventDefault();

    var host = dojo.byId('host').value
    var params = {}
    params.oauth_timestamp = OAuth.timestamp();
    params.oauth_nonce = OAuth.nonce(11);
    params.oauth_consumer_key = dojo.byId('consumer_key').value;
    params.oauth_version = oauth_version;
    params.oauth_signature_method = oauth_signature_method;

    //xauth params
    params.x_auth_password = dojo.byId('xauth_password').value;
    params.x_auth_username = dojo.byId('xauth_username').value;
    params.x_auth_mode = 'client_auth';

    var req_url = host+'/api/oauth/access_token/';
    var req_method = 'POST';
    var consumer_secret = dojo.byId('consumer_secret').value;

    var message = {
        method: req_method,
        action: req_url,
        parameters: params
    };

    baseString = OAuth.SignatureMethod.getBaseString(message);
    b64pad = '=';
    console.log(baseString);
    var signature = b64_hmac_sha1(consumer_secret + '&', baseString);
    console.log(signature);
    params.oauth_signature = signature;

    xhrArgs = {
        url: req_url,
        content: params,
        load: function(response) {
            dojo.byId('response').value = response;

            parameters = OAuth.decodeForm(response);
            //console.log(parameters);
            for (key in parameters)
            if (parameters[key][0] == 'oauth_token') dojo.byId('oauth_token').value = parameters[key][1];
            else dojo.cookie(parameters[key][0], parameters[key][1]);

            dojo.cookie('oauth_consumer_key', params.oauth_consumer_key);
            dojo.cookie('oauth_consumer_secret', consumer_secret);

        },
        error: function(error) {
            dojo.empty('result');
            dojo.place("<div> Ошибка связи </div> ", dojo.byId('result'), 'first');
        }
    }

    dojo.xhrPost(xhrArgs);

    return false;
}

function init() {
    dojo.query('#get_response').onclick(get_by_url);
    dojo.query('#authorize').onclick(authorize);
}

dojo.ready(init);