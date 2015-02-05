'use strict';

(function (global, $) {

  var
    exp = {},
    config = {},
    default_lifetime = 3600,
    options = {
      'debug': false
    },

    api_redirect,
    Api_default_storage,
    api_storage,

    internalStates = [];

  /*
   * ------ SECTION: Utilities
   */

  /*
   * Returns a random string used for state
   */
  var uuid = function () {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  };

  /**
   * A log wrapper, that only logs if logging is turned on in the config
   * @param  {string} msg Log message
   */
  var log = function (msg) {
    if (!options.debug) return;
    if (!console) return;
    if (!console.log) return;

    // console.log("LOG(), Arguments", arguments, msg)
    if (arguments.length > 1) {
      console.log(arguments);
    } else {
      console.log(msg);
    }

  };

  /**
   * Set the global options.
   */
  var setOptions = function (opts) {
    if (!opts) return;
    for (var k in opts) {
      if (opts.hasOwnProperty(k)) {
        options[k] = opts[k];
      }
    }
    log('Options is set to ', options);
  };


  /*
   * Takes an URL as input and a params object.
   * Each property in the params is added to the url as query string parameters
   */
  var encodeURL = function (url, params) {
    var res = url;
    var k, i = 0;
    var firstSeparator = (url.indexOf('?') === -1) ? '?' : '&';
    for (k in params) {
      if (params.hasOwnProperty(k)) {
        res += (i++ === 0 ? firstSeparator : '&') + encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
      }
    }
    return res;
  };


  /*
   * Returns epoch, seconds since 1970.
   * Used for calculation of expire times.
   */
  var epoch = function () {
    return Math.round(new Date().getTime() / 1000.0);
  };


  var parseQueryString = function (qs) {
    var e,
      a = /\+/g,  // Regex for replacing addition symbol with a space
      r = /([^&;=]+)=?([^&;]*)/g,
      d = function (s) {
        return decodeURIComponent(s.replace(a, ' '));
      },
      urlParams = {};

    while (e = r.exec(qs))
      urlParams[d(e[1])] = d(e[2]);

    return urlParams;
  };
  /*
   * ------ / SECTION: Utilities
   */


  /*
   * Redirects the user to a specific URL
   */
  api_redirect = function (url) {
    var newWindow = window.open(url, 'oauth2_dialogue', 'height=600,width=450');
    if (newWindow.focus) {
      newWindow.focus();
    }
    return newWindow;
    //window.location = url;
  };

  Api_default_storage = function () {
    log('Constructor');
  };

  /**
   saveState stores an object with an Identifier.
   TODO: Ensure that both localstorage and JSON encoding has fallbacks for ancient browsers.
   In the state object, we put the request object, plus these parameters:
   * restoreHash
   * providerID
   * scopes

   */
  Api_default_storage.prototype.saveState = function (state, obj, secondTry) {
    try {
      localStorage.setItem('state-' + state, JSON.stringify(obj));
    } catch (e) {
      var cleaningResult = this.cleanStates();

      if (cleaningResult && !secondTry) {
        this.saveState(state, obj, true);
      }
    }
  };

  Api_default_storage.prototype.cleanStates = function () {
    var cleaned = 0;

    try {
      for (var item in localStorage) {
        if (localStorage.hasOwnProperty(item) && item.indexOf('state-') === 0) {
          localStorage.removeItem(item);
          cleaned++;
        }
      }
    } catch (e) {
      cleaned = null;
    }

    return cleaned;
  };

  /**
   * getStage()  returns the state object, but also removes it.
   * @type {Object}
   */
  Api_default_storage.prototype.getState = function (state) {
    // log("getState (" + state+ ")");
    var obj = JSON.parse(localStorage.getItem('state-' + state));
    this.cleanStates();
    return obj;
  };


  /*
   * Checks if a token, has includes a specific scope.
   * If token has no scope at all, false is returned.
   */
  var hasScope = function (token, scope) {
    var i;
    if (!token.scopes) return false;
    for (i = 0; i < token.scopes.length; i++) {
      if (token.scopes[i] === scope) return true;
    }
    return false;
  };

  /*
   * Takes an array of tokens, and removes the ones that
   * are expired, and the ones that do not meet a scopes requirement.
   */
  var filterTokens = function (tokens, scopes) {
    var i, j,
      result = [],
      now = epoch(),
      usethis;

    if (!scopes) scopes = [];

    for (i = 0; i < tokens.length; i++) {
      usethis = true;

      // Filter out expired tokens. Tokens that is expired in 1 second from now.
      if (tokens[i].expires && tokens[i].expires < (now + 1)) usethis = false;

      // Filter out this token if not all scope requirements are met
      for (j = 0; j < scopes.length; j++) {
        if (!this.hasScope(tokens[i], scopes[j])) usethis = false;
      }

      if (usethis) result.push(tokens[i]);
    }
    return result;
  };


  /*
   * saveTokens() stores a list of tokens for a provider.

   Usually the tokens stored are a plain Access token plus:
   * expires : time that the token expires
   * providerID: the provider of the access token?
   * scopes: an array with the scopes (not string)
   */
  Api_default_storage.prototype.saveTokens = function (provider, tokens) {
    // log("Save Tokens (" + provider+ ")");
    localStorage.setItem('tokens-' + provider, JSON.stringify(tokens));
  };

  Api_default_storage.prototype.getTokens = function (provider) {
    // log("Get Tokens (" + provider+ ")");
    if (provider) {
      var tokens = JSON.parse(localStorage.getItem('tokens-' + provider));
      if (!tokens) tokens = [];

      log('Token received', tokens);
      return tokens;
    }

    var out = [];

    for (var item in localStorage) {
      if (localStorage.hasOwnProperty(item) && item.indexOf('state-') === 0) {
        try {
          out.push(JSON.parse(localStorage.getItem(item)) || []);
        }
        catch (e) {
          out.push([]);
        }
      }
    }
    return out;
  };

  Api_default_storage.prototype.wipeTokens = function (provider) {
    localStorage.removeItem('tokens-' + provider);
  };
  /*
   * Save a single token for a provider.
   * This also cleans up expired tokens for the same provider.
   */
  var saveToken = function (provider, token) {
    var tokens = this.getTokens(provider);
    tokens = this.filterTokens(tokens);
    tokens.push(token);
    this.saveTokens(provider, tokens);
  };

  /*
   * Get a token if exists for a provider with a set of scopes.
   * The scopes parameter is OPTIONAL.
   */
  var getToken = function (provider, scopes) {
    var tokens = this.getTokens(provider);
    tokens = this.filterTokens(tokens, scopes);
    if (tokens.length < 1) return null;
    return tokens[tokens.length - 1];
  };

  /*
   * Get all stored and valid tokens.
   */
  var getAllTokens = function() {
    var tokens = this.getTokens();
    for (var i = 0; i < tokens.length; i++) {
      tokens[i] = this.filterTokens(tokens[i]);

      if (tokens[i].length < 0) {
        tokens.splice(i, 1);
        i--;
      }
    }
    return tokens;
  };

  // Keep storage unrelated methods inside jso
  var extendStorageAPI = function (API) {
    API.hasScope = hasScope;
    API.filterTokens = filterTokens;
    API.getToken = getToken;
    API.saveToken = saveToken;
    API.getAllTokens = getAllTokens;
  };

  api_storage = new Api_default_storage();
  extendStorageAPI(api_storage);


  /**
   * Check if the hash contains an access token.
   * And if it do, extract the state, compare with
   * config, and store the access token for later use.
   *
   * The url parameter is optional. Used with phonegap and
   * childbrowser when the jso context is not receiving the response,
   * instead the response is received on a child browser.
   */
  exp.checkForToken = function (providerID, url) {
    var
      atoken,
      h = window.location.toString().replace(/^[^#]*/, ''), // Because of stupid Firefox bug — https://bugzilla.mozilla.org/show_bug.cgi?id=483304
      now = epoch(),
      state,
      co;

    log('checkForToken(' + providerID + ')');

    // If a url is provided
    if (url) {
      // log('Hah, I got the url and it ' + url);
      if (url.indexOf('#') === -1) return;
      h = url.substring(url.indexOf('#'));
      // log('Hah, I got the hash and it is ' +  h);
    }

    if (h.length < 2) return;
    atoken = parseQueryString(h.substring(1));

    // Check for errors
    if (atoken.error) {
      throw 'Error in auth request: ' + atoken.error;
    }

    /*
     * Start with checking if there is a token in the hash
     */
    if (!atoken.access_token) return;

    if (atoken.state) {
      state = api_storage.getState(atoken.state);
    } else {
      if (!providerID) {
        throw 'Could not get [state] and no default providerid is provided.';
      }
      state = {providerID: providerID};
    }


    if (!state) throw 'Could not retrieve state';
    if (!state.providerID) throw 'Could not get providerid from state';
    if (!config[state.providerID]) throw 'Could not retrieve config for this provider.';
    co = config[state.providerID];

    /**
     * If state was not provided, and default provider contains a scope parameter
     * we assume this is the one requested...
     */
    if (!atoken.state && co.scope) {
      state.scopes = co.scope;
      log('Setting state: ', state);
    }
    log('Checking atoken ', atoken, ' and co ', co);

    /*
     * Decide when this token should expire.
     * Priority fallback:
     * 1. Access token expires_in
     * 2. Life time in config (may be false = permanent...)
     * 3. Specific permanent scope.
     * 4. Default library lifetime:
     */
    if (atoken['expires_in']) {
      atoken['expires'] = now + parseInt(atoken['expires_in'], 10);
    } else if (co['default_lifetime'] === false) {
      // Token is permanent.
    } else if (co['default_lifetime']) {
      atoken['expires'] = now + co['default_lifetime'];
    } else if (co['permanent_scope']) {
      if (!api_storage.hasScope(atoken, co['permanent_scope'])) {
        atoken['expires'] = now + default_lifetime;
      }
    } else {
      atoken['expires'] = now + default_lifetime;
    }

    /*
     * Handle scopes for this token
     */
    if (atoken['scope']) {
      atoken['scopes'] = atoken['scope'].split(' ');
    } else if (state['scopes']) {
      atoken['scopes'] = state['scopes'];
    }


    api_storage.saveToken(state.providerID, atoken);

    if (state.restoreHash) {
      window.location.hash = state.restoreHash;
    } else {
      window.location.hash = '';
    }


    log(atoken);

    if (internalStates[atoken.state] && typeof internalStates[atoken.state] === 'function') {
      // log("InternalState is set, calling it now!");
      internalStates[atoken.state]();
      delete internalStates[atoken.state];
    }

    // log(atoken);

    return state.restoreLocation;
  };

  /*
   * A config object contains:
   */
  exp.authRequest = function (providerid, scopes, callback, extraQueryParameters) {

    var
      state,
      request,
      authurl,
      co;

    if (!config[providerid]) throw 'Could not find configuration for provider ' + providerid;
    co = config[providerid];

    log('About to send an authorization request to [' + providerid + ']. Config:');
    log(co);

    state = uuid();
    request = {
      'response_type': 'token'
    };
    request.state = state;

    if (callback && typeof callback === 'function') {
      internalStates[state] = callback;
    }

    if (co['redirect_uri']) {
      request['redirect_uri'] = co['redirect_uri'];
    }
    if (co['client_id']) {
      request['client_id'] = co['client_id'];
    }
    if (scopes) {
      request['scope'] = scopes.join(' ');
    }
    if (extraQueryParameters) {
      for (var parameterName in extraQueryParameters) {
        if (extraQueryParameters.hasOwnProperty(parameterName)) {
          request[parameterName] = extraQueryParameters[parameterName];
        }
      }
    }

    authurl = encodeURL(co.authorization, request);

    // We'd like to cache the hash for not loosing Application state.
    // With the implciit grant flow, the hash will be replaced with the access
    // token when we return after authorization.
    if (window.location.hash) {
      request['restoreHash'] = window.location.hash;
    }
    request['restoreLocation'] = window.location.href;
    request['providerID'] = providerid;
    if (scopes) {
      request['scopes'] = scopes;
    }


    log('Saving state [' + state + ']');
    log(JSON.parse(JSON.stringify(request)));

    api_storage.saveState(state, request);
    var newWindow = api_redirect(authurl);

    if (callback) {
      var timer = setInterval(function() {
        if(newWindow.closed) {
          clearInterval(timer);
          if (internalStates[state]) {
            internalStates[state]();
            delete internalStates[state];
          }
          exp.checkForToken(providerid);
        }
      }, 500);
    }

    return newWindow;
  };

  /**
   * Get an array of scopes except optional
   * @param {string} providerid
   * @param {string[]} scopes
   * @return {string[]}
   */
  exp.getRequiredScopes = function (providerid, scopes) {
    var optionalScopes = config[providerid].optionalScopes;
    if (!optionalScopes || !optionalScopes.length) {
      return scopes;
    }

    var requiredScopes = [];
    for (var i = 0; i < scopes.length; i++) {
      var isRequired = true;
      for (var j = 0; j < optionalScopes.length; j++) {
        isRequired = isRequired && scopes[i] !== optionalScopes[j];
      }
      if (isRequired) {
        requiredScopes.push(scopes[i]);
      }
    }
    return requiredScopes;
  };

  exp.ensureTokens = function (ensure) {
    var providerid, scopes, token;
    for (providerid in ensure) {
      if (ensure.hasOwnProperty(providerid)) {
        scopes = undefined;
        if (ensure[providerid]) scopes = ensure[providerid];
        token = api_storage.getToken(providerid, this.getRequiredScopes(providerid, scopes));

        log('Ensure token for provider [' + providerid + '] ');
        log(token);

        if (token === null) {
          exp.authRequest(providerid, scopes);
          return false;
        }
      }
    }


    return true;
  };

  exp.findDefaultEntry = function (c) {
    var
      k,
      i = 0;

    if (!c) return;
    log('c', c);
    for (k in c) {
      if (c.hasOwnProperty(k)) {
        i++;
        if (c[k].isDefault && c[k].isDefault === true) {
          return k;
        }
      }
    }
    if (i === 1) return k;
  };

  exp.configure = function (c, opts, callback) {
    config = c;
    setOptions(opts);

    if (typeof callback !== 'function') {
      callback = function () {
      };
    }

    try {
      var def = exp.findDefaultEntry(c);
      log('configure() about to check for token for this entry', def);

      callback(exp.checkForToken(def));
    } catch (e) {
      window.location.hash = '';
      log('Error when retrieving token from hash: ' + e);

      callback(null, e);
    }

  };

  exp.dump = function () {
    var key;
    for (key in config) {
      if (config.hasOwnProperty(key)) {
        log('=====> Processing provider [' + key + ']');
        log('=] Config');
        log(config[key]);
        log('=] Tokens');
        log(api_storage.getTokens(key));
      }
    }
  };

  exp.wipe = function () {
    var key;
    log('wipe()');
    for (key in config) {
      if (config.hasOwnProperty(key)) {
        log('Wipping tokens for ' + key);
        api_storage.wipeTokens(key);
      }
    }
  };

  exp.getTokens = function () {
    var tokens = api_storage.getAllTokens();
  };

  exp.getToken = function (providerid, scopes) {
    var token = api_storage.getToken(providerid, scopes);
    if (!token) return null;
    if (!token['access_token']) return null;
    return token;
  };


  exp.registerRedirectHandler = function (callback) {
    api_redirect = callback;
  };

  exp.registerStorageHandler = function (object) {
    extendStorageAPI(object);
    api_storage = object;
  };


  if (module && module.exports) {
    module.exports = exp;
  } else {
    global.jso = exp;
  }

})(window);
