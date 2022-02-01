//cordova.define("cordova-plugin-rsa.RSAPlugin", function(require, exports, module) {


    var RSAPlugin = function() {};


    RSAPlugin.prototype.init = function(params, success, fail) {
        cordova.exec(success, fail, 'RSAPlugin', 'init', [
            params.alias,
        ]);
    };
    RSAPlugin.prototype.getCertificate = function(params, success, fail) {
        cordova.exec(success, fail, 'RSAPlugin', 'getCertificate', [
            params.alias,
        ]);
    };

    RSAPlugin.prototype.cmsSign = function(params, success, fail) {
        cordova.exec(success, fail, 'RSAPlugin', 'cmsSign', [
            params.alias,
            params.data,
        ]);
    };
    RSAPlugin.prototype.cmsEncrypt = function(params, success, fail) {
        cordova.exec(success, fail, 'RSAPlugin', 'cmsEncrypt', [
            params.certs,
            params.data,
        ]);
    };
    RSAPlugin.prototype.cmsDecrypt = function(params, success, fail) {
        cordova.exec(success, fail, 'RSAPlugin', 'cmsDecrypt', [
            params.alias,
            params.data,
        ]);
    };

    if (!window.plugins) {
        window.plugins = {};
    }
    if (!window.plugins.rsa) {
        window.plugins.rsa = new RSAPlugin();
    }

    if (module.exports) {
        module.exports = RSAPlugin;
    }

//});
