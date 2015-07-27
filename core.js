/**
 * base.network 0.1 (c) 2015 Denis Glazkov | https://github.com/basenetwork/
 */
(function(){
    if(window.basenetwork) return;
    var base = { API: {} };

    //include ./ext/jsrsasign-4.7.0-all-min.js
    //include ./lib/utils.js
    //include ./lib/base/Certificate.js
    //include ./lib/base/Accounts.js
    //include ./lib/base/Pack.js
    //include ./lib/base/core.js
    //include ./lib/base/site.js
    //include ./lib/base/base.api-v0.js

    window.basenetwork = {
        getAPI: function(version) {
            return base.API.v0
        }
    };
})();