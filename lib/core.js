/**
 * base.network 0.1 (c) 2015 Denis Glazkov | https://github.com/basenetwork/
 */
(function(){
    if(window.basenetwork) return;
    var base = { API: {} };

    //include jsrsasign/jsrsasign-4.7.0-all-min.js
    //include ./utils.js
    //include ./base/Certificate.js
    //include ./base/Accounts.js
    //include ./base/Pack.js
    //include ./base/core.js
    //include ./base/site.js
    //include ./base/API/v0.js

    window.basenetwork = {
        getAPI: function(version) {
            return base.API.v0
        }
    };
})();