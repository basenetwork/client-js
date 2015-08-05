var _requestQueue = {};
var _coreFrameHost = 'core.base.network';
var _coreFrameURL = location.protocol + '//' + _coreFrameHost + '/';
var _cache = {};

base.site = {

    isCore: false, // is core frame

    fatal: function(err) {
        if(this.isCore && window.parent !== window) {
            window.parent.postMessage(JSON.stringify({
                command: 'fatal',
                data: err
            }), '*');
        } else {
            document.body.innerHTML = '<div class="alert alert-danger">' +
                '<h3>base.network FATAL:</h3>' +
                '<pre>' + err + '</pre>' +
                '<button class="btn btn-danger" onclick="location.reload()">RELOAD PAGE</button>' +
            '</div>';
            throw err;
        }
    },

    init: function() {
        if(document.readyState !== 'complete') {
            return setTimeout(arguments.callee.bind(this));
        }
        this.isCore = _coreFrameHost === location.host;// && parent && parent !== window;

        if(this.isCore) {
            window.base = base;
            base.core.init();

        } else {
            this.initSite();
        }
    },

    initSite: function() {
        // listen messages from base-core-frame
        window.addEventListener("message", this.onCoreResponse.bind(this));

        // append base-core-frame
        this.baseCoreFrame = _.element("IFRAME", document.body, {
            id: 'base-core-frame',
            name: 'base-core-frame',
            src: _coreFrameURL
        });
        this.ex_setStyle();
    },

    requestToCore: function(command, data, callback) {
        if(this.isCore) {
            base.core[command].call(base.core, data, callback);
        } else {
            var id = (Math.random()*0x7fffffff|0).toString(36);
            _requestQueue[id] = callback;
            window.frames["base-core-frame"].postMessage({
                id: id,
                command: command,
                data: data
            }, _coreFrameURL);
        }
    },

    onCoreResponse: function(event) {
        if(event.origin !== location.protocol+'//'+_coreFrameHost) return;

        var resp = event.data, fn;
        if(resp && resp.id && (fn = _requestQueue[resp.id])) {
            delete _requestQueue[resp.id];
            fn.apply(this, resp.args || []);
        }
        if(resp && (fn=this['ex_'+resp.command])) {
            fn.apply(this, resp.args || []);
        }
    },

    ex_reload: function() {
        window.location.reload();
    },

    ex_onNodesInfo: function(nodes) {
        base.site.nodes = nodes;
    },

    ex_onInitCore: function() {
        if(/[?&]_clearcache\b/.test(location.search)) {
            trace('Clear cache');
            delete localStorage.domainInfo;
            delete localStorage.siteInfo;
        }
        this.loadDomainInfo(function(domainInfo) {
            trace('Downloaded Domain info: ', domainInfo);
            base.domainInfo = domainInfo;
            base.domainInfo.cert = base.Certificate.parsePublicCertificate(domainInfo.owner);

            this.loadSiteInfo(function(siteInfo){
                trace('Downloaded Site info: ', siteInfo);
                base.siteInfo = siteInfo;

                if(localStorage.testJS) {
                    trace('!!! INCLUDE TEST JavaScript by URL: ', localStorage.testJS);
                    _.element('script', document.head, {
                        type: "text/javascript",
                        src: localStorage.testJS
                    });
                } else {
                    var jsLib = siteInfo.js; // || "D/...."  - todo: by default jsLib should be link on default js-file
                    jsLib = jsLib || "F/2b6b9598c440576ad49b167eb97a083ca26965548701c4a73ea6ab3ef74235af.js";
                    // todo: if siteInfo.js is Array then download sequentially
                    trace('loading js-script... ', jsLib);
                    this.requestToCore('requestFile', jsLib, function(err, content, info) {
                        trace('include js-script.', 'err:',err, 'info:', info,'cont:', content);
                        content && _.element('script', document.head, {
                            type:"text/javascript",
                            innerHTML:content
                        });
                    });
                }
            }.bind(this));
        }.bind(this));
    },

    ex_fatal: function(err) {
        this.fatal(err);
    },

    ex_setStyle: function(style) {
        this.baseCoreFrame.setAttribute("style", style || "width:50px; height:50px; position:fixed; z-index:10001; top:0; right:0; border:none;");
    },

    ex_setStatus: function(status) {
        log('Status: '+ status);
    },

    //-------- domain ------------
    loadDomainInfo: function(fn) {
        // load from LS or by request
        var info = _.parseJSON(localStorage.domainInfo);
        if(info) {
            setTimeout(fn.bind(this, info));
            fn = null;
        }
        if(info && (info.ts|0) > +new Date() - 86400e3) return;

        var hostname = location.hostname;
        info = {
            ring: 1,
            name: hostname,
            zone: null,
            registrar: null,
            owner: null
        };
        // is it registrar domain?
        base.registrars.forEach(function(registrar){
            if(hostname === registrar.zone || hostname === registrar.zoneDNS) {
                info.ring = 0;
                info.name = registrar.zone;
                info.zone = registrar.zone;
                info.owner = registrar.cert;
                info.registrar = registrar;
                return;
            }
            function check(zone) {
                if(hostname.substr(-zone.length-1) === "."+zone) {
                    info.name = hostname.substr(0, hostname.length - zone.length) + registrar.zone;
                    info.zone = registrar.zone;
                    info.registrar = registrar;
                    return true;
                }
            }
            check(registrar.zoneDNS) || check(registrar.zone);
        });
        if(info.owner) { // it is registrar domain
            return fn && setTimeout(fn.bind(this, info));
        }
        // load domain info by request
        var req = {
            storage: "N",
            ring: 0,
            uid: info.name
            // todo: use browser cache. request with expire param
        };
        this.requestToCore("requestData", req, function(err, packs) {
            if(err || !packs.length) this.fatal('Can not load domain-info '+info.name+'. (Error: '+(err||'Empty response')+')');
            var data = packs[0].data;
            info.owner = data.owner;
            if(!info.owner) this.fatal('Can not load domain-info '+info.name);
            if(data.ring !== undefined) info.ring = data.ring|0;
            info.ts = +new Date();
            localStorage.domainInfo = JSON.stringify(info);
            fn && fn(info);
        }.bind(this));
    },

    loadSiteInfo: function(fn) {
        // load from LS or by request
        var domain = base.domainInfo;
        var owner = domain.owner;
        var info = _.parseJSON(localStorage.siteInfo);
        if(info && info.owner === owner) {
            setTimeout(fn.bind(this, info));
            fn = null;
        }
        if(info && (info.ts|0) > +new Date() - 300e3) return;

        // request to site-info-data
        var req = {
            ring: domain.ring,
            uid: domain.name,
            aid: domain.cert.getID(),
            pos: "",
            cmd: "doc"
        };
        this.requestToCore("requestData", req, function(err, packs) {
            if(err || !packs.length) this.fatal('Can not load site-manifest. ('+domain.name+')');
            var pack = packs[0];
            var info = pack.data;
            info.ts = +new Date();
            info.owner = owner;
            info.ver = pack.ver;
            if(info.ring === undefined) info.ring = domain.ring || 1;
            localStorage.siteInfo = JSON.stringify(info);
            fn && fn(info);
        }.bind(this));
    }
};

base.site.init();
