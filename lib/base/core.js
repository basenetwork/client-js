//******** CONSTANTS ****************
var _init_nodes = [/*__INIT_NODES__*/];
var defaultNodePort = 8080;

//**************** PRIVATE METHODS ********************
// user IP functions
var _clientIP = localStorage.clientIP | 0;
function _distanceToIP(ip) {
    // distance between node-IP and current IP
    return Math.abs(_.ip2int(ip) - _clientIP);
}
function _compareIP(ip1, ip2) {
    return _distanceToIP(ip1) > _distanceToIP(ip2)? 1 : -1;
}

// revert MIME_TYPES
var MIME_TYPES = {/*__MIME_TYPES__*/};
var _MIME_TYPES = {};
for(var _mime_type in MIME_TYPES) _MIME_TYPES[MIME_TYPES[_mime_type]] = _mime_type;

//********* BASE CORE **************
base.core = {
    nodes: {},
    nodesBySeg: {},
    nodesErrors: {},

    init: function() {
        // listen messages from site-frames
        window.addEventListener("message", this.onSiteRequest);

        // load nodes info
        if(localStorage.testNodes) {
            localStorage.testNodes.split(/[\s,;]+/).forEach(function(nid){
                nid && this.addNode({
                    ver: 1,
                    nid: nid.replace(':', '/'),
                    seg: "N,D,D0,D1,D2,D3,D4,D5,D6,D7,F,F0,F1,F2,F3,F4,F5,F6,F7,P,P0,P1,P2,P3,P4,P5,P6,P7"
                });
            }.bind(this));

        } else {
            if(localStorage.nodesUpdTs > +new Date() - 7 * 86400e3) { // load nodes from local storage
                var nodes = _.parseJSON(localStorage.nodes) || {};
                for(var nid in nodes) this.addNode(_.ex({nid: nid}, nodes[nid]));
            }
            setTimeout(this.refreshNodesInfo.bind(this), 500);
        }
    },

    onSiteRequest: function(event) {
        // todo: calc statistic of sites
        var self = base.core;
        var request = event.data, fn;
        var response = function() {
            event.source.postMessage({
                id: request.id,
                args: _.toArray(arguments)
            }, event.origin);
        };
        if(request && (fn = self["ex_" + request.command])) {
            fn.call(self, request.data, response, request);
        } else {
            response("");
        }
    },

    onInitNodes: function() {
        if(base.site.isCore) {
            // core frame
            setTimeout(base.site.ex_onInitCore.bind(base.site));
        }
        // top frame
        this.postMessageToTopWindow('onInitCore');
    },

    postMessageToTopWindow: function(command, args) {
        if(window.parent === window) return;
        window.parent.postMessage({
            command: command,
            args: args || []
        }, '*');
    },

    //---------- external commands --------------
    ex_postData: function(data, fn) {
        this.postData(data, fn);
    },

    ex_uploadFile: function(data, fn) {
        this.uploadFile(data, fn);
    },

    ex_requestData: function(data, fn) {
        this.requestData(data, fn);
    },

    ex_requestFile: function(data, fn) {
        this.requestFile(data, fn);
    },

    ex_getUnsafeFileURL: function(fileURI, fn) {
        try {
            fn(null, this.getUnsafeFileURL(fileURI));
        } catch(e) {
            return fn(e);
        }
    },

    ex_getCertificateInfo: function(data, fn) {
        this.getCertificateInfo(data, fn);
    },

    ex_getUserInfo: function(data, fn) {
        this.getUserInfo(data, fn);
    },

    //----------------------------------
    fatal: function(err) {
        document.body.innerHTML = '<div class="base-profile-fatal" onclick="location.reload()">ERROR</div>';
        throw err;
    },

    //------------ nodes ------------
    refreshNodesInfo: function(fn) {
        // todo: lock others browser tabs
        // todo: request to several nodes and merge results
        var nodes = _.keys(this.nodes);
        if(!nodes.length) nodes = _init_nodes;
        this.requestToNodes(_.shuffle(nodes, 15), '/-/nodes', null, function(err, response){
            var data = response && response.toString();
            if(data) {
                data.split("\n").forEach(this.addNode.bind(this));
                localStorage.nodes = JSON.stringify(this.nodes);
                localStorage.nodesUpdTs = +new Date();
                var ip = response.header('X-Remote-Addr');
                if(ip) localStorage.clientIP = _clientIP = _.ip2int(ip); // set client IP
                // todo: check IP from several nodes. don`t believe only one node
            }
            setTimeout(this.refreshNodesInfo.bind(this), 115249);
            fn && fn();
        }.bind(this));
    },

    parseNode: function(nid) {
        if(!nid) return null;
        var a = nid.split('/');
        var h = a[0].trim().toLowerCase();
        var p = a[1]|0 || defaultNodePort;
        return /^([\d\.]{7,15}|[0-9a-f:]{3,39})$/.test(h) && {
            nid: h + '/' + p,
            host: h,
            port: p
        }
    },

    addNode: function(node) {
        if(typeof node === "string") node = _.parseJSON(node);
        if(!node || !node.nid) return false;
        var nid = node.nid, _node = this.nodes[nid];
        if(_node && _node.ver === node.ver && _node.seg === node.seg) return;
        if(_node) this.removeNode(nid);
        var segments = String(node.seg||'').split(',').filter(function(seg){ return /^[A-Z]+[0-7]*$/.test(seg) });
        this.nodes[nid] = {
            ver: parseFloat(node.ver) || 0,
            seg: segments.join(',')
        };
        this.nodesErrors[nid] = true;
        segments.forEach(function(seg){
            var arr = this[seg] || (this[seg] = []);
            if(arr.indexOf(nid) < 0) {
                arr._sorted = -1;
                arr.push(nid);
            }
        }.bind(this.nodesBySeg));
        this._nodesInitialized || (this._nodesInitialized = setTimeout(this.onInitNodes.bind(this)));
    },

    removeNode: function(nid) {
        if(this.nodes[nid]) {
            (this.nodes[nid].seg||'').split(',').forEach(function(seg) {
                var arr = this[seg], i;
                if(arr && (i = arr.indexOf(nid)) >= 0) arr.splice(i, 1);
            }.bind(this.nodesBySeg));
            delete this.nodes[nid];
        }
    },

    getNodesBySegment: function(seg, key) {
        var arr = this.nodesBySeg[seg];
        if(!arr || !arr.length) return [];
        if(arr._sorted !== _clientIP) {
            arr._sorted = _clientIP;
            arr.sort(_compareIP);
        }
        var nodes = arr.slice(), cachedNode;
        if(key && (cachedNode = _.lsCache.get(key))) {
            return [cachedNode].concat(nodes);
        }
        return nodes;
    },

    getUnsafeFileURL: function(request) {
        var req = _.parseRequest(request);
        if(!req) throw "Incorrect URI-link";
        var uri = "/-/" + req.segment + "/data/" + req.uid + (req.ext? "." + req.ext : "");
        var nodes = this.getNodesBySegment(req.segment, uri);
        if(!nodes.length) throw "Can not find node";
        var node = base.core.parseNode(nodes[0]);
        return "//" + node.host + ":" + node.port + uri;
    },

    //------------ request ------------
    httpRequest: function(url, data, fn) {
        base.core._loading = (base.core._loading|0) + 1;
        var xhr = new XMLHttpRequest();
        xhr.responseType = "arraybuffer";
        xhr.onreadystatechange = function() {
            if(xhr.readyState == 4) {
                base.core._loading--;
                if(xhr.status != 200) return fn('Response status is ' + xhr.status);
                var wa = _.parseArrayBuffer(xhr.response); // words array
                fn(null, {
                    xhr: xhr,
                    data: wa,
                    length: wa.sigBytes,
                    hash: function() { return _.sha256(wa) },
                    header: function(name) { return xhr.getResponseHeader(name) },
                    toString: function(enc) { return wa.toString(enc || CryptoJS.enc.Latin1) || ''; }
                });
            }
        };
        var formData, contType;
        if(data) { // POST-method
            if(data.file) { // multipart/form-data
                formData = new FormData();
                for(var i in data) formData.append(i, data[i]);
            } else {
                formData = [];
                for(var i in data) formData.push(encodeURIComponent(i) + "=" + encodeURIComponent(data[i]));
                formData = formData.join('&');
                contType = "application/x-www-form-urlencoded; charset=utf-8";
            }
        }
        xhr.open(formData? "POST" : "GET", url, true);
        contType && xhr.setRequestHeader("Content-Type", contType);
        try {
            xhr.send(formData);
        } catch(e) {
            setTimeout(function(){ fn(e) });
        }
        return xhr;
    },

    httpCreateSSEListener: function(req, node, fn) {
        var sse = new EventSource('http://'+node.host+':'+node.port+'/-/'+req.segment+'/listen/'+req.uid);
        sse.addEventListener('message', function(e) {
            var data = e.data && CryptoJS.enc.Base64.parse(e.data).toString(CryptoJS.enc.Latin1);
            if(data) fn(data, e);
        }, false);
        return sse;
    },

    requestToNodesBySegment: function(segment, uri, postData, fn) {
        var nodes = this.getNodesBySegment(segment, !postData && uri);
        if(!nodes.length) return fn('Not found nodes in segment ' + segment);
        return this.requestToNodes(nodes, uri, postData, fn);
    },

    requestToNodes: function(nodes, uri, postData, fn) {
        if(!nodes || !nodes.length) return fn('Not found nodes in the segment');
        (function _requestToNode() {
            if(!nodes.length) return fn('Can not complete the request');
            var node = base.core.parseNode(nodes.shift());
            var url = 'http://' + node.host + ':' + node.port + uri;
            base.core.httpRequest(url, postData, function(err, response) {
                // if error or callback-function return error
                if(err = err || fn(null, _.ex(response, { node: node }))) {
                    base.core.removeNode(node.nid);
                    setTimeout(_requestToNode);
                    _.warning(err);
                }
            });
        })();
    },

    requestFile: function(link, fn) {
        var req = _.parseRequest(link);
        if(!req) return fn('requestFile: Empty request');
        if(req.storage === 'D') { // get file by link
            req.limit = 1;
            return this.requestData(req, function(err, packs){
                if(err) return fn(err);
                if(!packs || !packs.length) return fn('requestFile: Empty reference by link');
                var ref = packs[0].data;
                if(ref && typeof ref === 'object') ref = ref.reference;
                if(!ref || !(ref = _.parseRequest(ref))) return fn('requestFile: Incorrect reference');
                this.requestFile(_.ex(req, ref), fn);
            }.bind(this));
        }
        if(req.storage !== 'F') return fn('requestFile: Bad storage ' + req.storage);
        var seg = req.segment, hash = req.uid;
        var uri = '/-/' + seg + '/data/' + hash + (req.ext? '.'+req.ext : '');
        this.requestToNodesBySegment(seg, uri, null, function(err, response) {
            if(err) return fn(err);
            if(hash !== response.hash()) return 'Invalid hash'; // return error
            var m = (response.header('x-base-author') || '').match(/^([^;]+);\s*sign=([^;\s]+)/) || {};
            if(!m) return 'Bad http-header X-Base-Author'; // return error
            var node = response.node;
            node.nid && _.lsCache.set(uri, node.nid); // add last success node to cache
            // size limit
            if(req.sizeLimit && response.length > req.sizeLimit) {
                return fn("Exceeded the allowable limit");
            }
            // available output encodings
            var enc = {
                latin1: CryptoJS.enc.Latin1,
                base64: CryptoJS.enc.Base64,
                utf8: CryptoJS.enc.Utf8,
                hex: CryptoJS.enc.Hex
            };
            var content = req.onlyInfo? null : response.toString(enc[req.outputEncoding]);
            fn(null, content, {
                contentType: response.header('Content-Type'),
                hash: hash,
                author: m[1],
                sign: m[2],
                node: node.nid,
                httpURL: "//" + node.host + ":" + node.port + uri
            });
        });
    },

    requestData: function(req, fn) {
        req = _.parseRequest(req);
        if(!req) return fn('requestData: Empty request');

        var uri = '/-/' + req.segment + '/data/' + req.uid, q = [];
        if(req.cmd) q.push('cmd=' + encodeURIComponent(req.cmd));
        if(req.aid) q.push('aid=' + encodeURIComponent(req.aid));
        if(req.pos !== undefined) q.push('pos=' + utf8tohex(req.pos));
        if(req.ver !== undefined) q.push('ver=' + (req.ver|0));
        if(req.limit) q.push('limit=' + (req.limit|0));
        if(q.length) uri += '?' + q.join('&');

        var _request = function(fn) {
            base.core.requestToNodesBySegment(req.segment, uri, null, function(err, response) {
                if(err) return fn(err);
                if(req.rawResponse) return fn(null, response.toString());

                // verify data by author-signature
                var packs = [], res = response.toString();
                var access = req.access || "all";
                if(typeof access === "string") access = access.split(",");
                var accessForAll = access.indexOf("all") > -1;
                var accessOnlyReg = access.indexOf("reg") > -1; // for registered users only
                var unpackErr;
                res && res.split('\n').forEach(function(line) {
                    //if (unpackErr) return; // break;
                    var pack = base.Pack.parse(line, req, response);
                    if(!pack) return unpackErr = 'Incorrect data';
                    if(!pack.data) return; // row is deleted
                    // check access (todo: to server???)
                    if(accessForAll || accessOnlyReg && pack.author.signed || access.indexOf(pack.author) > -1) {
                        packs.push(pack);
                    }
                });
                //if (unpackErr) return fn(unpackErr);
                fn(null, packs, response);
            });
        };

        _request(function(err, packs, response) {
            fn(err, packs);

            // set listener of server side events
            if(req.sse
            && response
            && !err && req.cmd == "top"
            && (req.segment[0] == "D" || req.segment[0] == "P")) {
                var sse = base.core._sse;
                if(sse) setTimeout(function() { // only ONE opened connection
                    sse.close();
                });
                var curPos = packs.length? packs[0].pos : '', newPos = curPos;
                base.core._sse = base.core.httpCreateSSEListener(req, response.node, function(evPos){
                    trace('SSE:', evPos);
                    if(!evPos || evPos <= newPos) return;
                    newPos = evPos;
                    // todo: request data where pos>curPos
                    _request(function(err, packs) {
                        if(err || !packs || !packs.length) return;
                        packs = packs.filter(function(pack){
                            return pack.pos > curPos;
                        });
                        trace('SSE-packs', err, packs);
                        curPos = newPos;
                        if(packs.length) fn("sse-updates", packs);
                    });
                });
            }
        });
    },

    postData: function(req, fn) {
        var cert = base.Accounts.getCurrentCertificate();
        if(cert.senderTag) { // set anonymous certificate
            cert = cert.generateChildCertificate(cert.senderTag);
        }
        var author  = cert && cert.toString();  if(!author) return fn("Author is not authorized");
        var storage = _.str(req.storage) || "D";
        var uid     = _.bin(req.uid);           if(!uid) return fn("Empty uid");
        var pos     = _.bin(req.pos || "");     if(pos.length > 20) return fn("Position is too long");
        var ring    = req.ring|0;               if(ring < 1) return fn("Incorrect ring");
        var ver     = req.ver|0;                if(ver<0 || ver>1e6) return fn("Version is too large");
        var data    = req.data || "";
        if(typeof data !== "string") {
            data = JSON.stringify(data);
        }
        if(req.recipient) {
            data = cert.encrypt(data, req.recipient); // return binary data
        } else {
            data = _.bin(data); // convert to binary
        }
        if(!/^[a-f0-9]{64}$/.test(uid)) uid = _.sha256(uid);
        var hash;
        switch(storage) {
            case 'D':
            case 'P': hash = _.sha256([uid, pos, author, ver, data].join('|')); break;
            case 'N': hash = _.sha256([uid, author, ver, data].join('|')); break;
            case 'F': hash = _.sha256(data); break;
            default: return fn("Incorrect storage-type");
        }
        var segment = _.getSegment(storage, ring, uid); //data segment
        var sign = cert.sign(segment + hash);
        var postData = {
            ver:    ver,
            author: author,
            pos:    _.bintob64(pos),
            uid:    hex2b64(uid),
            hash:   hex2b64(hash),
            sign:   hex2b64(sign),
            data:   _.bintob64(data)
        };
        this.requestToNodesBySegment(segment, '/-/' + segment + '/add', postData, function(err, response) {
            if(err) return fn(err);
            fn(null, {
                uri: response.toString(),
                node: response.node,
                author: {
                    aid: cert.getID(),
                    cert: author,
                    isMe: true
                }
            })
        });
    },

    uploadFile: function(req, fn) {
        var cert    = base.Accounts.getCurrentCertificate();
        var author  = cert && cert.toString();  if(!author) return fn("Author is not authorized");
        var file    = req.file;                 if(!file) return fn("Empty file");
        var size    = file.size;                if(!size) return fn("File is empty");
        var storage = req.storage || "F";
        var ring    = req.ring|0;
        var reader  = new FileReader();
        var sha256  = CryptoJS.algo.SHA256.create();
        var type    = file.type;
        var ext     = _MIME_TYPES[type] || ""; // file extension
        var pos = 0, _pos, MiB = 1<<20, chunkSize = MiB; // 1MiB
        if(!ring) {
            // search suitable ring
            // TODO: research available space in ring !!!
            ring = Math.max(1, Math.log2(size * 1.05 / MiB) / 3 | 0);
        }
        reader.onprogress = function(ev) {
            if((_pos = ev.loaded) == size || _pos - pos >= chunkSize) {
                sha256.update(CryptoJS.enc.Latin1.parse(reader.result.slice(pos, _pos)));
                pos = _pos;
                // todo: window.parent.postMessage({command: 'onFileUploadProgress'}, '*');
                //console.log('read progress: ' + (pos / size * 100).toFixed(2) + '%');
            }
        };
        reader.onloadend = function() {
            var hash = sha256.finalize().toString();
            var segment = _.getSegment(storage, ring, hash);
            var sign = cert.sign(segment + hash);
            var postData = {
                author: author,
                hash:   hex2b64(hash),
                sign:   hex2b64(sign),
                file:   file
            };
            base.core.requestToNodesBySegment(segment, '/-/' + segment + '/add', postData, function(err, response) {
                if(err) return fn(err);
                var node = response.node;
                var uri = response.toString().trim();
                if(ext && !/\.[a-z0-9]+$/.test(uri)) // append file extension
                    uri += "." + ext;
                fn(null, {
                    uri: uri,
                    size: file.size,
                    hash: hash,
                    type: type,
                    extension: ext,
                    node: node,
                    httpURL: "//" + node.host + ":" + node.port + "/-/" + segment + "/data/" + hash + (ext? "." + ext : "")
                })
            });
        };
        reader.onerror = function(err) {
            fn("FileReader Error: " + err);
        };
        reader.readAsBinaryString(file);
    },

    getCertificateInfo: function(certificate, fn) {
        if(!certificate) return fn("Empty certificate-param");
        var cert = base.Certificate.parsePublicCertificate(certificate);
        if(!cert) return fn("Invalid Certificate");
        var key = cert.getID();
        var _cache = this._cert || (this._cert = {});
        var info = _cache[key] || _.lsCache.get(key);
        if(info) return fn(null, info);

        // request info by pubkey from registrar
        this.requestData({
            storage: "N",
            ring: 0,
            uid: cert.pub
        }, function(err, packs){
            if(err || !packs.length) return fn("Can not find author info");
            info = packs[0].data;
            _.lsCache.set(key, _cache[key] = info);
            fn(null, info);
        });
    },

    getUserInfo: function(author, fn) {
        // todo: use queue (for the same requests)
        if (!author) return fn("Empty author-param");
        var aid = author;
        if (aid && aid.aid) aid = aid.aid;
        if (aid.length > 20) {
            var cert = base.Certificate.parsePublicCertificate(aid);
            if (!cert) return fn("Invalid Certificate");
            aid = cert.getID();
        }
        if (aid.length !== 20) return fn("Incorrect aid " + aid);
        var key = aid;
        var _cache = this._users || (this._users = {});
        var info = _cache[key] || _.lsCache.get(key);
        if (info) return fn(null, info);

        // search auth info into different rings
        var search = function (ring) {
            if (ring > 2) return fn("Can not find author info");
            this.requestData({
                storage: "D",
                ring: ring,
                uid: aid,
                aid: aid,
                limit: 1
            }, function (err, packs) {
                if (err || !packs.length) return search(ring + 1);
                var info = packs[0].data;
                _.lsCache.set(key, _cache[key] = info);
                fn(null, info);
            });
        }.bind(this);

        search(1);
    }
};
