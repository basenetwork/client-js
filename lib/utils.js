/**
 * base.network 0.1 (c) 2015 Denis Glazkov | https://github.com/basenetwork/
 *
 */
var log = function(arg0){
    try { console.log.apply(console, arguments); } catch(e) {}
    return arg0;
};
var trace = location.hash.match(/\btrace\b/) || localStorage.trace? function(arg0) {
    try { console.log.apply(console, arguments); } catch(e) {}
} : function(){};

var ALPHA58 = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ', _MAP58;

var _ = base._ = {
    enc: CryptoJS.enc,

    ex: function(a, b) {
        a = a || {};
        if(b) for(var i in b) if(b[i] !== undefined) a[i] = b[i];
        return a;
    },

    element: function(tagName, parent, attributes) {
        var e = document.createElement(tagName);
        attributes && _.ex(e, attributes);
        parent && parent.appendChild(e);
        return e;
    },

    class: function(proto) {
        var fn = proto.constructor || function() {};
        _.ex(_.ex(fn, proto).prototype, proto);
        return fn;
    },

    parseArrayBuffer: function(data) {
        var arr8 = new Uint8Array(data), n = arr8.byteLength;
        var bb = [24,16,8,0], arr32 = [];
        for(var i=0;i<n;i++) arr32[i>>2] |= arr8[i] << bb[i%4];
        return CryptoJS.lib.WordArray.create(arr32, n);
    },

    sha256: function(data, enc) {
        return CryptoJS.SHA256(data).toString(enc);
    },

    str: function(data) {
        try {
            return data.toString();
        } catch(e) {
            return "";
        }
    },

    toArray: function(args) {
        var arr = [], n;
        if(args && (n = args.length)) {
            for(var i=0; i<n; i++) arr.push(args[i]);
        }
        return arr;
    },

    keys: function(obj) {
        var res = [];
        if(obj) for(var i in obj) res.push(i);
        return res;
    },

    shuffle: function(arr, count) {
        if(arr instanceof Array) {
            var a = arr.slice(), res = [];
            if(count === undefined) count = a.length;
            while(count-- && a.length) res.push(a.splice(Math.random() * a.length|0, 1)[0]);
            return res;
        }
    },

    warning: function(msg) {
        console.log('WARNING:', msg);
        return msg;
    },

    parseJSON: function(str) {
        try { return JSON.parse(str); } catch(e) {}
    },

    ip2int: function(ip) {
        ip = ip.split(/[^\d]/);
        return (ip[0]<<24) | (ip[1]<<16) | (ip[2]<<8) | ip[3];
    },

    getSegment: function(storage, ring, uid) {
        return (storage[0] || "D") + parseInt(uid.substr(0, 12), 16).toString(8).substr(0, ring|0);
    },

    /**
     * Method parses request from URI-string or from Object
     *
     *  req := Object | "<protocol>:<STORAGE:char><ring:int><path>@<author:hex>:<pos:hex>.<ext>?<param>=<val>&..."
     */
    parseRequest: function(req, defaultParams) {
        if(!req) return null;
        if(typeof req === "string") {
            var a = req.match(/^((base):)?([A-Z])(\d*)(\/([a-f0-9]{64})|\/[^?&=@:\.]+)([^?]*)(\?(.*))?/);
            if (!a) return null;
            req = {
                protocol: a[2] || "base",
                storage:  a[3],
                ring: a[4]|0,
                uid: a[6] || a[5],
                aid: (a[7].match(/@([a-zA-Z0-9\-_]+)/) || {})[1] || null,
                ext: (a[7].match(/\.([a-z0-9]+)/) || {})[1] || null,
                pos: hextoutf8((a[7].match(/:([a-f0-9]+)/) || {})[1] || "") || null
            };
            a[9] && a[9].split('&').forEach(function(s){
                if(s = s.match(/^([a-z]+)\=(\S+)/)) req[s[1]] = decodeURIComponent(s[2]);
            });
        }
        req = _.ex(_.ex({
            protocol: "base",
            storage: "D",
            ring: 1
        }, defaultParams), req);
        var uid = req.uid;
        if(uid && !/^[a-f0-9]{64}$/.test(uid)) req.uid = uid = _.sha256(uid);
        if(!uid) return null;
        req.segment = _.getSegment(req.storage, req.ring, uid);
        if(req.aid && req.aid.length > 20) { // probably it is Certificate?
            req.aid = base.Certificate.parsePublicCertificate(req.aid).getID();
        }
        return req;
    },
    
    lsCache: {
        _buf: null,
        _flushing: null,
        
        _key: function(key) {
            if(!this._buf) { // init cache - load from LS
                this._buf = _.parseJSON(localStorage["_cache"]) || {};
            }
            return CryptoJS.MD5(key).toString(CryptoJS.enc.Base64).substr(0, 8); // short hash key
        },
        
        flush: function() {
            while(1) {
                var s = JSON.stringify(this._buf);
                if(s.length < 1e6) {
                    localStorage["_cache"] = s;
                    return;
                }
                var n = 100; // remove N objects
                for(var i in this._buf) {
                    if(!n--) break;
                    delete this._buf[i];
                }
            }
        },
        
        get: function(key) {
            if(!key) return;
            key = this._key(key);
            return this._buf[key];
        },
        
        set: function(key, val) {
            if(!key) return val;
            key = this._key(key);
            if(val && this._buf[key] !== val) {
                this._buf[key] = val;
                this._flushing = this._flushing || setTimeout(function(){ // flush cache to LS
                    this.flush();
                    this._flushing = false;
                }.bind(this), 1777);
            }
            return val;
        }
    },

    /*
    makeURI: function(req) {
        req = _.parseRequest(req);
        var q = [];
        if(req.cmd) q.push('cmd='+req.cmd);
        if(req.ver) q.push('ver='+(req.ver|0));
        if(req.limit) q.push('limit='+(req.limit|0));
        return [
            req.protocol, ':',
            req.segment,
            '/', (/^[a-f0-9]{64}$/.test(req.uid)? req.uid : _.sha256(req.uid)),
            req.aid && req.aid !== '*'? '@' + req.aid : '',
            req.pos? ':' + utf8tohex(req.pos) : '',
            req.ext? '.' + req.ext : '',
            q? '?' + q.join('&') : ''
        ].join('');
    }
    */

    // Base58 encoding/decoding
    // Originally written by Mike Hearn for BitcoinJ
    // Copyright (c) 2011 Google Inc
    // Ported to JavaScript by Stefan Thomas
    // Merged Buffer refactorings from base58-native by Stephen Pair
    // Copyright (c) 2013 BitPay Inc
    encode58: function(hex) {
        if (!hex) return '';
        var buffer = [], i, j, digits = [0], str = "";
        for (i = 0; i < hex.length; i+=2) buffer.push(parseInt(hex.substr(i, 2), 16));
        for (i = 0; i < buffer.length; ++i) {
            var carry = 0;
            for (j = 0; j < digits.length; ++j) digits[j] <<= 8;
            digits[0] += buffer[i];
            for (j = 0; j < digits.length; ++j) {
                digits[j] += carry;
                carry = (digits[j] / 58) | 0;
                digits[j] %= 58
            }
            for ( ; carry; carry = (carry / 58) | 0) digits.push(carry % 58);
        }
        for (i = 0; buffer[i] === 0 && i < buffer.length - 1; ++i) digits.push(0);
        for (i = digits.length - 1; i >= 0; --i) str += ALPHA58[digits[i]];
        return str
    },

    decode58: function(string) {
        if (string.length === 0) return [];
        var i, j, bytes = [0];
        if(!_MAP58) for(_MAP58 = {}, i = 0; i < ALPHA58.length; i++) _MAP58[ALPHA58.charAt(i)] = i;
        for (i = 0; i < string.length; ++i) {
            var c = string[i], carry = 0;
            if (!(c in _MAP58)) return null;
            for (j = 0; j < bytes.length; ++j) bytes[j] *= 58;
            bytes[0] += _MAP58[c];
            for (j = 0; j < bytes.length; ++j) {
                bytes[j] += carry;
                carry = bytes[j] >> 8;
                bytes[j] &= 0xff
            }
            for (; carry; carry >>= 8) bytes.push(carry & 0xff);
        }
        for (i = 0; string[i] === '1' && i < string.length - 1; ++i) bytes.push(0);
        var HEX = "0123456789abcdef";
        return bytes.reverse().map(function(c){ return HEX[c/16|0]+HEX[c%16] }).join("")
    }
};
