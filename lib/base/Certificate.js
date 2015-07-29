base.registrars = [/*__REGISTRARS__*/];

base.Certificate = (function() {
    var CERTIFICATE_VER = 0;  // int
    var ecdsa = new KJUR.crypto.ECDSA({curve: "secp256k1"});
    var ecdsaCurve = ecdsa.ecparams['curve'];
    var ecdsaKeyLen = ecdsa.ecparams.keylen/4;
    var _rootCert, _certs = {}, _regCerts = {};
    var _keysBuf = {};
    base.registrars.forEach(function(reg){
        _regCerts[reg.cert] = true;
    });

    // ---- redefine ecdsa format functions -------
    // todo: remove KJUR. use only Fp curves http://www-cs-students.stanford.edu/~tjw/jsbn/
    KJUR.crypto.ECDSA.biRSSigToASN1Sig = function(x, y) {
        return ("000000000000000" + x.toString(16)).slice(-ecdsaKeyLen)
             + ("000000000000000" + y.toString(16)).slice(-ecdsaKeyLen);
    };
    KJUR.crypto.ECDSA.parseSigHex = function(signHex) {
        return {
            r: new BigInteger(signHex.substr(0, ecdsaKeyLen), 16),
            s: new BigInteger(signHex.substr(ecdsaKeyLen), 16)
        }
    };
    ECPointFp.decodeFromHex = function(g, c) {
        var a = new BigInteger(c.substr(0, ecdsaKeyLen), 16);
        var h = new BigInteger(c.substr(ecdsaKeyLen), 16);
        return new ECPointFp(g, g.fromBigInteger(a), g.fromBigInteger(h))
    };

    function _generatePrivateKey() {
        var k = ecdsa.ecparams.n;
        return ("000000000000000" + ecdsa.getBigRandom(k).toString(16)).slice(-ecdsaKeyLen);
    }
    function _getPublicKeyByPrivate(prvHex) {
        var p = new BigInteger(prvHex, 16);
        var m = ecdsa.ecparams.G.multiply(p);
        var x = ("000000000000000" + m.getX().toBigInteger().toString(16)).slice(-ecdsaKeyLen);
        var y = ("000000000000000" + m.getY().toBigInteger().toString(16)).slice(-ecdsaKeyLen);
        return x + y;
    }

    return _.class({

        ver: null,
        pub: null,
        prv: null,
        rsign: '',
        name: null, // nick name

        constructor: function() {

        },

        toStringHex: function() {
            return ("0"+(this.ver|0).toString(16)).substr(-2) + this.pub + (this.rsign||'')
        },

        toString: function() {
            return hextob64(this.toStringHex());
        },

        generate: function() {
            this.ver = CERTIFICATE_VER;
            this.prv = _generatePrivateKey();
            this.pub = _getPublicKeyByPrivate(this.prv);
            return this;
        },

        /**
         * Short Certificate ID (aid)
         *
         * @returns {string}
         */
        getID: function() {
            return CryptoJS.SHA256(CryptoJS.enc.Hex.parse(this.toStringHex()))
                        .toString(CryptoJS.enc.Base64)
                        .substr(0, 20)
                        .replace(/\+/g, '-').replace(/\//g, '_');
        },

        getPrivateKey: function() {
            return _.encode58(this.prv);
        },

        setPrivateKey: function(prvKey58) {
            var prv = (prvKey58||"").trim();
            if(!prv) return false;
            if(prv.length != ecdsaKeyLen) { // is base58
                prv = _.decode58(prv);
                if(!prv) throw "Invalid key";
            }
            if(prv.length != ecdsaKeyLen) throw "Invalid key";
            this.ver = CERTIFICATE_VER;
            this.prv = prv;
            this.pub = _getPublicKeyByPrivate(prv);
            return true;
        },

        //------- sign, verify -----------
        sign: function(data) {
            if(!this.prv) throw "Is not private certificate";
            var hash = /^[0-9a-f]{64}$/.test(data)? data : _.sha256(data);
            try {
                return ecdsa.signHex(hash, this.prv);
            } catch(e) {
                return false;
            }
        },

        verify: function(data, sign) {
            if(!this.pub) return null;
            var hash = /^[0-9a-f]{64}$/.test(data)? data : _.sha256(data);
            try {
                return ecdsa.verifyHex(hash, sign, this.pub);
            } catch(e) {
                return false;
            }
        },

        //------- encrypt, decrypt -----------
        encrypt: function(message, recipientCert) {
            var cert = this.parsePublicCertificate(recipientCert);
            if(!cert) return false;
            var keyPvPb = hex2b64(this.prv + cert.pub), kE = _keysBuf[keyPvPb];
            if(!kE) {
                var r = new BigInteger(this.prv, 16);
                var KB = ECPointFp.decodeFromHex(ecdsaCurve, cert.pub);
                var S = KB.multiply(r).getX();
                kE = _keysBuf[keyPvPb] = CryptoJS.enc.Hex.parse(S.toBigInteger().toString(16));
            }
            var iv = CryptoJS.lib.WordArray.random(128 / 8);
            var ct = CryptoJS.AES.encrypt(message, kE, {iv:iv}).ciphertext;
            return CryptoJS.enc.Latin1.parse(
                "\x00"                             // version
                + iv.toString(CryptoJS.enc.Latin1) // ivbuf
                + ct.toString(CryptoJS.enc.Latin1) // encrypted message
            ).toString(CryptoJS.enc.Base64);
        },

        decrypt: function(encryptedMessage, senderCert) {
            encryptedMessage = CryptoJS.enc.Base64.parse(encryptedMessage).toString(CryptoJS.enc.Latin1);
            var ver = encryptedMessage.substr(0, 1);
            if(ver !== "\x00") return null;
            var cert = this.parsePublicCertificate(senderCert);
            if(!cert) return false;
            var keyPvPb = hex2b64(cert.pub + this.prv), kE = _keysBuf[keyPvPb];
            if(!kE) {
                var kB = new BigInteger(this.prv, 16);
                var R = ECPointFp.decodeFromHex(ecdsaCurve, cert.pub);
                var S = R.multiply(kB).getX();
                kE = _keysBuf[keyPvPb] = CryptoJS.enc.Hex.parse(S.toBigInteger().toString(16));
            }
            var iv = CryptoJS.enc.Latin1.parse(encryptedMessage.substr(1, 16));
            var ct = CryptoJS.enc.Latin1.parse(encryptedMessage.substr(17));
            return CryptoJS.AES.decrypt({ciphertext:ct}, kE, {iv:iv}).toString(CryptoJS.enc.Utf8);
        },

        generateChildCertificate: function(tag) {
            var cert = new base.Certificate();
            cert.ver = CERTIFICATE_VER;
            cert.prv = _.sha256(this.prv + (tag||"")).slice(-ecdsaKeyLen);
            cert.pub = _getPublicKeyByPrivate(cert.prv);
            return cert;
        },

        //------- registrars ---------
        is: function(cert) {
            if(typeof cert === "string") {
                if(cert.length == 20) { // is aid
                    return cert === this.getID;
                }
                return cert === this.toString();
            }
            return cert.pub === this.pub;
        },

        isRegistrar: function() {
            return this._isRegistrar;
        },

        isAnonymous: function() {
            return !this.isSignedByRootRegistrar();
        },

        isSignedByRootRegistrar: function() {
            if(this._isRegistrar) return true;
            if(!this.rsign) return false;
            _rootCert = _rootCert || base.Certificate.parsePublicCertificate(base.registrars[0].cert);
            return this._valid = this._valid || _rootCert.verify(this.pub, this.rsign);
        },

        isCurrentCertificate: function() {
            return this.is(base.Accounts.getCurrentCertificate());
        },

        loadRegistrationInfo: function(fn) {
            // load info from pub-hex@registrar
            base.core.requestData({
                storage: "N",
                ring:    0,
                uid:     this.pub // pub-hex
            }, function(err, packs){
                if(err || !packs || !packs.length) return fn && fn(err || "Empty registration info");
                var data = packs[0].data || {};
                var c = base.Certificate.parsePublicCertificate(data.owner);
                if(!c || c.pub !== this.pub) return fn && fn("Bad registration info");
                this.name = data.name;
                this.rsign = c.rsign;
                return fn && fn(null, data);
            }.bind(this));
        },

        //------ static ------------
        parsePublicCertificate: function(cert64) {
            if(typeof cert64 !== "string") cert64 = cert64.toString();
            if(_certs[cert64]) return _certs[cert64];
            var hex = b64tohex(cert64);
            if(hex.length < 2) return null; // Bad certificate version
            var ver = parseInt(hex.substr(0, 2), 16)|0;
            if(ver !== CERTIFICATE_VER) return null; //throw "Bad certificate";
            if(hex.length < ecdsaKeyLen*2+2) return null; // Bad certificate
            var cert = new base.Certificate();
            cert.ver = ver;
            cert.pub = hex.substr(2, ecdsaKeyLen*2);
            cert.rsign = hex.substr(2 + ecdsaKeyLen*2, ecdsaKeyLen*2) || ''; // sign of registrar
            cert._isRegistrar = _regCerts[cert64];
            return _certs[cert64] = cert;
        }

    });
})();
