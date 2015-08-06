base.Pack = {
    _unpackData: function(data, author) {
        if(typeof data === "string") {
            if(!data.length) return null; // deleted element
            switch(data[0]) {
                case 'S':
                    return _.bintoutf8(data.substr(1));

                case 'J':
                    return JSON.parse(_.bintoutf8(data.substr(1)));

                case '"':
                case '{':
                    return JSON.parse(_.bintoutf8(data));

                case 'E':
                    var cert = base.Accounts.getCurrentCertificate();
                    data = cert && cert.decrypt(data, author, enc);
                    if(!data) throw "Decrypt error";
                    return this._unpackData(data, author);

                default:
                    throw "Unknown format";
            }
        }
        throw "Unknown format";
    },

    _hash: function(req, pack) {
        switch(req.storage || req.segment[0]) {
            case 'P':
            case 'D':   return _.sha256([req.uid, pack.pos, pack.author, pack.ver, pack.data].join('|'));
            case 'N':   return _.sha256([req.uid, pack.author, pack.ver, pack.data].join('|'));
            case 'F':   return _.sha256(pack.data);
            default: throw "Unknown storage type";
        }
    },

    parse: function(line, req, response) {
        try {
            var pack = _.parseJSON(line), cert, aid;
            var checkAuthor = (req.storage !== "P" || req.cmd === "doc" || req.cmd === "ver") && req.aid;
            if(!pack) return null;
            for(var name in pack) {
                if(!/^[a-z][a-zA-Z0-9]*$/.test(name)) continue;
                if(name === 'author') {
                    cert = base.Certificate.parsePublicCertificate(pack.author);
                    if(!cert) throw "Empty certificate";
                    aid = cert.getID();
                    if(checkAuthor && req.aid != aid) {
                        throw "Incorrect author (request.aid != response.aid)";
                    }

                } else if(name === 'hash' || name === 'sign') {
                    pack[name] = b64tohex(pack[name]);

                } else if(typeof pack[name] === "string") {
                    pack[name] = CryptoJS.enc.Base64.parse(pack[name]).toString(CryptoJS.enc.Latin1);
                }
            }
            var hash = this._hash(req, pack);
            if(!hash || hash !== pack.hash) throw "Invalid hash";
            var seg = req.segment || req.storage + req.ring;
            if(req.verifyData && !cert.verify(seg + hash, pack.sign)) throw "Bad sign";
            var data = this._unpackData(pack.data, pack.author);
            return {
                author: {
                    cert: pack.author,
                    aid: aid,
                    signed: cert.isSignedByRootRegistrar(),
                    isMe: cert.isCurrentCertificate()
                },
                uid: req.uid,
                pos: pack.pos,
                ver: pack.ver,
                hash: pack.hash,
                sign: pack.sign,
                raw: pack.data,
                data: data,
                verified: true,
                segment: seg,
                storage: seg[0],
                ring: seg.length - 1,
                node: response.node
            };
        } catch(e) {
            console.log("UNPACK-error: Pack not verified! Error:"+e+".", "Request:", req, " Pack:", pack);
            return false;
        }
    }
};
