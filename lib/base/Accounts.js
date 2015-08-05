
//-------- Accounts in local storage ----------------
base.Accounts = function() {
    var _curCert, _accounts;

    // init accounts (load from localStorage)
    setTimeout(function(){
        _accounts = (_.parseJSON(localStorage.accounts) || []).map(function(acc){
            // todo: if(acc.ver !== CERTIFICATE_VER) convert or alert
            var cert = _.ex(new base.Certificate(), acc);
            if(cert.pub === localStorage.curAcc) _curCert = cert;
            return cert;
        });
        if(!_accounts.length) base.Accounts.addNewAccount();
        _curCert = _curCert || _accounts[0];
    });

    return {

        // save accounts to local storage
        saveAccounts: function(){
            localStorage.accounts = JSON.stringify(_accounts.map(function(cert){
                return {
                    ver:    cert.ver,
                    pub:    cert.pub,
                    prv:    cert.prv,
                    name:   cert.name,
                    rsign:  cert.rsign
                }
            }));
        },

        getAccounts: function(){
            return _accounts;
        },

        getCurrentCertificate: function() {
            return _curCert || _accounts[0];
        },

        getCurrentPrivateKey: function() {
            return _curCert.getPrivateKey();
        },

        setCurrentAccount: function(cert) {
            if(_curCert = cert) {
                localStorage.curAcc = cert.pub;
            } else {
                delete localStorage.curAcc;
            }
        },

        setRegistrarSign: function(rsign) {
            _curCert.rsign = rsign;
            this.saveAccounts();
        },

        setPrivateKey: function(key) {
            if(this.getCurrentCertificate().setPrivateKey(key)) {
                this.saveAccounts();
                return true;
            }
        },

        addNewAccount: function() {
            var cert = (new base.Certificate()).generate();
            _accounts.push(cert);
            this.saveAccounts();
            base.Accounts.setCurrentAccount(cert);
            return cert;
        },

        removeCurrentAccount: function() {
            var i = _accounts.indexOf(_curCert);
            if(i < 0) return;
            _accounts.splice(i, 1);
            if(!_accounts.length) return base.Accounts.addNewAccount();
            this.saveAccounts();
            base.Accounts.setCurrentAccount(_accounts[0]);
        },

        // get name of current account
        getRegistrationName: function() {
            var cert = this.getCurrentCertificate();
            //if(cert.name) return cert.name;
        }
    };
}();
