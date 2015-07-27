/**
 * base.network 0.1 (c) 2015 Denis Glazkov | https://github.com/basenetwork/client-js
 */
base.API.v0 = {

    getCurrentSiteInfo: function() {
        return {
            host:  base.domainInfo.name,    // site hostname
            owner: base.domainInfo.owner,   // owner of site
            title: base.siteInfo.title,     // title of site
            ring:  base.siteInfo.ring,      // storage ring of site data
            storage: "D",                   // storage type of site data
            ver:   base.siteInfo.ver,       // version of site data
            js:    base.siteInfo.js,        // reference to js-script
            css:   base.siteInfo.css,       // reference to style sheet

            // additional information
            _domain: _.ex({}, base.domainInfo),
            _info:   _.ex({}, base.siteInfo)
        }
    },

    parseRequest: function(req) {
        return _.parseRequest(req);
    },

    parseCertificate: function(cert64) {
        return base.Certificate.parsePublicCertificate(cert64);
    },

    /**
     * @param request := {
     *      storage: "<storage:char>",  // default: "F"
     *      ring:    <ring:int>,
     *      uid:     "<hash:hex>",
     *      ext:     "<extension>",
     *  }
     * @param callback Function(error, content, responseInfo)
     */
    requestFile: function(request, callback) {
        return base.site.requestToCore("requestFile", request, callback);
    },

    /**
     *
     * @param imageElement
     * @param request
     * @param callback
     * @returns {*}
     */
    setImageContent: function(imageElement, request, callback) {
        function setUrl(url){
            if(typeof imageElement === "string") imageElement = document.getElementById(imageElement);
            if(imageElement instanceof HTMLImageElement || imageElement instanceof Image) {
                imageElement.src = url;
            } else if(imageElement instanceof HTMLElement) {
                imageElement.style.backgroundImage = "url(" + url + ")";
            }
        }
        request = _.parseRequest(request);
        request.outputEncoding = "base64";
        // pre set data. At first set unsafe url, after that load and check content.  // todo: ???
        //base.site.requestToCore("getUnsafeFileURL", request, function(err, url){
        //    !err && url && setUrl(url);
            base.site.requestToCore("requestFile", request, function(err, content, info) {
                if(!err && info.contentType.substr(0, 5) === "image") {
                    setUrl("data:" + info.contentType + ";base64," + content);
                }
                callback && callback.apply(this, arguments);
            });
        //});
    },

    /**
     * @param request := {
     *      storage: "<storage:char>",  // default: "D"
     *      ring:    <ring:int>,
     *      uid:     "<uid:hex>",
     *      cmd:     "top|nxt|prv|doc|old",
     *      aid:     "<aid:chars>",
     *      pos:     "<pos:chars>",
     *      ver:     <ver:int>,
     *      limit:   <ver:int>,
     *  }
     * @param callback Function(error, packs)
     */
    requestData: function(request, callback) {
        return base.site.requestToCore("requestData", request, callback);
    },

    /**
     * Post data into stream
     *
     * @param request := {
     *      storage, // char        - Storage type: "D" - author`s data (by default); "P" - public data.
     *      ring,    // int         - Number of ring. By default: ring of current site.
     *      uid,     // hex(64)     - Unique address id of stream. Hex-string 64 or string with absolute path. (ex: "site/path/")
     *      pos,     // char(20)    - Position in stream. By default: Empty string.
     *      ver,     // uint,       - Version of data. Max 1e6. By default: 0
     *      data,    // object|null - Object with data or null for delete data from stream
     *  }
     * @param callback Function(error, packs)
     */
    postData: function(request, callback) {
        if(request.ring === undefined) request.ring = base.siteInfo.ring;
        return base.site.requestToCore("postData", request, callback);
    },

    /**
     * Upload file into cloud
     *
     * @param request := {
     *      storage, // char        - Storage type. By default "F"
     *      ring,    // int         - Number of ring. By default: Suitable ring
     *      file:    // FileReader|string,
     *  }
     * @param callback Function(error, fileUri)
     */
    uploadFile: function(request, callback) {
        return base.site.requestToCore("uploadFile", request, callback);
    },

    /**
     * Get http-link by base-uri of file
     *
     * @param fileURI String
     * @param callback Function(error, httpURL)
     */
    getUnsafeFileURL: function(fileURI, callback) {
        return base.site.requestToCore("getUnsafeFileURL", fileURI, callback);
    },

    //-------- Other Information ---------
    /**
     * @param author    aid or public-certificate
     * @param callback  Function(error, authorInfo)
     * @returns {*}
     */
    getAuthorInfo: function(author, callback) {
        if(author.cert) author = author.cert;
        return base.site.requestToCore("getAuthorInfo", author, callback);
    }
};
