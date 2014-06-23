define http_status_101 => `Switching Protocols`
define http_status_400 => `Bad Request`
define http_status_426 => `Upgrade Required`
define http_status_501 => `Not Implemented`

define websocket_handler => type {

    data
        private supported = (:13)

    public supported => .'supported'


    public handshake(conn::web_connection) => {
        local(params) = #conn->requestParams

        // Validate HTTP version
        // Would prefer to 505 instead of 400, but spec says it's for major versions
        local(http_protocol) = #params->find(::SERVER_PROTOCOL)
        local(http_version)  = decimal(#http_protocol->split(`/`)->second)
        if(not #http_protocol->beginsWith(`HTTP`) or #http_version < 1.1) => {
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Requires HTTP 1.1 or higher`))
            return
        }

        // Validate HTTP method
        if(bytes(#params->find(::REQUEST_METHOD)) != bytes(`GET`)) => {
            #conn->setStatus(501, http_status_501)
                & writeBodyBytes(bytes(`Method "` + #params->find(::REQUEST_METHOD) + `" is not implemented`))
            return
        }

        // Validate URL
        local(path) = #params->find(::PATH_INFO)->asString
        if(#path->first != '/' and not #path->beginsWith(`http://`) and not #path->beginsWith(`https://`)) => {
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Malformated URL`))
            return
        }

        // Validate Host header
        if(#params->find(::HTTP_HOST) == void) => {
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Missing header field "Host"`))
            return
        }

        // Validate Upgrade Header
        if(#params->find(::HTTP_UPGRADE) == void) => {
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Missing header field "Upgrade"`))
            return
        else(not #params->find(::HTTP_UPGRADE)->contains('websocket'))
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Missing "websocket" Upgrade header`))
            return
        }

        // Validate Connection Header
        if(#params->find(::HTTP_CONNECTION) == void) => {
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Missing header field "Connection"`))
            return
        else(not #params->find(::HTTP_CONNECTION)->contains('Upgrade'))
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Missing "upgrade" Connection header`))
            return
        }

        // Validate Sec-WebSocket-Key header
        local(ws_key) = #params->find(::HTTP_SEC_WEBSOCKET_KEY)
        if(#ws_key == void) => {
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Missing header field "Sec-WebSocket-Key"`))
            return
        // This should verify the decoded value is 16 characters long
        else(#ws_key->size != 24 or not #ws_key->endswith(`==`))
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Sec-WebSocket-Key header value is invalid`))
            return
        }

        // Validate Sec-WebSocket-Version header
        local(ws_version) = #params->find(::HTTP_SEC_WEBSOCKET_VERSION)
        if(#ws_version == void) => {
            #conn->setStatus(400, http_status_400)
                & writeBodyBytes(bytes(`Missing header field "Sec-WebSocket-Version"`))
            return
        else(not .supported->contains(integer(#ws_version)))
            #conn->setStatus(426, http_status_426)
                & writeHeaderLine(`Upgrade: websocket`)
                & writeHeaderLine(`Connection: Upgrade`)
                & writeHeaderLine(`Sec-WebSocket-Version: ` + (with v in .supported select string(#v))->join(', '))
                & writeBodyBytes(bytes(`Sec-WebSocket-Version header requesting invalid version. Supported versions are: ` + (with v in .supported select string(#v))->join(',')))
            return
        }


        // All browser clients should have an Origin header - do we care about that here?
        // If not, where do we care about that and what do we send back? (pg. 21)

        // If we want, we can validate the origin (if sent?)
        
        #conn->setStatus(101, http_status_101)
            & writeHeaderLine('Upgrade: websocket')
            & writeHeaderLine('Connection: Upgrade')
            & writeHeaderLine('Sec-WebSocket-Accept: ' + encode_base64(cipher_digest(#ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", -digest='SHA1')))
            & writeBodyBytes(bytes)
    }



    public readMsg(conn::web_connection) => {}


}