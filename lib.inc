define ws_supportedVersions => (: 13)

define http_response_400 => bytes('HTTP/1.1 400 Bad Request\r\n\r\n')
define http_response_501 => bytes('HTTP/1.1 501 Not Implemented\r\n\r\n')

define ws_http_response_426 => bytes('\
    HTTP/1.1 426 Upgrade Required\r\n\
    Upgrade: websocket\r\n\
    Connection: Upgrade\r\n\
    Sec-WebSocket-Version: ' + (with v in ws_supportedVersions select string(#v))->join(', ') + '\r\n\r\n'
)

/**!
    This method takes in an http_request object and checks that the client's opening
    handshake is valid and returns the corresponding handshake response for the
    server.
*/
define ws_generateHandshakeResponse(req::http_request)::bytes => {
    /*
    /* Validate the client's handshake request
    /*/
    // Validate HTTP version
    // Would prefer to 505 instead of 400, but spec says it's for major versions
    not #req->protocol->beginsWith(`HTTP`) or #req->protocolVersion < 1.1
        ? return http_response_400 + bytes(`Requires HTTP 1.1 or higher`)

    // Validate HTTP method
    bytes(`GET`) != bytes(#req->method)
        ? return http_response_501 + bytes(`Method "` + #req->method + `" is not implemented`)

    // Validate URL
    #req->uri->first != '/' and not #req->uri->beginsWith(`http://`) and not #req->uri->beginsWith(`https://`)
        ? return http_response_400 + bytes(`Malformated URL`)

    // Validate Host header
    local(headers) = #req->headers
    #headers === null or #headers->find('host') == void
        ? return http_response_400 + bytes(`Missing header field "Host"`)

    // Validate Upgrade Header
    #headers->find('upgrade') == void
        ? return http_response_400 + bytes(`Missing header field "Upgrade"`)
    not #headers->find('upgrade')->asString->contains('websocket')
        ? return http_response_400 + bytes(`Missing "websocket" Upgrade header`)

    // Validate Connection Header
    #headers->find('connection') == void
        ? return http_response_400 + bytes(`Missing header field "Connection"`)
    not #headers->find('connection')->asString->contains('upgrade')
        ? return http_response_400 + bytes(`Missing "upgrade" Connection header`)

    // Validate Sec-WebSocket-Key header
    #headers->find('sec-websocket-key') == void
        ? return http_response_400 + bytes(`Missing header field "Sec-WebSocket-Key"`)
    decode_base64(#headers->find('sec-websocket-key'))->size != 16
        ? return http_response_400 + bytes(`Sec-WebSocket-Key header value is invalid`)

    // Validate Sec-WebSocket-Version header
    #headers->find('sec-websocket-version') == void
        ? return http_response_400 + bytes(`Missing header field "Sec-WebSocket-Version"`)
    not ws_supportedVersions->contains(integer(#headers->find('sec-websocket-version')))
        ? return ws_http_response_426 + bytes(`Sec-WebSocket-Version header requesting invalid version. Supported versions are: ` + (with v in ws_supportedVersions select string(#v))->join(','))

    // All browser clients should have an Origin header - do we care about that here?
    // If not, where do we care about that and what do we send back? (pg. 21)

    // If we want, we can validate the origin (if sent?)

    local(response) = bytes("\
        HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Accept: " + encode_base64(cipher_digest(#headers->find('sec-websocket-key') + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"), -digest='SHA1') + "\r\n\
        \r\n"
    )

    return #response
}