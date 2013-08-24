local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
if(not var_defined(`_cms_loaded`)) => {
    sourcefile(file(#here + 'spec_helper.inc'), -autoCollect=false)->invoke
}
//local(x) = split_thread => {
//    sourcefile(file(#here + '../daemon.inc')      , -autoCollect=false)->invoke
//}

var(base_url) = "http://localhost:8000"

describe('HTTP Daemon') => {
    it('Returns a "501 Not Implemented" when called with a method (gEt) that is not supported') => {
        local(req) = curl($base_url + '/')
        #req->set(CURLOPT_CUSTOMREQUEST, 'gEt')
        
        expect('' , #req->result)
        expect(501, #req->statusCode)
    }
}

describe(::ws_generateHandshakeResponse) => {
    local(not_implemented)  = bytes('HTTP/1.1 501 Not Implemented')
    local(bad_request)      = bytes('HTTP/1.1 400 Bad Request')
    local(upgrade_required) = bytes(`HTTP/1.1 426 Upgrade Required`)

    describe(`HTTP Version Check`) => {
        it(`Returns "400 Bad Request" when the request specifies HTTP 1.0`) => {
            // By making this a POST request, it also checks that this check runs first
            local(result) = ws_generateHandshakeResponse(http_request('POST / HTTP/1.0\r\n\r\n'))->split('\r\n\r\n')

            expect(#bad_request, #result->first)
            expect('Requires HTTP 1.1 or higher', #result->second)
        }

        it(`Passes the HTTP version check with HTTP 1.2`) => {
            // I'm going to make it a post request so should get different error
            local(result) = ws_generateHandshakeResponse(http_request('POST / HTTP/1.2\r\n\r\n'))->split('\r\n\r\n')
            
            expect(#not_implemented, #result->first)
            expect('Method "POST" is not implemented', #result->second)
        }
    }

    it('Returns a "501 Not Implemented" when called with a method (gEt) that is not supported') => {
        local(result) = ws_generateHandshakeResponse(http_request('gEt / HTTP/1.1\r\n\r\n'))->split('\r\n\r\n')

        expect(#not_implemented, #result->first)
        expect('Method "gEt" is not implemented', #result->second)
    }
    it('Returns a "501 Not Implemented" when called with a method that is not implemented') => {
        local(req_head) = ws_generateHandshakeResponse(http_request('HEAD / HTTP/1.1\r\n\r\n'))->split('\r\n\r\n')
        local(req_post) = ws_generateHandshakeResponse(http_request('POST / HTTP/1.1\r\n\r\n'))->split('\r\n\r\n')
        local(req_put) =  ws_generateHandshakeResponse(http_request('PUT / HTTP/1.1\r\n\r\n'))->split('\r\n\r\n')

        expect(#not_implemented, #req_head->first)
        expect(#not_implemented, #req_post->first)
        expect(#not_implemented, #req_put->first)

        expect('Method "HEAD" is not implemented', #req_head->second)
        expect('Method "POST" is not implemented', #req_post->second)
        expect('Method "PUT" is not implemented' , #req_put->second)
    }

    it(`returns a 400 response if request path isn't a path or absolute URI`) => {
        local(result) = ws_generateHandshakeResponse(http_request('GET * HTTP/1.1\r\n\r\n'))->split('\r\n\r\n')

        expect(#bad_request, #result->first)
        expect('Malformated URL', #result->second)
    }

    it(`returns a 400 response if there is no "host" header field`) => {
        local(result) = ws_generateHandshakeResponse(http_request('GET / HTTP/1.1\r\n\r\n'))->split('\r\n\r\n')
        
        expect(#bad_request, #result->first)
        expect(#result->second->contains("Missing header field"))
        expect(#result->second->contains("Host"))
    }

    it(`returns a 400 response if there is no "upgrade" header`) => {
        local(result) = ws_generateHandshakeResponse(http_request(
            'GET / HTTP/1.1\r\n\
            Host: localhost\r\n\r\n'
        ))->split('\r\n\r\n')
        
        expect(#bad_request, #result->first)
        expect(#result->second->contains("Missing header field"))
        expect(#result->second->contains("Upgrade"))
    }
    it(`returns a 400 response if the "upgrade" header doesn't contain "websocket"`) => {
        local(result) = ws_generateHandshakeResponse(http_request(
            'GET / HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: 8 Available\r\n\r\n'
        ))->split('\r\n\r\n')
        
        expect(#bad_request, #result->first)
        expect(#result->second->contains(`Missing "websocket" Upgrade header`))
    }

    it(`returns a 400 response if there is no "connection" header`) => {
        local(result) = ws_generateHandshakeResponse(http_request(
            'GET / HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\r\n'
        ))->split('\r\n\r\n')
        
        expect(#bad_request, #result->first)
        expect(#result->second->contains("Missing header field"))
        expect(#result->second->contains("Connection"))
    }
    it(`returns a 400 response if the "connection" header doesn't contain "upgrade"`) => {
        local(result) = ws_generateHandshakeResponse(http_request(
            'GET / HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: intermitent\r\n\r\n'
        ))->split('\r\n\r\n')
        
        expect(#bad_request, #result->first)
        expect(#result->second->contains(`Missing "upgrade" Connection header`))
    }

    it(`returns a 400 response if there is no "Sec-WebSocket-Key" header`) => {
        local(result) = ws_generateHandshakeResponse(http_request(
            'GET / HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\r\n'
        ))->split('\r\n\r\n')

        expect(#bad_request, #result->first)
        expect(#result->second->contains("Missing header field"))
        expect(#result->second->contains("Sec-WebSocket-Key"))
    }
    it(`returns a 400 response if the "Sec-WebSocket-Key" header doesn't decode to a 16 length byte stream`) => {
        local(result) = ws_generateHandshakeResponse(http_request(
            'GET / HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: cmhpbm8=\r\n\r\n'
        ))->split('\r\n\r\n')
        
        expect(#bad_request, #result->first)
        expect(#result->second->contains(`Sec-WebSocket-Key header value is invalid`))
    }

    it(`returns a 400 response if there is no "Sec-WebSocket-Version" header`) => {
        local(result) = ws_generateHandshakeResponse(http_request(
            'GET / HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: cmhpbm8hcmhpbm8hcmhpbg==\r\n\r\n\r\n\r\n'
        ))->split('\r\n\r\n')
        
        expect(#bad_request, #result->first)
        expect(#result->second->contains("Missing header field"))
        expect(#result->second->contains("Sec-WebSocket-Version"))
    }
    it(`returns a 426 response if the "Sec-WebSocket-Version" header doesn't contain proper version`) => {
        local(result) = http_request(ws_generateHandshakeResponse(http_request(
            'GET / HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: cmhpbm8hcmhpbm8hcmhpbg==\r\n\
            Sec-WebSocket-Version: 0\r\n\r\n'
        )))
        local(headers)  = #result->headers
        local(versions) =(with v in ws_supportedVersions select string(#v))->join(',') 

        expect(#upgrade_required          , #result->message)
        expect(`websocket`                , #headers->find('Upgrade')->asString)
        expect(`upgrade`                  , #headers->find('Connection')->asString)
        expect(ws_supportedVersions->first, integer(#headers->find(`Sec-WebSocket-Version`)))

        expect(#result->body->contains(`Sec-WebSocket-Version header requesting invalid version`))
    }
}