local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
if(not var_defined(`_ws_loaded`)) => {
    sourcefile(file(#here + 'spec_helper.inc'), -autoCollect=false)->invoke
}


describe(`websocket_handler->handshake`) => {
    local(ws_con)

    describe(`HTTP Version Check`) => {
        it(`Returns "400 Bad Request" when the request specifies HTTP 1.0`) => {
            // By making this a POST request, it also checks that this check runs first
            #ws_con = test_conn
            #ws_con->requestParams = map(
                ::SERVER_PROTOCOL = `HTTP/1.0`,
                ::REQUEST_METHOD  = `POST`,
                ::PATH_INFO       = `/`
            )
            websocket_handler->handshake(#ws_con)

            expect(400            , #ws_con->statusCode)
            expect(http_status_400, #ws_con->statusMsg)

            expect('Requires HTTP 1.1 or higher', #ws_con->body)
        }

        it(`Passes the HTTP version check with HTTP 1.2`) => {
            // I'm going to make it a post request so should get different error
            #ws_con = test_conn
            #ws_con->requestParams = map(
                ::SERVER_PROTOCOL = `HTTP/1.2`,
                ::REQUEST_METHOD  = `POST`,
                ::PATH_INFO       = `/`
            )
            websocket_handler->handshake(#ws_con)

            expect(501            , #ws_con->statusCode)
            expect(http_status_501, #ws_con->statusMsg)

            expect('Method "POST" is not implemented', #ws_con->body)
        }
    }

    it('Returns a "501 Not Implemented" when called with a method (gEt) that is not supported') => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `gEt`,
            ::PATH_INFO       = `/`
        )
        websocket_handler->handshake(#ws_con)

        expect(501            , #ws_con->statusCode)
        expect(http_status_501, #ws_con->statusMsg)

        expect('Method "gEt" is not implemented', #ws_con->body)
    }
    it('Returns a "501 Not Implemented" when called with a method that is not implemented') => {
        local(req_head) = test_conn
        local(req_post) = test_conn
        local(req_put) =  test_conn

        #req_head->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `HEAD`,
            ::PATH_INFO       = `/`
        )
        #req_post->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `POST`,
            ::PATH_INFO       = `/`
        )
        #req_put->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `PUT`,
            ::PATH_INFO       = `/`
        )

        websocket_handler->handshake(#req_head)
        websocket_handler->handshake(#req_post)
        websocket_handler->handshake(#req_put)

        expect(501            , #req_head->statusCode)
        expect(http_status_501, #req_head->statusMsg)
        expect(501            , #req_post->statusCode)
        expect(http_status_501, #req_post->statusMsg)
        expect(501            , #req_put ->statusCode)
        expect(http_status_501, #req_put ->statusMsg)

        expect('Method "HEAD" is not implemented', #req_head->body)
        expect('Method "POST" is not implemented', #req_post->body)
        expect('Method "PUT" is not implemented' , #req_put ->body)
    }

    it(`returns a 400 response if request path isn't a path or absolute URI`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `GET`,
            ::PATH_INFO       = `*`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)

        expect('Malformated URL', #ws_con->body)
    }

    it(`returns a 400 response if there is no "host" header field`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `GET`,
            ::PATH_INFO       = `/`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)
        
        expect(#ws_con->body->contains("Missing header field"))
        expect(#ws_con->body->contains("Host"))
    }

    it(`returns a 400 response if there is no "upgrade" header`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `GET`,
            ::PATH_INFO       = `/`,
            ::HTTP_HOST       = `localhost`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)
        
        expect(#ws_con->body->contains("Missing header field"))
        expect(#ws_con->body->contains("Upgrade"))
    }
    it(`returns a 400 response if the "upgrade" header doesn't contain "websocket"`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `GET`,
            ::PATH_INFO       = `/`,
            ::HTTP_HOST       = `localhost`,
            ::HTTP_UPGRADE    = `8 Available`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)
        
        expect(#ws_con->body->contains(`Missing "websocket" Upgrade header`))
    }

    it(`returns a 400 response if there is no "connection" header`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `GET`,
            ::PATH_INFO       = `/`,
            ::HTTP_HOST       = `localhost`,
            ::HTTP_UPGRADE    = `websocket`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)
        
        expect(#ws_con->body->contains("Missing header field"))
        expect(#ws_con->body->contains("Connection"))
    }
    it(`returns a 400 response if the "connection" header doesn't contain "upgrade"`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `GET`,
            ::PATH_INFO       = `/`,
            ::HTTP_HOST       = `localhost`,
            ::HTTP_UPGRADE    = `websocket`,
            ::HTTP_CONNECTION = `intermitent`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)
        
        expect(#ws_con->body->contains(`Missing "upgrade" Connection header`))
    }

    it(`returns a 400 response if there is no "Sec-WebSocket-Key" header`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL = `HTTP/1.1`,
            ::REQUEST_METHOD  = `GET`,
            ::PATH_INFO       = `/`,
            ::HTTP_HOST       = `localhost`,
            ::HTTP_UPGRADE    = `websocket`,
            ::HTTP_CONNECTION = `Upgrade`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)
        
        expect(#ws_con->body->contains("Missing header field"))
        expect(#ws_con->body->contains("Sec-WebSocket-Key"))
    }
    it(`returns a 400 response if the "Sec-WebSocket-Key" header doesn't decode to a 16 length byte stream`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL        = `HTTP/1.1`,
            ::REQUEST_METHOD         = `GET`,
            ::PATH_INFO              = `/`,
            ::HTTP_HOST              = `localhost`,
            ::HTTP_UPGRADE           = `websocket`,
            ::HTTP_CONNECTION        = `Upgrade`,
            ::HTTP_SEC_WEBSOCKET_KEY = `cmhpbm8=`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)
        
        expect(#ws_con->body->contains(`Sec-WebSocket-Key header value is invalid`))
    }

    it(`returns a 400 response if there is no "Sec-WebSocket-Version" header`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL        = `HTTP/1.1`,
            ::REQUEST_METHOD         = `GET`,
            ::PATH_INFO              = `/`,
            ::HTTP_HOST              = `localhost`,
            ::HTTP_UPGRADE           = `websocket`,
            ::HTTP_CONNECTION        = `Upgrade`,
            ::HTTP_SEC_WEBSOCKET_KEY = `cmhpbm8hcmhpbm8hcmhpbg==`
        )
        websocket_handler->handshake(#ws_con)

        expect(400            , #ws_con->statusCode)
        expect(http_status_400, #ws_con->statusMsg)
        
        expect(#ws_con->body->contains("Missing header field"))
        expect(#ws_con->body->contains("Sec-WebSocket-Version"))
    }
    it(`returns a 426 response if the "Sec-WebSocket-Version" header doesn't contain proper version`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL            = `HTTP/1.1`,
            ::REQUEST_METHOD             = `GET`,
            ::PATH_INFO                  = `/`,
            ::HTTP_HOST                  = `localhost`,
            ::HTTP_UPGRADE               = `websocket`,
            ::HTTP_CONNECTION            = `Upgrade`,
            ::HTTP_SEC_WEBSOCKET_KEY     = `cmhpbm8hcmhpbm8hcmhpbg==`,
            ::HTTP_SEC_WEBSOCKET_VERSION = `0`
        )
        websocket_handler->handshake(#ws_con)

        expect(426            , #ws_con->statusCode)
        expect(http_status_426, #ws_con->statusMsg)

        expect(`websocket`, #ws_con->header->find('Upgrade'))
        expect(`upgrade`  , #ws_con->header->find('Connection'))
        expect(
            websocket_handler->supported->first,
            integer(#ws_con->header->find(`Sec-WebSocket-Version`))
        )
        
        expect(#ws_con->body->contains(`Sec-WebSocket-Version header requesting invalid version`))
    }

    it(`returns the proper handshake response with the proper return key`) => {
        #ws_con = test_conn
        #ws_con->requestParams = map(
            ::SERVER_PROTOCOL            = `HTTP/1.1`,
            ::REQUEST_METHOD             = `GET`,
            ::PATH_INFO                  = `/`,
            ::HTTP_HOST                  = `localhost`,
            ::HTTP_UPGRADE               = `websocket`,
            ::HTTP_CONNECTION            = `Upgrade`,
            ::HTTP_SEC_WEBSOCKET_KEY     = `cmhpbm8hcmhpbm8hcmhpbg==`,
            ::HTTP_SEC_WEBSOCKET_VERSION = `13`
        )
        websocket_handler->handshake(#ws_con)

        expect(101            , #ws_con->statusCode)
        expect(http_status_101, #ws_con->statusMsg)

        expect(`websocket`, #ws_con->header->find('Upgrade'))
        expect(`upgrade`  , #ws_con->header->find('Connection'))

        expect(`ORV6IE9y3CKZHuifmuqQEZmKHIM=`, #ws_con->header->find(`Sec-WebSocket-Accept`))
    }
}