define websocket_handler => type {

    data
        private supported          = (:13),
        private sentClose::boolean = false
    data
        protected connection

    public supported  => .`supported`
    public connection => .`connection`
    public netTcp     => .`connection`->connection


    public onCreate() => {}
    public onCreate(conn::web_connection) => {
        .connection = #conn
    }


    public handshake => {
        local(conn)   = .connection
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


    // Default timeout is -1 which means block until you get a message
    public readMsg(timeout::integer=-1) => {
        local(frame) = .getFrame(#timeout)
        #frame->isA(::null)? return null

        match(#frame->opcode) => {
        case(ws_opcode_close)
            not .sentClose
                ? .sendClose(#frame->payloadUnmasked->getRange(1,2)->export16bits)
            .close
            return null

        case(ws_opcode_ping)
            .sendPong(#frame->payloadUnmasked)
            return .readMsg(#timeout)

        case(ws_opcode_pong)
            return .readMsg(#timeout)

        case(ws_opcode_binaryData, ws_opcode_continuation)
            #frame->isFin
                ? return #frame->payloadUnmasked

            local(more_data) = .readMsg(#timeout)
            #more_data->isA(::null)? return null
            
            return (#frame->payloadUnmasked + #more_data)

        case(ws_opcode_textData)
            #frame->isFin
                ? return #frame->payloadUnmasked->exportAs('UTF-8')

            local(more_data) = .readMsg(#timeout)
            #more_data->isA(::null)? return null
            
            return (#frame->payloadUnmasked + #more_data)->exportAs('UTF-8')
        }

        return null
    }

    private getFrame(timeout::integer) => {
        local(conn) = .netTcp
        not #conn or not #conn->isOpen
            ? return null

        local(buffer) = #conn->readSomeBytes(2, #timeout)
        #buffer->size != 2 ? return null

        local(info_frame)     = websocket_frame(#buffer)
        local(base_size)      = 2
        local(mask_size)      = #info_frame->numBytesForMask
        local(expayload_size) = #info_frame->numBytesForExtendedPayloadLength

        #expayload_size != 0
            ? #info_frame = websocket_frame(#buffer->append(#conn->readSomeBytes(#expayload_size))&)


        local(data)
        local(bytes_left) = #mask_size + #info_frame->payloadLength
        while(#conn and #conn->isOpen and #bytes_left > 0 and #data := #conn->readSomeBytes(#bytes_left)) => {
            #bytes_left -= #data->size
            #buffer->append(#data)
        }

        #buffer->size != #base_size + #mask_size + #expayload_size + #info_frame->payloadLength
            ? return null

        local(frame) = websocket_frame(#buffer)
        if(not #frame->isMasked) => {
            .sendClose(ws_statusCode_clientUnmasked, ws_statusMsg_clientUnmasked)
            // In case they sent us an unmasked closed - this will cause TCP connection to be closed
            ws_opcode_close == #frame->opcode
                ? .close
            return null
        }
        return #frame
    }


    public writeMsg(message::string, -maxFrameContentLength::integer=ws_frame_maxPayloadLength) => .writeMsg(bytes(#message), -maxFrameContentLength=#maxFrameContentLength, -isTextData)

    public writeMsg(message::bytes, -maxFrameContentLength::integer=ws_frame_maxPayloadLength, -isTextData::boolean=false) => {
        #message == bytes
            ? return

        #maxFrameContentLength = math_min(#maxFrameContentLength, ws_frame_maxPayloadLength)

        if(#message->size <= #maxFrameContentLength) => {
            .writeFrame(
                websocket_frame(
                    -fin,
                    -opcode  = (#isTextData ? ws_opcode_textData | ws_opcode_binaryData),
                    -payload = #message
                )
            )
            return
        }

        local(num_frames_needed) = (#message->size / #maxFrameContentLength) + ((#message->size % #maxFrameContentLength) > 0 ? 1 | 0)
        local(frame_count) = 1

        // Write first frame
        .writeFrame(websocket_frame(
            -opcode  = (#isTextData ? ws_opcode_textData | ws_opcode_binaryData),
            -payload = #message->sub(1, #maxFrameContentLength)
        ))

        // Write intermediate and final frames
        // If the number of bytes to read in bytes->sub is > then number left, it just does number left (no need to trap for final frame)
        local(num_loops) = #num_frames_needed - 1
        loop(#num_loops) => {
            .writeFrame(websocket_frame(
                -fin     = (loop_count == #num_loops),
                -opcode  = ws_opcode_continuation,
                -payload = #message->sub((#maxFrameContentLength * loop_count) + 1, #maxFrameContentLength)
            ))
        }
    }

    public writeFrame(frame::websocket_frame) => {
        .netTcp->writeBytes(#frame->raw)
    }


    public sendClose(status_code::integer=we_statusCode_normalClose, status_msg::string='') => {
        local(payload) = bytes->import16bits(#status_code->hostToNet16)&append(bytes(#status_msg))&;

        .netTcp->writeBytes(
            websocket_frame(
                -fin,
                -opcode  = ws_opcode_close,
                -payload = #payload
            )->raw
        )

        .sentClose = true
    }

    public sendPong(data::bytes=bytes) => {
        .netTcp->writeBytes(
            websocket_frame(
                -fin,
                -opcode  = ws_opcode_pong,
                -payload = #data
            )->raw
        )
    }

    public close => .connection->close
}

// EXTENDING NET_TCP
protect => {\net_tcp}
define net_tcp->isOpen => .fd->isValid