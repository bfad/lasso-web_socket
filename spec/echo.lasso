local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
sourcefile(file(#here + '../lib.lasso'), -autoCollect=false)->invoke




\net_tcp
define net_tcp->readBytesFully(count::integer, timeoutSeconds::integer = -1, timeoutCallback = null)::bytes => {
        local(data = bytes, left = integer(#count))
        {
            #left <= 0?
                return #data
            local(read = .readSomeBytes(#left, #timeoutSeconds))
            if (VOID == #read) => {
                #timeoutCallBack? #timeoutCallBack(#data)
                return #data
            }
            #read->size == 0?
                fail(-1, 'Unable to fully read ' + #count + ' bytes. Only read ' + (#count-#left))
            #data += #read
            #left -= #read->size
            currentCapture->restart
        }()
        return #data
    }



define echo_websocket => type {

    parent websocket_handler
    
    data protected lastMsg
    
    public invoke(conn::web_connection) => { handle_error => stdoutnl(error_stack + '\n' + error_msg)
        // hand shake
        .handshake(#conn)


        
        log_always('did handshake')
        local(read)

        while(true) => {
            if(#read := .readMsg(#conn)) => {
                log_always('READ: '+#read)
                .writeMsg('ECHO: '+#read, #conn)
            }
            sleep(1000)
        }
        .close(#conn)
        log_always('Request done')
    }

    public readMsg(conn::web_connection) => {
        // TRASH
        local(data) = bytes
        local(buffer)
        while(#conn->net and #buffer := #conn->net->readSomeBytes(1024)) => {
            #data->append(#buffer)
        }

        #data->size == 0 ? return

        //log_always('0x' + (with d in #data->eachByte sum #d->asStringHex))
        local(x) = websocket_frame(#data) 

        return #x->payloadUnmasked
    }

    public writeMsg(msg::bytes, conn::web_connection) => {
        local(msgBytes = bytes)
        #msgBytes->import8bits(0x81)
            &import8Bits(#msg->size)
            &importBytes(#msg)
            log_always(#msg->size)
        //log_always('0x' + (with b in #msgBytes->eachByte sum #b->asStringHex))
        //#msgBytes=bytes
        //#msgBytes->import8bits(0x81)&import8bits(0x05)&import8bits(0x48)&import8bits(0x65)&import8bits(0x6c)&import8bits(0x6c)&import8bits(0x6f)
        #conn->net->writeBytes(#msgBytes)
        //.close(#conn)
    }
    public writeMsg(msg::string, conn::web_connection) => .writeMsg(#msg->asBytes, #conn)

    public close(conn::web_connection) => #conn->close
    
}

http_server->start(8282, '127.0.0.1', -handler=echo_websocket)