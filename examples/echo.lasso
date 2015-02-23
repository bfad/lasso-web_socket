local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
sourcefile(file(#here + '../websocket_server.lasso'), -autoCollect=false)->invoke


define echo_websocket => type { parent websocket_handler
    
    public onCreate(conn::web_connection) => {
        // hand shake
        ..onCreate(#conn)
        .handshake

        handle => { .close }
        .handleMessages
    }

    public handleMessages => {
        local(read)
        while(#read := .readMsg) => {
            log_always('READ: ' + #read)
            .writeMsg('ECHO: ' + #read)
        }
    }
    
}

http_server->start(8282, '127.0.0.1', -handler=\(::echo_websocket))