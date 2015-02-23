local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
sourcefile(file(#here + '../websocket_server.lasso'), -autoCollect=false)->invoke


// Storing the connections in a thread object so that it can be used by other threads
define app_websocket_store => thread {
    data
        private store::map

    public onCreate() => {
        .store = map
    }
    
    public addConnectionHandler(connection_handler) => {
        .store->insert(#connection_handler->id = #connection_handler)
    }
}


define app_websocket => type { parent websocket_handler
    data
        private id

    public id => .`id`

    public onCreate(conn::web_connection) => {
        ..onCreate(#conn)
        .handshake

        .id = lasso_uniqueID

        app_websocket_store->addConnectionHandler(self)

        handle => { .close }
        .handleMessages
    }

    public handleMessages => {
        // Here is where I would call a method that just waits for messages and then
        // call the appropriate app_websocket_store method if needed
        local(read)
        while(#read := .readMsg) => {
            // Deal with incoming messages from the client
        }
    }
}

// If running this from a lassoserver instance, split this into it's own thread
// so that the server won't block the lassoserver from continuing to run.
local(server) = http_server
handle => {
    #server->close
}
#server->start(8282, '127.0.0.1', -handler=\(::app_websocket))
