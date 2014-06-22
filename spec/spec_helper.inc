if(not var_defined(`_ws_loaded`)) => {

    local(here) = currentCapture->callSite_file->stripLastComponent + '/'
    not #here->beginsWith('/') or #here->size == 1
        ? #here = io_file_getcwd + '/' + #here

    sourcefile(file(#here + '../lib.inc'), -autoCollect=false)->invoke
    sourcefile(file(#here + '../websocket_frame.lasso'), -autoCollect=false)->invoke

    var(_ws_loaded) = true
}

// A web_connection mock
define test_conn => type {
    trait { import web_connection }
    
    data
        public requestParams::trait_map = map,
        public stdin  = '',
        public mimes  = '',
        public header = map,
        public body   = '',
        public statusCode = 200,
        public statusMsg  = `OK`

    public getStatus()  => pair(.statusCode, .statusMsg)
    public setStatus(code::integer, msg::string) => {
        .'statusCode' = #code
        .'statusMsg'  = #msg
    }
    public writeHeaderLine(h::string) => {
        local(key, val) = #h->split(`:`)
        #val->trim
        .'header'->insert(#key=#val)
    }
    public writeHeaderBytes(b::bytes) => {
        // Remove the opening line 
        #b->remove(1, #b->find('\r\n') + 1)
        
        if(not #b->beginsWith('\r\n')) => {
            .'header' = map
            
            local(tmp_headers) = #b->sub(1, #b->find('\r\n\r\n') - 1)
            #tmp_headers->replace('\r\n ' , ' ')
            #tmp_headers->replace('\r\n\t', '\t')
            
            with header in #tmp_headers->split('\r\n') 
            let key = #header->sub(1, #header->find(':') - 1)
            let val = #header->sub(#header->find(':') + 1)
            let cur = .'header'->find(#key)
            do {
                #val->trim
                // Taking advantage of #cur being a references in the else clause
                #cur == void
                    ? .'header'->insert(#key=#val)
                    | #cur->append(',' + #val)
            }
            
            #b->remove(1, #b->find('\r\n\r\n') + 1)
        }
    }
    public writeBodyBytes(b::bytes) => {
        .'body' = #b
    }
    public connection() => {}

    // Not for the trait
    public writeHeader => {}
}