define http_request => type {
    data private message,
         public  headers = null,
         public  body    = null
    
    public onCreate(raw::string) => .onCreate(#raw->asBytes)
    public onCreate(raw::bytes)  => {
        .'message' = #raw->sub(1, #raw->find('\r\n') - 1)->split(' ')
        #raw->remove(1, #raw->find('\r\n') + 1)
        
        if(not #raw->beginsWith('\r\n')) => {
            .'headers' = map
            
            local(tmp_headers) = #raw->sub(1, #raw->find('\r\n\r\n') - 1)
            #tmp_headers->replace('\r\n ' , ' ')
            #tmp_headers->replace('\r\n\t', '\t')
            
            with header in #tmp_headers->split('\r\n') 
            let key = #header->sub(1, #header->find(':') - 1)
            let val = #header->sub(#header->find(':') + 1)
            let cur = .'headers'->find(#key)
            do {
                #val->trim
                // Taking advantage of #cur being a references in the else clause
                #cur == void
                    ? .'headers'->insert(#key=#val)
                    | #cur->append(',' + #val)
            }
            
            #raw->remove(1, #raw->find('\r\n\r\n') + 1)
        }
        
        // By the time we get here, #raw should have the \r\n of the empty line
        // and the message body, so remove that empty line and setup the body.
        #raw->remove(1,2)
        #raw->size > 0? .'body' = #raw
    }
    
    public message  => .'message'->join(' ')->asString
    public method   => .'message'->get(1)->asString
    public uri      => .'message'->get(2)->asString
    public protocol => .'message'->get(3)->asString

    public protocolVersion => decimal(.protocol->split(`/`)->second)
}