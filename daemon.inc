local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
sourcefile(file(#here + 'lib.inc'         ), -autoCollect=false)->invoke
sourcefile(file(#here + 'http_request.inc'), -autoCollect=false)->invoke


var(listener) = net_tcp
handle => { $listener->close }
$listener->bind(8000)&listen



define daemon_connect(con) => {
    //local(con) = #1
    local(req) = ''
    handle => { #con->close }
    
    // Read in the request in chunks
    {
        #req->append(#con->readSomeBytes(8096))
        not #req->contains('\r\n\r\n')? currentCapture->restart
    }()
    
    local(response) = ws_generateHandshakeResponse(http_request(#req))

    #con->writeBytes(#response)
    not #response->beginsWith(bytes(`HTTP/1.1 101 Switching Protocols`))
        ? return  // Closing the connection with the handle
    
    while(true) => {
        //read_data
        //send_data
    }
    // If we've gotten here, then we have received a good handshake
}

$listener->forEachAccept => { daemon_connect(#1) }