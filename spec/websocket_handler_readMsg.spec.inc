local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
if(not var_defined(`_ws_loaded`)) => {
    sourcefile(file(#here + 'spec_helper.inc'), -autoCollect=false)->invoke
}


describe(`websocket_handler->readMsg`) => {
    it(`closes the connection if the client sends unmasked message`) => {
        // In this case, a server MAY send a Close frame with a status code of 1002 (protocol error) as defined in Section 7.4.1.
    }

    it(`properly reads a single-framed message`) => {}

    it(`properly reads a message in two frames`) => {}

    it(`properly reads a message in three frames`) => {}

    it(`properly reads multiple messages into a message queue?`) => {}
}