local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
if(not var_defined(`_cms_loaded`)) => {
    sourcefile(file(#here + 'spec_helper.inc'), -autoCollect=false)->invoke
}


describe(::http_request) => {
    describe('Parsing the HTTP Message') => {
        it("properly parses the HTTP message") => {
            local(req) = http_request('GET /foo?d=c HTTP/1.1\r\n\r\n')
            
            expect('GET /foo?d=c HTTP/1.1', #req->message)
            expect('GET'     , #req->method)
            expect('HTTP/1.1', #req->protocol)
            expect(1.1       , #req->protocolVersion)
            expect('/foo?d=c', #req->uri)
        }
        
        it("properly parses basic headers") => {
            local(req) = http_request('\
                GET / HTTP/1.1\r\n\
                Host: localhost:8000\r\n\
                Accept: text/html\r\n\r\n\
            ')
            
            expect('localhost:8000', #req->headers->get('Host'))
            expect('text/html'     , #req->headers->get('Accept'))
        }
        it("properly parses headers that wrap with a space") => {
            local(req) = http_request('\
                GET / HTTP/1.1\r\n\
                Host: localhost:8000\r\n\
                Accept: text/html;\r\n text/xml\r\n\r\n\
            ')
            
            expect('localhost:8000'     , #req->headers->get('Host'))
            expect('text/html; text/xml', #req->headers->get('Accept'))
        }
        
        it("properly parses headers that wrap with a tab") => {
            local(req) = http_request('\
                GET / HTTP/1.1\r\n\
                Host: localhost:8000\r\n\
                Accept: text/html;\r\n\ttext/xml\r\n\r\n\
            ')
            
            expect('localhost:8000'     , #req->headers->get('Host'))
            expect('text/html;\ttext/xml', #req->headers->get('Accept'))
        }
        it("properly parses repeated headers as csv values") => {
            local(req) = http_request('\
                GET / HTTP/1.1\r\n\
                Host: localhost:8000\r\n\
                Accept: text/html\r\n\
                Accept: text/xml\r\n\r\n\
            ')
            
            expect('localhost:8000'    , #req->headers->get('Host'))
            expect('text/html,text/xml', #req->headers->get('Accept'))
        }
        it("sticks the message body into body") => {
            local(req) = http_request('\
                GET / HTTP/1.1\r\n\
                Host: localhost:8000\r\n\
                Accept: text/html\r\n\r\n\
                Message Body\
            ')
            
            expect('Message Body', #req->body)
        }
    }
}