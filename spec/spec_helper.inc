if(not var_defined(`_cms_loaded`)) => {

    local(here) = currentCapture->callSite_file->stripLastComponent + '/'
    not #here->beginsWith('/') or #here->size == 1
        ? #here = io_file_getcwd + '/' + #here

    sourcefile(file(#here + '../http_request.inc'), -autoCollect=false)->invoke
    sourcefile(file(#here + '../lib.inc'         ), -autoCollect=false)->invoke

    var(_cms_loaded) = true
}