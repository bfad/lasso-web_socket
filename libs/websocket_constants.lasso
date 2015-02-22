/*
* HTTP status Messages
*/
define http_status_101 => `Switching Protocols`
define http_status_400 => `Bad Request`
define http_status_426 => `Upgrade Required`
define http_status_501 => `Not Implemented`


/*
* Web Socket Status Codes
*/
define ws_statusCode_clientUnmasked => 1002
define ws_statusMsg_clientUnmasked  => "Client sent unmasked data"

define we_statusCode_normalClose => 1000


/*
* Opcodes
*/
define ws_opcode_binaryData   => 0x2
define ws_opcode_close        => 0x8
define ws_opcode_continuation => 0x0
define ws_opcode_textData     => 0x1
define ws_opcode_ping         => 0x9
define ws_opcode_pong         => 0xA


/*
* Miscellaneous
*/
define ws_frame_maxPayloadLength => 9223372036854775807