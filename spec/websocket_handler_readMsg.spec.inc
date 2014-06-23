local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
if(not var_defined(`_ws_loaded`)) => {
    sourcefile(file(#here + 'spec_helper.inc'), -autoCollect=false)->invoke
}


describe(`websocket_handler->readMsg`) => {
    context(`When no data is sent`) => {
        it(`returns null if an open connection`) => {
            expect(::null, websocket_handler(test_conn(mock_tcp))->readMsg->type)
        }
        it(`returns null if no connection`) => {
            expect(::null, websocket_handler(test_conn)->readMsg->type)
        }
    }
    context(`Only message is a control frame`) => {
        describe(`Close`) => {
            it(`sends an error close message if the client sends an unmasked frame and closes the connection`) => {
                local(mtcp) = mock_tcp(array(
                    bytes->import8bits(0x88)&import8bits(0x00)&
                ))
                local(client_frame) = websocket_frame(#mtcp->readStore->get(1))
                // Make sure the frame was properly setup
                expect(false, #client_frame->isMasked)
                expect(true , #client_frame->isFin)
                expect(0x8  , #client_frame->opcode)

                // Test the response
                expect(null, websocket_handler(test_conn(#mtcp))->readMsg)
                expect(not #mtcp->isOpen)
                expect(bytes->import16bits(1002->hostToNet16)&, websocket_frame(#mtcp->writeStore->first)->payloadUnmasked->getRange(1,2))
            }

            it(`sends a responding close message echoing the status code (if one hasn't been sent) and closes the connection`) => {
                local(mtcp) = mock_tcp(array(
                    websocket_frame(
                        -fin,
                        -opcode  = ws_opcode_close,
                        -maskKey = sys_random->bitAnd(0xFFFFFFFF),
                        -payload = bytes->import16bits(1000->hostToNet16)&
                    )->raw
                ))
                local(handler) = websocket_handler(test_conn(#mtcp))

                expect(::null, #handler->readMsg->type)
                expect(not #mtcp->isOpen)
                expect(1000, websocket_frame(#mtcp->writeStore->first)->payload->export16bits)
            }

            it(`Just closes the connection if it's receiving a responsive close`) => {
                local(mtcp) = mock_tcp(array(
                    websocket_frame(
                        -fin,
                        -opcode  = ws_opcode_close,
                        -maskKey = sys_random->bitAnd(0xFFFFFFFF),
                        -payload = bytes->import16bits(1000->hostToNet16)&
                    )->raw
                ))
                local(handler) = websocket_handler(test_conn(#mtcp))

                expect(0, #mtcp->writeStore->size)

                #handler->sendClose

                expect(1, #mtcp->writeStore->size)

                #handler->readMsg

                // verify didn't send another close message
                expect(1, #mtcp->writeStore->size)
                expect(not #mtcp->isOpen)
            }
        }

        describe(`Ping`) => {
            it(`sends an error close message if the client sends an unmasked frame`) => {
                local(mtcp) = mock_tcp(array(
                    websocket_frame(
                        -fin,
                        -opcode  = ws_opcode_ping,
                        -payload = bytes('ding!')
                    )->raw
                ))

                expect(null, websocket_handler(test_conn(#mtcp))->readMsg)
                expect(1002, websocket_frame(#mtcp->writeStore->first)->payload->export16bits->netToHost16)
            }

            it(`sends a pong response with the same data as the ping and returns no data`) => {
                local(mtcp) = mock_tcp(array(
                    websocket_frame(
                        -fin,
                        -opcode  = ws_opcode_ping,
                        -maskKey = sys_random->bitAnd(0xFFFFFFFF),
                        -payload = bytes('ding!')
                    )->raw
                ))

                expect(::null, websocket_handler(test_conn(#mtcp))->readMsg->type)
                local(written) = websocket_frame(#mtcp->writeStore->first)

                expect(bytes('ding!'), #written->payload)
                expect(ws_opcode_pong, #written->opcode)
            }
        }

        describe(`Pong`) => {
            it(`sends an error close message if the client sends an unmasked frame`) => {
                local(mtcp) = mock_tcp(array(
                    websocket_frame(
                        -fin,
                        -opcode  = ws_opcode_pong,
                        -payload = bytes('dong!')
                    )->raw
                ))

                expect(null, websocket_handler(test_conn(#mtcp))->readMsg)
                expect(1002, websocket_frame(#mtcp->writeStore->first)->payload->export16bits->netToHost16)
            }

            it(`returns no data and writes nothing in response`) => {
                local(mtcp) = mock_tcp(array(
                    websocket_frame(
                        -fin,
                        -opcode  = ws_opcode_pong,
                        -maskKey = sys_random->bitAnd(0xFFFFFFFF),
                        -payload = bytes('ding!')
                    )->raw
                ))

                expect(::null, websocket_handler(test_conn(#mtcp))->readMsg->type)
                expect(0     , #mtcp->writeStore->size)
            }
        }
    }

    /*
    it(`closes the connection if the client sends unmasked message`) => {
        // In this case, a server MAY send a Close frame with a status code of 1002 (protocol error) as defined in Section 7.4.1.
    }

    it(`properly reads a single-framed message`) => {}

    it(`properly reads a message in two frames`) => {}

    it(`properly reads a message in three frames`) => {}

    it(`properly reads multiple messages into a message queue?`) => {}*/
}