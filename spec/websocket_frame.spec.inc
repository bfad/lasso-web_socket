local(here) = currentCapture->callSite_file->stripLastComponent + '/'
not #here->beginsWith('/') or #here->size == 1
    ? #here = io_file_getcwd + '/' + #here
if(not var_defined(`_ws_loaded`)) => {
    sourcefile(file(#here + 'spec_helper.inc'), -autoCollect=false)->invoke
}


describe(::websocket_frame) => {
    context(`Given a bytestream that is a complete frame`) => {
        describe(`-> isFin`) => {
            it(`returns true when the first bit is set to 1`) => {
                expect(true, websocket_frame(0x1->bytes)->isFin)
            }
            it(`returns false when the first bit is set to 0`) => {
                expect(false, websocket_frame(0->bytes)->isFin)
            }
        }

        describe(`-> isRsv1`) => {
            it(`returns true when the second bit is set to 1`) => {
                expect(true, websocket_frame(integer->bitSet(2)->bytes)->isRsv1)
            }
            it(`returns false when the second bit is set to 0`) => {
                expect(false, websocket_frame(0->bytes)->isRsv1)
            }
        }

        describe(`-> isRsv2`) => {
            it(`returns true when the second bit is set to 1`) => {
                expect(true, websocket_frame(integer->bitSet(3)->bytes)->isRsv2)
            }
            it(`returns false when the second bit is set to 0`) => {
                expect(false, websocket_frame(0->bytes)->isRsv2)
            }
        }

        describe(`-> isRsv3`) => {
            it(`returns true when the second bit is set to 1`) => {
                expect(true, websocket_frame(integer->bitSet(4)->bytes)->isRsv3)
            }
            it(`returns false when the second bit is set to 0`) => {
                expect(false, websocket_frame(0->bytes)->isRsv3)
            }
        }

        describe(`-> opcode`) => {
            it(`returns the value of the last four bits of the first byte`) => {
                expect(0xC, websocket_frame(0xC0->bytes)->opcode)
                expect(0x3, websocket_frame(0x31->bytes)->opcode)
            }
        }

        describe(`-> isMasked`) => {
            it(`returns true when the ninth bit is set to 1`) => {
                expect(true, websocket_frame(integer->bitSet(16)->bytes)->isMasked)
            }
            it(`returns false when the ninth bit is set to 0`) => {
                expect(false, websocket_frame(0->bytes)->isMasked)
            }
        }

        describe(`-> payloadLength`) => {
            it(`uses the last 7 bits of the second byte to return values < 126`) => {
                expect(125, websocket_frame(0xFD91->bytes)->payloadLength)
            }

            it(`uses bytes 3 & 4 to determine the payload length if the last 7 bits of the second byte is 126`) => {
                expect(130, websocket_frame(0x0082FE91->bytes)->payloadLength)
            }

            it(`uses bytes 3 - 11 to determine the payload length if the last 7 bits of the second byte is 127`) => {
                expect(65536, websocket_frame(0x10000FF91->bytes)->payloadLength)
            }
        }

        describe(`-> maskKey`) => {
            it(`returns null if isMasked is false`) => {
                local(frame) = websocket_frame(0x7A91->bytes)

                expect(false, #frame->isMasked)
                expect(null , #frame->maskKey)
            }

            it(`returns a 32bit value used for the mask`) => {
                local(frame) = websocket_frame(0x3FFFB91->bytes)
                
                expect(true, #frame->isMasked)
                expect(1023, #frame->maskKey->export32bits)
            }
        }

        describe(`-> payload`) => {
            it(`returns the rest of the bytes data based up to the size specified by the payloadLength`) => {
                // This has a mask
                // Have to be very exact with all this to get it to work right.
                // The concatenation actualy sticks the 0x3FA7 to the front of new byte stream
                // Also, integer->bytes doesn't work for > 64bit streams (also seems to always produce a 64bit stream)
                expect(
                    bytes->import32bits(0x3FA79BB8)&,
                    websocket_frame(bytes->import64bits(0x9BB8000003FF8491)& + bytes->import16bits(0x3FA7)&)->payload
                )
            }
        }

        describe(`-> payloadUnmasked`) => {}
    }
}