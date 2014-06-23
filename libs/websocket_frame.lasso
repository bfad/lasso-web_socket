define websocket_frame => type {

    data private raw

    public onCreate(data::bytes) => {
        .raw = #data
    }
    public onCreate(
        -fin ::boolean = false,
        -rsv1::boolean = false,
        -rsv2::boolean = false,
        -rsv3::boolean = false,

        -opcode ::integer = 0,
        -maskKey          = null,
        -payload::bytes   = bytes
    ) => {
        local(data)     = bytes
        local(cur_byte) = 0

        #opcode > 0xF or #opcode < 0
            ? fail("Opcode out of range")

        #maskKey->isA(::bytes) and #maskKey->size != 4
            ? fail("Masking key is out of range")
        #maskKey->isA(::integer) and (#maskKey < 0 or #maskKey > 0xFFFFFFFF)
            ? fail("Masking key is out of range")
            | (#maskKey->isA(::integer) ? #maskKey = bytes->import32bits(#maskKey)&)
        

        #fin ? #cur_byte = #cur_byte->bitSet(4)
        #rsv1? #cur_byte = #cur_byte->bitSet(3)
        #rsv2? #cur_byte = #cur_byte->bitSet(2)
        #rsv3? #cur_byte = #cur_byte->bitSet(1)

        // add in opcode
        #cur_byte = #cur_byte->bitShiftLeft(4) + #opcode

        #data->import8bits(#cur_byte)
        #cur_byte = 0

        null != #maskKey
            ? #cur_byte = #cur_byte->bitSet(8)

        local(payload_size) = #payload->size
        match(true) => {
        case(#payload_size < 126)
            #data->import8bits(#cur_byte + #payload_size)

        case(#payload_size <= 0xFFFF)
            #data->import8bits(#cur_byte + 126)&import16bits(#payload_size)

        case(#payload_size > 0xFFFF and #payload_size <= 0xFFFFFFFFFFFFFFFF)
            #data->import8bits(#cur_byte + 127)&import64bits(#payload_size)

        case
            fail('payload too big')
        }
        #cur_byte = 0

        if(#maskKey->isA(::bytes)) => {
            #data->append(#maskKey)
            #payload = .applyMask(#maskKey, #payload)
        }

        #payload_size > 0
            ? #data->append(#payload)

        .raw = #data
    }



    public isFin         => .raw->get(1)->bitShiftRight(4)->bitTest(4)
    public isRsv1        => .raw->get(1)->bitShiftRight(4)->bitTest(3)
    public isRsv2        => .raw->get(1)->bitShiftRight(4)->bitTest(2)
    public isRsv3        => .raw->get(1)->bitShiftRight(4)->bitTest(1)
    public isMasked      => .raw->get(2)->bitTest(8)
    public opcode        => .raw->get(1)->bitClear(8)->bitClear(7)->bitClear(6)->bitClear(5) // I want the last 4 bits of the first byte (might want 'em reversed)
    public payloadLength => {
        local(length) = .payloadLengthOrFlag

        match(true) => {
        case(#length < 126)
            return #length

        case(#length == 126)
            return .raw->getRange(3,4)->padTrailing(2, 0->bytes)&export16bits

        case(#length == 127)
            return .raw->getRange(3,11)->padTrailing(8, 0->bytes)&export64bits
        case
            fail("Can't determine payload length")
        }
    }
    public maskKey => {
        not .isMasked? return null

        local(start) = .numBytesBase + .numBytesForExtendedPayloadLength + 1
        return .raw->getRange(#start, #start + 4)
    }
    public payload => {
        local(start) = .numBytesBase + .numBytesForExtendedPayloadLength + .numBytesForMask + 1
        local(end)   = #start + .payloadLength

        return .raw->getRange(#start, #end)
    }
    public payloadUnmasked => not .isMasked? .payload | .applyMask(.maskKey, .payload)

    public applyMask(key::bytes, data::bytes) => {
        local(retval) = bytes

        loop(#data->size) => {
            #retval->append(bytes->import8bits(#data->get(loop_count)->bitXor(#key->get(((loop_count - 1) % 4) + 1)))&)
        }

        return #retval
    }

    private payloadLengthOrFlag => .raw->get(2)->bitClear(8)

    private numBytesBase => 2

    private numBytesForMask => .isMasked? 4 | 0

    private numBytesForExtendedPayloadLength => {
        local(flag) = .payloadLengthOrFlag
        match(true) => {
        case(#flag < 126)
            return 0
        case(#flag == 126)
            return 2
        case(#flag == 127)
            return 8
        case
            fail("Invalid payload length flag")
        }
    }
}