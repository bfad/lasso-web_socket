define websocket_frame => type {

    data private raw

    public onCreate(data::bytes) => {
        .raw = #data
    }



    public isFin         => .raw->get(1)->bitTest(1)
    public isRsv1        => .raw->get(1)->bitTest(2)
    public isRsv2        => .raw->get(1)->bitTest(3)
    public isRsv3        => .raw->get(1)->bitTest(4)
    public isMasked      => .raw->get(2)->bitTest(1)
    public opcode        => .raw->get(1)->bitShiftRight(4) // I want the last 4 bits of the first byte (might want 'em reversed)
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
        return .raw->getRange(#start, #start + 4)->export32bits
    }
    public payload => {
        local(start) = .numBytesBase + .numBytesForExtendedPayloadLength + .numBytesForMask + 1
        local(end)   = #start + .payloadLength

        return .raw->getRange(#start, #end)
    }


    private payloadLengthOrFlag => .raw->get(2)->bitShiftRight(1)

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