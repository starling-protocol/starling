package packet_layer

import "errors"

type packetHeader struct {
	size  int
	flags packetFlags
}

func newPacketHeader(size int, flags packetFlags) packetHeader {
	return packetHeader{
		size:  size,
		flags: flags,
	}
}

func (header *packetHeader) toBytes() [2]byte {
	var bytes [2]byte
	bytes[0] = (byte(header.size>>8) & 0b11) | header.flags.toByte()
	bytes[1] = byte(header.size & 0xff)
	return bytes
}

func packetHeaderFromBytes(bytes []byte) (packetHeader, error) {
	if len(bytes) < 2 {
		return packetHeader{}, errors.New("corrupt packet: header expected at least 2 bytes")
	}

	flags := packetFlagsFromByte(bytes[0])
	size := (int(bytes[0]&0x3F) << 8) | int(bytes[1])

	return packetHeader{
		flags: flags,
		size:  size,
	}, nil
}

type packetFlags struct {
	NonEmpty bool
	// this packet continues in the next one
	Continuation bool
}

func newPacketFlags(continuation bool) packetFlags {
	return packetFlags{
		NonEmpty:     true,
		Continuation: continuation,
	}
}

func (flags *packetFlags) toByte() byte {
	bitRep := func(value bool, bitIdx byte) byte {
		if value {
			return 1 << (7 - bitIdx)
		} else {
			return 0
		}
	}

	result := byte(0)
	result |= bitRep(flags.NonEmpty, 0)
	result |= bitRep(flags.Continuation, 1)

	return result
}

func packetFlagsFromByte(b byte) packetFlags {
	readBit := func(bitIdx byte) bool {
		if b&(1<<(7-bitIdx)) > 0 {
			return true
		} else {
			return false
		}
	}

	flags := packetFlags{}
	flags.NonEmpty = readBit(0)
	flags.Continuation = readBit(1)

	return flags
}
