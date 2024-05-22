package sync

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

type Delta struct {
	PublicKey      NodePublicKey
	Version        Version
	Value          []byte
	AttachedSecret []byte
	Signature      Signature
}

func NewDelta(publicKey NodePublicKey, version Version, value []byte, attachedSecret []byte, signature Signature) *Delta {
	return &Delta{
		PublicKey:      publicKey,
		Version:        version,
		Value:          value,
		AttachedSecret: attachedSecret,
		Signature:      signature,
	}
}

type Deltas []Delta

// Len implements sort.Interface.
func (d Deltas) Len() int {
	return len(d)
}

// Less implements sort.Interface.
func (d Deltas) Less(i int, j int) bool {
	return d[i].Version < d[j].Version
}

// Swap implements sort.Interface.
func (d Deltas) Swap(i int, j int) {
	d[j], d[i] = d[i], d[j]
}

func (d *Delta) Encode(buf []byte) []byte {
	buf = d.PublicKey.Encode(buf)
	buf = d.Version.Encode(buf)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(d.Value)))
	buf = append(buf, d.Value...)

	hasContactAttached := d.AttachedSecret != nil
	if hasContactAttached {
		buf = append(buf, 0x01)
		buf = append(buf, d.AttachedSecret...)
	} else {
		buf = append(buf, 0x00)
	}

	buf = append(buf, d.Signature...)

	return buf
}

func DecodeDelta(buf []byte) (*Delta, int, error) {
	if len(buf) < 40 {
		return nil, 0, errors.New("error decoding delta: 'buffer too short'")
	}

	publicKey := DecodeNodePublicKey(buf[0:])
	version := DecodeVersion(buf[32:])
	length := binary.BigEndian.Uint32(buf[36:])

	if len(buf) < 40+int(length)+65 {
		return nil, 0, errors.New("error decoding delta: 'buffer too short'")
	}

	value := buf[40 : 40+length]
	offset := 40 + int(length)

	var attachedSecret []byte = nil
	hasContactAttached := buf[offset] == 0x01
	offset += 1
	if hasContactAttached {
		if len(buf) < offset+32+64 {
			return nil, 0, errors.New("error decoding delta: 'buffer too short'")
		}

		attachedSecret = buf[offset : offset+32]
		offset += 32
	}

	signature := buf[offset : offset+64]
	if !ed25519.Verify(publicKey.Key(), buf[0:offset], signature) {
		return nil, 0, errors.New("invalid signature for delta")
	}

	return NewDelta(publicKey, version, value, attachedSecret, signature), offset + 64, nil
}

func (d Deltas) Encode(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(d)))
	for _, delta := range d {
		buf = delta.Encode(buf)
	}
	return buf
}

func DecodeDeltas(buf []byte) (Deltas, int, error) {
	if len(buf) < 4 {
		return nil, 0, errors.New("error decoding deltas: 'buffer too short'")
	}

	deltaCount := int(binary.BigEndian.Uint32(buf))

	deltas := []Delta{}
	current := 4
	for i := 0; i < deltaCount; i++ {
		delta, readCount, err := DecodeDelta(buf[current:])
		if err != nil {
			return []Delta{}, 0, err
		}
		deltas = append(deltas, *delta)
		current += readCount
	}

	return deltas, current, nil
}
