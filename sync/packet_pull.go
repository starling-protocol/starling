package sync

import (
	"crypto/ed25519"
	"errors"
)

type PullPacket struct {
	senderPublicKey NodePublicKey
	senderVersion   Version
	digest          *Digest
	signature       Signature
}

func pullPacketHeader(senderPublicKey NodePublicKey, senderVersion Version, digest *Digest) []byte {
	buf := []byte{byte(SYNC_PULL)}
	buf = senderPublicKey.Encode(buf)
	buf = senderVersion.Encode(buf)
	buf = digest.EncodeWithoutSender(buf, senderPublicKey)
	return buf
}

func (model *Model) NewPullPacket() (*PullPacket, error) {

	digest := model.Digest()
	senderVersion := digest.Nodes[model.PublicKey]

	header := pullPacketHeader(model.PublicKey, senderVersion, digest)
	signature := ed25519.Sign(model.PrivateKey, header)

	return &PullPacket{
		senderPublicKey: model.PublicKey,
		senderVersion:   senderVersion,
		digest:          digest,
		signature:       signature,
	}, nil
}

func (packet *PullPacket) Encode() []byte {
	buf := pullPacketHeader(packet.senderPublicKey, packet.senderVersion, packet.digest)
	buf = packet.signature.Encode(buf)
	return buf
}

func DecodePullPacket(buf []byte) (*PullPacket, error) {
	if len(buf) < 37 {
		return nil, errors.New("error decoding sync pull packet 'buffer too short'")
	}

	if buf[0] != byte(SYNC_PULL) {
		return nil, errors.New("error decoding sync pull packet 'invalid packet type'")
	}

	senderPublicKey := DecodeNodePublicKey(buf[1:33])
	senderVersion := DecodeVersion(buf[33:37])
	digest, digestLen, err := DecodeDigest(buf[37:])
	if err != nil {
		return nil, err
	}

	// Reinsert sender in digest
	digest.UpdateNode(senderPublicKey, senderVersion)

	if len(buf) < 37+digestLen+64 {
		return nil, errors.New("error decoding sync pull packet 'buffer too short'")
	}

	signature := buf[37+digestLen : 37+digestLen+64]

	validSignature := ed25519.Verify(senderPublicKey.Key(), buf[0:37+digestLen], signature)
	if !validSignature {
		return nil, errors.New("error decoding sync pull packet 'invalid signature'")
	}

	return &PullPacket{
		senderPublicKey: senderPublicKey,
		senderVersion:   senderVersion,
		digest:          digest,
		signature:       signature,
	}, nil
}
