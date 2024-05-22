package sync

import (
	"encoding/binary"
	"errors"
)

type Version uint32

func (v Version) Encode(buf []byte) []byte {
	return binary.BigEndian.AppendUint32(buf, uint32(v))
}

func DecodeVersion(buf []byte) Version {
	return Version(binary.BigEndian.Uint32(buf))
}

type DigestNodes map[NodePublicKey]Version

type Digest struct {
	Nodes      DigestNodes `json:"nodes"`
	MaxVersion Version     `json:"max_version"`
}

func NewDigest() *Digest {
	return &Digest{
		Nodes:      make(DigestNodes),
		MaxVersion: 0,
	}
}

func (d *Digest) IncrementNode(node NodePublicKey) Version {
	if _, found := d.Nodes[node]; !found {
		d.Nodes[node] = 0
	}

	d.MaxVersion += 1
	d.Nodes[node] = d.MaxVersion
	return d.Nodes[node]
}

func (d *Digest) UpdateNode(node NodePublicKey, version Version) Version {
	if _, found := d.Nodes[node]; !found {
		d.Nodes[node] = 0
	}

	newVersion := max(d.Nodes[node], version)
	d.Nodes[node] = newVersion

	d.MaxVersion = max(newVersion, d.MaxVersion)
	return newVersion
}

func (d *Digest) SubtractNodes(other *Digest) []NodePublicKey {
	result := []NodePublicKey{}
	for node := range d.Nodes {
		if _, found := other.Nodes[node]; !found {
			result = append(result, node)
		}
	}
	return result
}

func (d *Digest) IntersectingNodes(other *Digest) []NodePublicKey {
	result := []NodePublicKey{}
	for node := range d.Nodes {
		if _, found := other.Nodes[node]; found {
			result = append(result, node)
		}
	}
	return result
}

// Decodes the given buffer to a digest, and returns the digest along with an integer representing how many bytes of the buffer was read
func DecodeDigest(buf []byte) (*Digest, int, error) {

	digestNodes := make(DigestNodes)

	if len(buf) < 4 {
		return nil, 0, errors.New("error decoding digest: 'buffer too short'")
	}

	digestCount := int(binary.BigEndian.Uint32(buf))

	if len(buf) < 4+digestCount*36 {
		return nil, 0, errors.New("error decoding digest: 'buffer too short'")
	}

	maxVersion := Version(0)
	for i := 4; i < 4+digestCount*36; i += 36 {
		node := DecodeNodePublicKey(buf[i:])
		version := DecodeVersion(buf[i+32:])
		digestNodes[node] = version
		maxVersion = max(maxVersion, version)
	}

	return &Digest{
		Nodes:      digestNodes,
		MaxVersion: maxVersion,
	}, 4 + digestCount*36, nil
}

func (d *Digest) EncodeWithoutSender(buf []byte, sender NodePublicKey) []byte {
	nodeCount := len(d.Nodes)
	if _, found := d.Nodes[sender]; found {
		nodeCount -= 1
	}

	buf = binary.BigEndian.AppendUint32(buf, uint32(nodeCount))

	for nodeID, version := range d.Nodes {
		if nodeID == sender {
			continue
		}

		buf = nodeID.Encode(buf)
		buf = version.Encode(buf)
	}
	return buf
}
