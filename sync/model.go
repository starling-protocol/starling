package sync

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"sort"

	"github.com/starling-protocol/starling/device"
)

type NodePublicKey [32]byte

func (s NodePublicKey) Encode(buf []byte) []byte {
	return append(buf, s[:]...)
}

func DecodeNodePublicKey(buf []byte) NodePublicKey {
	return NodePublicKey(buf[0:32])
}

func (s NodePublicKey) Key() ed25519.PublicKey {
	return ed25519.PublicKey(s[:])
}

type NodeState map[Version]Message
type ModelNodeStates map[NodePublicKey]NodeState

type Message struct {
	Value          []byte              `json:"value"`
	Signature      Signature           `json:"sig"`
	AttachedSecret device.SharedSecret `json:"attached_secret"`
}

type Signature []byte

func (s Signature) Encode(buf []byte) []byte {
	return append(buf, s...)
}

type Digests map[NodePublicKey]*Digest

type ModelType string

const (
	ModelTypeGroup ModelType = "group"
	ModelTypeLink  ModelType = "link"
)

type Model struct {
	Digests    Digests            `json:"digests"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	PublicKey  NodePublicKey      `json:"public_key"`
	NodeStates ModelNodeStates    `json:"node_states"`
	Type       ModelType          `json:"type"`
}

func NewMessage(value []byte, signature Signature, attachedSecret []byte) Message {
	return Message{
		Value:          value,
		Signature:      signature,
		AttachedSecret: attachedSecret,
	}
}

func NewNodeState() NodeState {
	return NodeState{}
}

func ExtractNodePublicKey(privateKey ed25519.PrivateKey) NodePublicKey {
	var nodePK = NodePublicKey{}
	n := copy(nodePK[:], privateKey.Public().(ed25519.PublicKey))
	if n != 32 {
		panic("failed to extract NodePK")
	}
	return nodePK
}

func NewModel(privateKey ed25519.PrivateKey, modelType ModelType) *Model {
	return &Model{
		Digests:    make(map[NodePublicKey]*Digest),
		PrivateKey: privateKey,
		PublicKey:  ExtractNodePublicKey(privateKey),
		NodeStates: ModelNodeStates{},
		Type:       modelType,
	}
}

func (s *Model) NewMessage(value []byte, attachedSecret device.SharedSecret) Version {
	value = bytes.Clone(value)

	newVersion := s.Digest().IncrementNode(s.PublicKey)

	if _, found := s.NodeStates[s.PublicKey]; !found {
		s.NodeStates[s.PublicKey] = NewNodeState()
	}

	signMsg := []byte{}
	signMsg = s.PublicKey.Encode(signMsg)
	signMsg = newVersion.Encode(signMsg)
	signMsg = binary.BigEndian.AppendUint32(signMsg, uint32(len(value)))
	signMsg = append(signMsg, value...)
	if attachedSecret != nil {
		signMsg = append(signMsg, 0x01)
		signMsg = append(signMsg, attachedSecret...)
	} else {
		signMsg = append(signMsg, 0x00)
	}

	signature := Signature(ed25519.Sign(s.PrivateKey, signMsg))

	s.NodeStates[s.PublicKey][newVersion] = NewMessage(value, signature, attachedSecret)
	return newVersion
}

func (s *Model) Digest() *Digest {
	if _, found := s.Digests[s.PublicKey]; !found {
		s.Digests[s.PublicKey] = NewDigest()
		s.Digests[s.PublicKey].UpdateNode(s.PublicKey, 0)
	}
	return s.Digests[s.PublicKey]
}

func (s *Model) UpdateDigests(node NodePublicKey, digest *Digest) bool {
	digestChange := false
	for nodeB, version := range digest.Nodes {
		if _, nodeFound := s.Digests[node]; nodeFound {
			oldVersion, found := s.Digests[node].Nodes[nodeB]
			if !found || oldVersion != version {
				digestChange = true
			}
		} else {
			digestChange = true
		}

		if digestChange {
			break
		}
	}

	// Update entire digest
	s.Digests[node] = digest

	return digestChange
}

func (s *Model) UpdateDigest(baseNode, nodeToUpdate NodePublicKey, version Version) bool {
	_, digestFound := s.Digests[baseNode]
	if !digestFound {
		s.Digests[baseNode] = NewDigest()
	}

	oldVersion, versionFound := s.Digests[baseNode].Nodes[nodeToUpdate]
	newVersion := s.Digests[baseNode].UpdateNode(nodeToUpdate, version)

	return !versionFound || oldVersion < newVersion
}

func (s *Model) Delta(digest *Digest) Deltas {
	delta := Deltas{}

	for _, node := range digest.IntersectingNodes(s.Digest()) {
		nodeState := s.NodeStates[node]
		for version, msg := range nodeState {
			if digest.Nodes[node] < version {
				delta = append(delta, *NewDelta(node, version, msg.Value, msg.AttachedSecret, msg.Signature))
			}
		}
	}

	for _, node := range s.Digest().SubtractNodes(digest) {
		nodeState := s.NodeStates[node]
		for version, msg := range nodeState {
			delta = append(delta, *NewDelta(node, version, msg.Value, msg.AttachedSecret, msg.Signature))
		}
	}

	sort.Sort(delta)
	return delta
}

func (s *Model) Merge(sender NodePublicKey, deltas Deltas) bool {
	var stateChanged bool = false

	for _, delta := range deltas {
		_, found := s.NodeStates[delta.PublicKey]
		if !found {
			stateChanged = true
			s.NodeStates[delta.PublicKey] = NewNodeState()
		}

		_, versionFound := s.NodeStates[delta.PublicKey][delta.Version]
		if !versionFound || !bytes.Equal(s.NodeStates[delta.PublicKey][delta.Version].Value, delta.Value) {
			stateChanged = true
		}

		s.NodeStates[delta.PublicKey][delta.Version] = NewMessage(delta.Value, delta.Signature, delta.AttachedSecret)

		// Update our, original sender and push sender digests
		s.Digest().UpdateNode(delta.PublicKey, delta.Version)
		s.UpdateDigest(delta.PublicKey, delta.PublicKey, delta.Version)
		s.UpdateDigest(sender, delta.PublicKey, delta.Version)
	}

	return stateChanged
}

func (s *Model) EncodeToJSON() ([]byte, error) {
	return json.Marshal(s)
}

func DecodeModelFromJSON(data []byte) (*Model, error) {
	var model Model
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, err
	}
	return &model, nil
}
