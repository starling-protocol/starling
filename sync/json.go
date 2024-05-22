package sync

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

func unmarshalNodeDict[M ~map[NodePublicKey]T, T any](b []byte, dict *M) error {
	*dict = make(M)
	object := map[string]T{}
	if err := json.Unmarshal(b, &object); err != nil {
		return err
	}

	for key, value := range object {
		publicKeyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return err
		}

		var publicKey NodePublicKey
		if n := copy(publicKey[:], publicKeyBytes); n != 32 {
			return errors.New("invalid public key")
		}

		(*dict)[publicKey] = value
	}

	return nil
}

func marshalNodeDict[M ~map[NodePublicKey]T, T any](dict M) ([]byte, error) {
	result := map[string]T{}

	for publicKey, value := range dict {
		key := base64.StdEncoding.EncodeToString(publicKey[:])
		result[key] = value
	}

	return json.Marshal(result)
}

func (k *NodePublicKey) UnmarshalJSON(b []byte) error {
	var object string
	if err := json.Unmarshal(b, &object); err != nil {
		return err
	}

	n, err := base64.StdEncoding.Decode((*k)[:], []byte(object))
	if n != 32 {
		return errors.New("invalid public key length")
	}

	return err
}

func (n NodePublicKey) MarshalJSON() ([]byte, error) {
	encodedKey := base64.StdEncoding.EncodeToString(n[:])
	return json.Marshal(encodedKey)
}

func (s *ModelNodeStates) UnmarshalJSON(b []byte) error {
	return unmarshalNodeDict(b, s)
}

func (s ModelNodeStates) MarshalJSON() ([]byte, error) {
	return marshalNodeDict(s)
}

func (d *Digests) UnmarshalJSON(b []byte) error {
	return unmarshalNodeDict(b, d)
}

func (d Digests) MarshalJSON() ([]byte, error) {
	return marshalNodeDict(d)
}

func (d *DigestNodes) UnmarshalJSON(b []byte) error {
	return unmarshalNodeDict(b, d)
}

func (d DigestNodes) MarshalJSON() ([]byte, error) {
	return marshalNodeDict(d)
}
