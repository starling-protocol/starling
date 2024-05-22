package contacts

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/hkdf"
)

var curve ecdh.Curve = ecdh.X25519()

type LinkingSession struct {
	private *ecdh.PrivateKey
}

func StartLinking() (*LinkingSession, error) {
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &LinkingSession{
		private: private,
	}, nil
}

func (l *LinkingSession) GetShare() []byte {
	return l.private.PublicKey().Bytes()
}

func (l *LinkingSession) CreateContact(remoteShare []byte) ([]byte, error) {
	remoteKey, err := curve.NewPublicKey(remoteShare)
	if err != nil {
		return nil, err
	}

	keyMaterial, err := l.private.ECDH(remoteKey)
	if err != nil {
		return nil, err
	}

	secretReader := hkdf.New(sha256.New, keyMaterial, nil, nil)

	sharedSecret := [32]byte{}
	n, err := secretReader.Read(sharedSecret[:])
	if err != nil {
		return nil, err
	}

	if n != 32 {
		return nil, errors.New("failed to read 32 bytes from HKDF reader when linking contact")
	}

	return sharedSecret[:], nil
}
