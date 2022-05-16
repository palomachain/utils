package signing

import (
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	EncodingDelimiter = byte('|')
)

// Signer is an interface that can sign byte slice and return a signature and
// an error back.
type Signer interface {
	Sign([]byte) ([]byte, error)
}

// SignatureVerifier is an interface that can verify a signature given a message.
type SignatureVerifier interface {
	VerifySignature(msg []byte, signature []byte) bool
}

// Serializer takes any object and serializes it in a deterministic way.
// e.g.
// DeterministicSerialize(struct {A string; B int}) == DeterministicSerialize(struct{B int; A string})
// it doesn't care about the order of the fields in a struct.
type Serializer interface {
	DeterministicSerialize(any) ([]byte, error)
}

type SignerFnc func([]byte) ([]byte, error)

func (fnc SignerFnc) Sign(b []byte) ([]byte, error) {
	return fnc(b)
}

// KeyringSigner returns a function that implements the Signer interface, which
// will sign a byte slice given a keyring and a key's uid.
func KeyringSigner(k keyring.Signer, uid string) SignerFnc {
	return SignerFnc(func(b []byte) ([]byte, error) {
		signedBytes, _, err := k.Sign(uid, b)
		return signedBytes, err
	})
}

// KeyringSigner returns a function that implements the Signer interface, which
// will sign a byte slice given a keyring and a key's address..
func KeyringSignerByAddress(k keyring.Signer, address sdk.Address) SignerFnc {
	return SignerFnc(func(b []byte) ([]byte, error) {
		signedBytes, _, err := k.SignByAddress(address, b)
		return signedBytes, err
	})
}

type SerializeFnc func(any) ([]byte, error)

func (fnc SerializeFnc) DeterministicSerialize(msg any) ([]byte, error) {
	return fnc(msg)
}

// JsonDeterministicEncoding takes any object and returns back a json serialized object
// that is deterministic no matter the key ordering.
func JsonDeterministicEncoding(msg any) ([]byte, error) {
	// take anything and create a json byte slice
	js, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var c any
	// then unmarshal this back to Go!
	err = json.Unmarshal(js, &c)
	if err != nil {
		return nil, err
	}
	// and finally, when calling the marshal on the new unmarshaled data
	// it will be sorted!
	js, err = json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return js, nil
}

// SignBytes takes something that can sign a byte slice, a deterministic
// serializer, message and a nonce and returns back a signature, message that
// was used for signing and an error if there was any.
func SignBytes(s Signer, ser Serializer, msg any, nonce []byte, extra ...[]byte) ([]byte, []byte, error) {
	msgBytes, err := buildMessage(ser, msg, nonce, extra...)
	if err != nil {
		return nil, nil, err
	}

	signedBytes, err := s.Sign(msgBytes)

	if err != nil {
		return nil, nil, err
	}

	return signedBytes, signedBytes, nil
}

// VerifySignature verifies the signature that was generated using SignBytes function.
func VerifySignature(v SignatureVerifier, ser Serializer, signature []byte, msg any, nonce []byte, extra ...[]byte) bool {
	msgBytes, err := buildMessage(ser, msg, nonce, extra...)
	if err != nil {
		return false
	}

	return v.VerifySignature(msgBytes, signature)
}

func buildMessage(ser Serializer, msg any, nonce []byte, extra ...[]byte) ([]byte, error) {
	encodedMsg, err := ser.DeterministicSerialize(msg)

	if err != nil {
		return nil, err
	}

	// appending nonce to the end of the message that needs to be signed
	msgBytes := append(encodedMsg, nonce...)
	for _, extraBytes := range extra {
		msgBytes = append(msgBytes, EncodingDelimiter)
		msgBytes = append(msgBytes, extraBytes...)
	}

	return msgBytes, nil
}
