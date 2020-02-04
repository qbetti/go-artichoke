package pas

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/ethereum/go-ethereum/crypto"
	"strings"
)

const (
	NonceSize      = 12
	fieldSeparator = "|"
	fieldNb        = 4
)

type PeerAction struct {
	encryptedAction []byte
	pubKey          []byte
	groupId         string
	digest          []byte
}

func Encrypt(action []byte, groupKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(groupKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encryptedAction := aesgcm.Seal(nil, nonce, action, nil)
	actionCipher := append(nonce, encryptedAction...)
	return actionCipher, nil
}

func Decrypt(actionCipher []byte, groupKey []byte) ([]byte, error) {
	nonce := actionCipher[:NonceSize]
	encryptedAction := actionCipher[NonceSize:]

	block, err := aes.NewCipher(groupKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	action, err := aesgcm.Open(nil, nonce, encryptedAction, nil)
	if err != nil {
		return nil, err
	}

	return action, nil
}

func FromLine(line string) (*PeerAction, error) {
	fields := strings.Split(line, fieldSeparator)
	if len(fields) != fieldNb {
		return nil, errors.New("wrong number of fields for PeerAction")
	}

	encryptedAction, err := base64.StdEncoding.DecodeString(fields[0])
	if err != nil {
		return nil, errors.New("encrypted action format is not base64")
	}

	pubKey, err := hex.DecodeString(fields[1])
	if err != nil {
		return nil, errors.New("public key format is not hexadecimal")
	}

	groupId := fields[2]
	if len(groupId) == 0 {
		return nil, errors.New("group id is empty")
	}

	digest, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil {
		return nil, errors.New("digest format is not base64")
	}

	peerAction := new(PeerAction)
	peerAction.encryptedAction = encryptedAction
	peerAction.pubKey = pubKey
	peerAction.groupId = groupId
	peerAction.digest = digest
	return peerAction, nil
}

func (pa PeerAction) Decrypt(groupKey []byte) ([]byte, error) {
	if pa.encryptedAction == nil {
		return nil, errors.New("nothing to decrypt")
	}
	return Decrypt(pa.encryptedAction, groupKey)
}

func (pa PeerAction) String() string {
	var s string
	s += base64.StdEncoding.EncodeToString(pa.encryptedAction) + fieldSeparator
	s += hex.EncodeToString(pa.pubKey) + fieldSeparator
	s += pa.groupId + fieldSeparator
	s += base64.StdEncoding.EncodeToString(pa.digest)
	return s
}

// Check whether or not the digest of the peer-action corresponds to the peer-action AND
// to the previous peer-action
func (pa *PeerAction) VerifyDigest(previousPa *PeerAction) bool {
	previousDigest := getPreviousDigest(previousPa)
	hash := pa.computePeerActionHash(previousDigest)
	// In go-ethereum, a final byte is added to the signature to extract the pub key from it.
	// It is not directly part of the signature, so we constrain the digest to its 64 first bytes.
	return crypto.VerifySignature(pa.pubKey, hash, pa.digest[:64])
}

// Creates a new peer-action with provided info. Uses the previous peer-action and the private key to
// build and sign the digest of the created peer-action
func NewPeerAction(encryptedAction []byte, groupId string, previousPa *PeerAction, privKey *ecdsa.PrivateKey) (*PeerAction, error) {
	pa := new(PeerAction)
	pa.encryptedAction = encryptedAction
	pa.pubKey = crypto.CompressPubkey(&privKey.PublicKey)
	pa.groupId = groupId

	hash := pa.computePeerActionHash(getPreviousDigest(previousPa))
	digest, err := crypto.Sign(hash, privKey)
	if err != nil {
		return nil, err
	}

	pa.digest = digest
	return pa, nil
}

// Computes the hash of the peer-action. This hash must be signed to become a digest.
func (pa *PeerAction) computePeerActionHash(previousDigest []byte) []byte {
	data := append(pa.encryptedAction, pa.pubKey...)
	data = append(data, []byte(pa.groupId)...)
	data = append(data, previousDigest...)

	return crypto.Keccak256(data)
}

// Returns the digest of the previous peer-action, empty byte array if nil
func getPreviousDigest(previousPa *PeerAction) []byte {
	if previousPa == nil {
		return make([]byte, 0)
	} else {
		return previousPa.digest
	}
}
