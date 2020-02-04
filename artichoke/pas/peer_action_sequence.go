package pas

import (
	"bufio"
	"crypto/ecdsa"
	"fmt"
	"os"
)

type PeerActionSequence struct {
	filePath    string
	peerActions []*PeerAction
}

type InvalidDigestError struct {
	index      int
	peerAction *PeerAction
}

func (e *InvalidDigestError) Error() string {
	return fmt.Sprintf("digest invalid for peer-action with index %v: %s", e.index, e.peerAction)
}

func NewPeerActionSequence() *PeerActionSequence {
	pas := new(PeerActionSequence)
	return pas
}

func (pas *PeerActionSequence) SaveToFile(filePath string) error {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, peerAction := range pas.peerActions {
		_, err := f.WriteString(peerAction.String() + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func LoadFromFile(filePath string) (*PeerActionSequence, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	pas := NewPeerActionSequence()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pa, err := FromLine(scanner.Text())
		if err != nil {
			return nil, err
		}
		pas.AddPeerAction(pa)
	}
	return pas, nil
}

//func (pas *PeerActionSequence) SaveToFile(filePath string) error {
//	f, err := os.Open(filePath)
//	if err != nil {
//		return err
//	}
//	defer f.Close()
//
//	w := bufio.NewWriter(f)
//	for _, pa := range pas.peerActions {
//		_, err := w.WriteString(pa.String())
//		if err != nil {
//			return err
//		}
//		w.Flush()
//	}
//
//	return nil
//}

func (pas *PeerActionSequence) AddPeerAction(peerAction *PeerAction) {
	if peerAction != nil {
		pas.peerActions = append(pas.peerActions, peerAction)
	}
}

func (pas PeerActionSequence) String() string {
	var s string
	for _, peerAction := range pas.peerActions {
		s += peerAction.String()
		s += "\n"
	}
	return s
}

func (pas *PeerActionSequence) Verify() (bool, []InvalidDigestError) {
	var errors []InvalidDigestError
	result := true

	var previousPA *PeerAction
	previousPA = nil

	for i, peerAction := range pas.peerActions {
		if !peerAction.VerifyDigest(previousPA) {
			result = false
			errors = append(errors, InvalidDigestError{i, peerAction})
		}
		previousPA = peerAction
	}

	return result, errors
}

func (pas *PeerActionSequence) Append(action []byte, peerPrivKey *ecdsa.PrivateKey, groupId string, groupKey []byte) error {
	actionCipher, err := Encrypt(action, groupKey)
	if err != nil {
		return err
	}

	return pas.AppendWithoutEncryption(actionCipher, peerPrivKey, groupId)
}

func (pas *PeerActionSequence) AppendWithoutEncryption(data []byte, peerPrivKey *ecdsa.PrivateKey, groupId string) error {
	peerAction, err := NewPeerAction(data, groupId, pas.LastPeerAction(), peerPrivKey)
	if err != nil {
		return err
	}
	pas.AddPeerAction(peerAction)
	return nil
}

func (pas *PeerActionSequence) LastPeerAction() *PeerAction {
	pasLength := len(pas.peerActions)
	if pasLength < 1 {
		return nil
	} else {
		return pas.peerActions[pasLength-1]
	}
}

func (pas *PeerActionSequence) GetPeerAction(index int) *PeerAction {
	if index < 0 || index >= len(pas.peerActions) {
		return nil
	} else {
		return pas.peerActions[index]
	}
}

func (pas *PeerActionSequence) GetSize() int {
	return len(pas.peerActions)
}
