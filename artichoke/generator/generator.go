package generator

import (
	"crypto/rand"
)

func GenerateRandomAction(size int) []byte {
	if size < 0 {
		panic("cannot generate action with negative size")
	}

	action := make([]byte, size)
	rand.Read(action)
	return action
}

func GenerateRandomActions(actionNb int, actionSize int) [][]byte {
	actions := make([][]byte, actionNb)
	for i := 0; i < actionNb; i++ {
		actions[i] = GenerateRandomAction(actionSize)
	}
	return actions
}