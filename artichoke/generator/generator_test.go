package generator

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateRandomAction(t *testing.T) {
	action := GenerateRandomAction(100)
	assert.Equal(t, 100, len(action))
}

func TestGenerateRandomActions(t *testing.T) {
	actionNb := 20
	actionSize := 100
	actions := GenerateRandomActions(actionNb, actionSize)

	assert := assert.New(t)
	assert.Equal(actionNb, len(actions))

	for i := 0; i < actionNb; i++ {
		assert.Equal(actionSize, len(actions[i]))
	}
}