package config

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestGetContracts(t *testing.T) {
	var (
		bnbChain = &Contracts{
			Exchange:         common.HexToAddress("0xF0aebf65490374a477100351291c736c73c11D9F"),
			FeeModule:        common.HexToAddress("0xC9063Dc52dEEfb518E5b6634A6b8D624bc5d7c36"),
			NegRiskExchange:  common.HexToAddress(""),
			NegRiskFeeModule: common.HexToAddress(""),
			NegRiskAdapter:   common.HexToAddress(""),
			Collateral:       common.HexToAddress(""),
			Conditional:      common.HexToAddress("0xAD1a38cEc043e70E83a3eC30443dB285ED10D774"),
		}
	)

	c, err := GetContracts(56)
	assert.NotNil(t, c)
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(c.Exchange[:], bnbChain.Exchange[:]))
	assert.True(t, bytes.Equal(c.FeeModule[:], bnbChain.FeeModule[:]))
	assert.True(t, bytes.Equal(c.Conditional[:], bnbChain.Conditional[:]))

	c, err = GetContracts(100000)
	assert.Nil(t, c)
	assert.NotNil(t, err)
}
