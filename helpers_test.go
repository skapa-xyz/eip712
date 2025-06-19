package eip712

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

// Test constants
const (
	testPrivateKey1 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	testPrivateKey2 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	testAddress1    = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	testAddress2    = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
)

// Helper functions for testing

func assertSignatureComponents(t *testing.T, sig *Signature) {
	t.Helper()
	
	// Check R component
	require.NotEmpty(t, sig.R)
	rBytes, err := hexutil.Decode(sig.R)
	require.NoError(t, err)
	require.Len(t, rBytes, 32)
	
	// Check S component
	require.NotEmpty(t, sig.S)
	sBytes, err := hexutil.Decode(sig.S)
	require.NoError(t, err)
	require.Len(t, sBytes, 32)
	
	// Check V component
	require.True(t, sig.V == 27 || sig.V == 28, "V should be 27 or 28")
	
	// Check hash
	require.NotEmpty(t, sig.Hash)
	hashBytes, err := hexutil.Decode(sig.Hash)
	require.NoError(t, err)
	require.Len(t, hashBytes, 32)
	
	// Check full signature
	require.NotEmpty(t, sig.Bytes)
	sigBytes, err := hexutil.Decode(sig.Bytes)
	require.NoError(t, err)
	require.Len(t, sigBytes, 65)
}

func compareSignatures(t *testing.T, sig1, sig2 *Signature) {
	t.Helper()
	require.Equal(t, sig1.R, sig2.R)
	require.Equal(t, sig1.S, sig2.S)
	require.Equal(t, sig1.V, sig2.V)
	require.Equal(t, sig1.Hash, sig2.Hash)
	require.Equal(t, sig1.Bytes, sig2.Bytes)
}

func createTestDomain(name, version string, chainID int64) Domain {
	return Domain{
		Name:    name,
		Version: version,
		ChainID: big.NewInt(chainID),
	}
}

func createTestDomainWithContract(name, version string, chainID int64, contract string) Domain {
	return Domain{
		Name:              name,
		Version:           version,
		ChainID:           big.NewInt(chainID),
		VerifyingContract: common.HexToAddress(contract),
	}
}

func createTestDomainWithSalt(name, version string, chainID int64, salt string) Domain {
	var saltBytes [32]byte
	saltData, _ := hex.DecodeString(salt)
	copy(saltBytes[:], saltData)
	
	return Domain{
		Name:    name,
		Version: version,
		ChainID: big.NewInt(chainID),
		Salt:    saltBytes,
	}
}

func createMailTypes() map[string][]Type {
	return map[string][]Type{
		"Person": {
			{Name: "name", Type: "string"},
			{Name: "wallet", Type: "address"},
		},
		"Mail": {
			{Name: "from", Type: "Person"},
			{Name: "to", Type: "Person"},
			{Name: "contents", Type: "string"},
		},
	}
}

func createMailMessage(fromName, fromWallet, toName, toWallet, contents string) Message {
	return Message{
		"from": map[string]interface{}{
			"name":   fromName,
			"wallet": fromWallet,
		},
		"to": map[string]interface{}{
			"name":   toName,
			"wallet": toWallet,
		},
		"contents": contents,
	}
}

func createPermitTypes() map[string][]Type {
	return map[string][]Type{
		"Permit": {
			{Name: "owner", Type: "address"},
			{Name: "spender", Type: "address"},
			{Name: "value", Type: "uint256"},
			{Name: "nonce", Type: "uint256"},
			{Name: "deadline", Type: "uint256"},
		},
	}
}

func createPermitMessage(owner, spender string, value, nonce, deadline *big.Int) Message {
	return Message{
		"owner":    owner,
		"spender":  spender,
		"value":    value.String(),
		"nonce":    nonce.String(),
		"deadline": deadline.String(),
	}
}

// Test table structures

type signerTestCase struct {
	name      string
	key       string
	chainID   int64
	wantAddr  string
	wantError bool
}

type signTestCase struct {
	name        string
	domain      Domain
	types       map[string][]Type
	primaryType string
	message     Message
	wantError   bool
}

type recoveryTestCase struct {
	name        string
	signature   *Signature
	domain      Domain
	types       map[string][]Type
	primaryType string
	message     Message
	wantAddr    string
	wantError   bool
}