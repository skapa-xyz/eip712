package eip712

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

type TestVector struct {
	Name         string                 `json:"name"`
	Domain       json.RawMessage        `json:"domain"`
	Types        map[string][]Type      `json:"types"`
	PrimaryType  string                 `json:"primaryType"`
	Message      json.RawMessage        `json:"message"`
	ExpectedHash string                 `json:"expectedHash,omitempty"`
	Signature    *SignatureVector       `json:"signature,omitempty"`
	SignerAddress string                `json:"signerAddress,omitempty"`
}

type SignatureVector struct {
	R string `json:"r"`
	S string `json:"s"`
	V uint8  `json:"v"`
}

type TestVectors struct {
	Description string       `json:"description"`
	Vectors     []TestVector `json:"vectors"`
}

func loadTestVectors(t *testing.T) TestVectors {
	data, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	
	var vectors TestVectors
	err = json.Unmarshal(data, &vectors)
	require.NoError(t, err)
	
	return vectors
}

func parseDomain(t *testing.T, raw json.RawMessage) Domain {
	var d struct {
		Name              string `json:"name"`
		Version           string `json:"version"`
		ChainID           *int64 `json:"chainId"`
		VerifyingContract string `json:"verifyingContract"`
		Salt              string `json:"salt"`
	}
	
	err := json.Unmarshal(raw, &d)
	require.NoError(t, err)
	
	domain := Domain{
		Name:    d.Name,
		Version: d.Version,
	}
	
	if d.ChainID != nil {
		domain.ChainID = big.NewInt(*d.ChainID)
	}
	
	if d.VerifyingContract != "" {
		domain.VerifyingContract = common.HexToAddress(d.VerifyingContract)
	}
	
	if d.Salt != "" {
		saltBytes, err := hex.DecodeString(strings.TrimPrefix(d.Salt, "0x"))
		require.NoError(t, err)
		copy(domain.Salt[:], saltBytes)
	}
	
	return domain
}

func parseMessage(raw json.RawMessage) Message {
	var msg map[string]interface{}
	json.Unmarshal(raw, &msg)
	return Message(msg)
}

func TestCompatibilityWithKnownVectors(t *testing.T) {
	vectors := loadTestVectors(t)
	
	// Use a known test private key for signing
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			domain := parseDomain(t, vector.Domain)
			message := parseMessage(vector.Message)
			
			// Test signing
			sig, err := signer.SignTypedData(domain, vector.Types, vector.PrimaryType, message)
			require.NoError(t, err)
			require.NotNil(t, sig)
			
			// If we have an expected hash, verify it matches
			if vector.ExpectedHash != "" {
				require.Equal(t, vector.ExpectedHash, sig.Hash)
			}
			
			// Test signature recovery
			recovered, err := sig.Recover(domain, vector.Types, vector.PrimaryType, message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
			
			// If we have a known signature from another implementation, test recovery
			if vector.Signature != nil && vector.SignerAddress != "" {
				knownSig := &Signature{
					R: vector.Signature.R,
					S: vector.Signature.S,
					V: vector.Signature.V,
				}
				
				// Reconstruct full signature bytes
				rBytes, _ := hex.DecodeString(strings.TrimPrefix(vector.Signature.R, "0x"))
				sBytes, _ := hex.DecodeString(strings.TrimPrefix(vector.Signature.S, "0x"))
				sigBytes := make([]byte, 65)
				copy(sigBytes[:32], rBytes)
				copy(sigBytes[32:64], sBytes)
				sigBytes[64] = vector.Signature.V
				knownSig.Bytes = "0x" + hex.EncodeToString(sigBytes)
				
				recovered, err := knownSig.Recover(domain, vector.Types, vector.PrimaryType, message)
				require.NoError(t, err)
				require.Equal(t, common.HexToAddress(vector.SignerAddress), recovered)
			}
		})
	}
}

// Test against the official EIP-712 example
func TestOfficialEIP712Example(t *testing.T) {
	// This is the exact example from the EIP-712 specification
	domain := Domain{
		Name:              "Ether Mail",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: common.HexToAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
	}
	
	types := map[string][]Type{
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
	
	message := Message{
		"from": map[string]interface{}{
			"name":   "Cow",
			"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
		},
		"to": map[string]interface{}{
			"name":   "Bob",
			"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
		},
		"contents": "Hello, Bob!",
	}
	
	// Create a signer
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	// Sign the message
	sig, err := signer.SignTypedData(domain, types, "Mail", message)
	require.NoError(t, err)
	
	// The hash should be deterministic
	expectedHashPrefix := "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
	require.Equal(t, expectedHashPrefix, sig.Hash)
	
	// Verify we can recover the signer
	recovered, err := sig.Recover(domain, types, "Mail", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

// Test compatibility with ethers.js/viem permit example
func TestPermitCompatibility(t *testing.T) {
	// Standard EIP-2612 permit
	domain := Domain{
		Name:              "USD Coin",
		Version:           "2",
		ChainID:           big.NewInt(1),
		VerifyingContract: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
	}
	
	types := createPermitTypes()
	
	owner := common.HexToAddress(testAddress1)
	spender := common.HexToAddress(testAddress2)
	value := new(big.Int).SetUint64(1e18) // 1 token
	nonce := big.NewInt(0)
	deadline := new(big.Int).SetUint64(1893456000) // Far future
	
	message := createPermitMessage(
		owner.Hex(),
		spender.Hex(),
		value,
		nonce,
		deadline,
	)
	
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	sig, err := signer.SignTypedData(domain, types, "Permit", message)
	require.NoError(t, err)
	require.NotNil(t, sig)
	
	// Verify signature
	recovered, err := sig.Recover(domain, types, "Permit", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

// Test that our implementation produces consistent results
func TestDeterministicSignatures(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Test App", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "text", Type: "string"}},
	}
	message := Message{"text": "Hello, world!"}
	
	// Sign the same message multiple times
	signatures := make([]*Signature, 5)
	for i := 0; i < 5; i++ {
		sig, err := signer.SignTypedData(domain, types, "Message", message)
		require.NoError(t, err)
		signatures[i] = sig
	}
	
	// All signatures should be identical
	for i := 1; i < len(signatures); i++ {
		compareSignatures(t, signatures[0], signatures[i])
	}
}

// Test cross-chain compatibility
func TestCrossChainCompatibility(t *testing.T) {
	testCases := []struct {
		name    string
		chainID int64
	}{
		{"Ethereum Mainnet", 1},
		{"Polygon", 137},
		{"Arbitrum", 42161},
		{"Optimism", 10},
		{"BSC", 56},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewSigner(testPrivateKey1, tc.chainID)
			require.NoError(t, err)
			
			domain := Domain{
				Name:    "Cross Chain App",
				Version: "1",
				ChainID: big.NewInt(tc.chainID),
			}
			
			types := map[string][]Type{
				"Message": {{Name: "content", Type: "string"}},
			}
			
			message := Message{"content": "Cross-chain message"}
			
			sig, err := signer.SignTypedData(domain, types, "Message", message)
			require.NoError(t, err)
			
			// Verify the signature includes the chain ID
			recovered, err := sig.Recover(domain, types, "Message", message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
			
			// Changing chain ID should produce different signature
			wrongDomain := domain
			wrongDomain.ChainID = big.NewInt(999)
			
			recovered2, err := sig.Recover(wrongDomain, types, "Message", message)
			require.NoError(t, err)
			require.NotEqual(t, signer.Address(), recovered2)
		})
	}
}

// Test array type compatibility
func TestArrayTypeCompatibility(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Array Test", "1", 1)
	
	// Test with string array
	types := map[string][]Type{
		"Message": {
			{Name: "items", Type: "string[]"},
		},
	}
	
	message := Message{
		"items": []string{"apple", "banana", "cherry"},
	}
	
	sig, err := signer.SignTypedData(domain, types, "Message", message)
	require.NoError(t, err)
	assertSignatureComponents(t, sig)
	
	// Test with uint256 array
	types2 := map[string][]Type{
		"Numbers": {
			{Name: "values", Type: "uint256[]"},
		},
	}
	
	message2 := Message{
		"values": []string{"100", "200", "300"},
	}
	
	sig2, err := signer.SignTypedData(domain, types2, "Numbers", message2)
	require.NoError(t, err)
	assertSignatureComponents(t, sig2)
	
	// Test with address array
	types3 := map[string][]Type{
		"Addresses": {
			{Name: "addresses", Type: "address[]"},
		},
	}
	
	message3 := Message{
		"addresses": []string{testAddress1, testAddress2},
	}
	
	sig3, err := signer.SignTypedData(domain, types3, "Addresses", message3)
	require.NoError(t, err)
	assertSignatureComponents(t, sig3)
}

// Test bytes type compatibility
func TestBytesTypeCompatibility(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Bytes Test", "1", 1)
	
	testCases := []struct {
		name      string
		types     map[string][]Type
		message   Message
	}{
		{
			name: "bytes32",
			types: map[string][]Type{
				"Message": {{Name: "data", Type: "bytes32"}},
			},
			message: Message{
				"data": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		},
		{
			name: "bytes",
			types: map[string][]Type{
				"Message": {{Name: "data", Type: "bytes"}},
			},
			message: Message{
				"data": "0x48656c6c6f20776f726c64", // "Hello world"
			},
		},
		{
			name: "multiple fixed bytes",
			types: map[string][]Type{
				"Message": {
					{Name: "byte1", Type: "bytes1"},
					{Name: "byte4", Type: "bytes4"},
					{Name: "byte8", Type: "bytes8"},
				},
			},
			message: Message{
				"byte1": "0x01",
				"byte4": "0x01020304",
				"byte8": "0x0102030405060708",
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := signer.SignTypedData(domain, tc.types, "Message", tc.message)
			require.NoError(t, err)
			assertSignatureComponents(t, sig)
			
			recovered, err := sig.Recover(domain, tc.types, "Message", tc.message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
		})
	}
}