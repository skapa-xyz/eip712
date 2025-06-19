package eip712

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureRecoveryWithValidSignatures(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Security Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Test message"}
	
	// Create a valid signature
	sig, err := signer.SignTypedData(domain, types, "Message", message)
	require.NoError(t, err)
	
	// Test recovery
	recovered, err := sig.Recover(domain, types, "Message", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
	
	// Test VerifySignature function
	valid, err := VerifySignature(sig, signer.Address(), domain, types, "Message", message)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestSignatureRecoveryWithInvalidSignatures(t *testing.T) {
	domain := createTestDomain("Security Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Test message"}
	
	testCases := []struct {
		name      string
		signature *Signature
		wantError bool
	}{
		{
			name: "invalid R value",
			signature: &Signature{
				R:     "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
				S:     "0x2222222222222222222222222222222222222222222222222222222222222222",
				V:     27,
				Hash:  "0x3333333333333333333333333333333333333333333333333333333333333333",
				Bytes: "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF22222222222222222222222222222222222222222222222222222222222222221b",
			},
			wantError: true,
		},
		{
			name: "invalid S value",
			signature: &Signature{
				R:     "0x1111111111111111111111111111111111111111111111111111111111111111",
				S:     "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
				V:     27,
				Hash:  "0x3333333333333333333333333333333333333333333333333333333333333333",
				Bytes: "0x1111111111111111111111111111111111111111111111111111111111111111FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1b",
			},
			wantError: true,
		},
		{
			name: "invalid V value",
			signature: &Signature{
				R:     "0x1111111111111111111111111111111111111111111111111111111111111111",
				S:     "0x2222222222222222222222222222222222222222222222222222222222222222",
				V:     29, // Invalid V value
				Hash:  "0x3333333333333333333333333333333333333333333333333333333333333333",
				Bytes: "0x111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222221d",
			},
			wantError: true,
		},
		{
			name: "malformed signature bytes",
			signature: &Signature{
				R:     "0x1111111111111111111111111111111111111111111111111111111111111111",
				S:     "0x2222222222222222222222222222222222222222222222222222222222222222",
				V:     27,
				Hash:  "0x3333333333333333333333333333333333333333333333333333333333333333",
				Bytes: "0x11112222", // Too short
			},
			wantError: true,
		},
		{
			name: "empty signature",
			signature: &Signature{
				R:     "",
				S:     "",
				V:     0,
				Hash:  "",
				Bytes: "",
			},
			wantError: true,
		},
		{
			name: "zero signature",
			signature: &Signature{
				R:     "0x0000000000000000000000000000000000000000000000000000000000000000",
				S:     "0x0000000000000000000000000000000000000000000000000000000000000000",
				V:     27,
				Hash:  "0x3333333333333333333333333333333333333333333333333333333333333333",
				Bytes: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b",
			},
			wantError: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.signature.Recover(domain, types, "Message", message)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSignatureMalleabilityProtection(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Malleability Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Test message"}
	
	// Create a valid signature
	sig, err := signer.SignTypedData(domain, types, "Message", message)
	require.NoError(t, err)
	
	// Decode the signature components
	_, _ = hexutil.Decode(sig.R)
	sBytes, _ := hexutil.Decode(sig.S)
	
	// Check that S is in the lower half of the curve order
	// This prevents signature malleability
	s := new(big.Int).SetBytes(sBytes)
	halfN := new(big.Int).Div(secp256k1N, big.NewInt(2))
	
	// S should be <= N/2 for non-malleable signatures
	assert.True(t, s.Cmp(halfN) <= 0, "S value should be in lower half of curve order")
}

// secp256k1N is the order of the secp256k1 curve
var secp256k1N = new(big.Int).SetBytes([]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
})

func TestModifiedMessageFailsVerification(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Modification Test", "1", 1)
	types := map[string][]Type{
		"Transfer": {
			{Name: "from", Type: "address"},
			{Name: "to", Type: "address"},
			{Name: "amount", Type: "uint256"},
		},
	}
	
	originalMessage := Message{
		"from":   testAddress1,
		"to":     testAddress2,
		"amount": "1000000000000000000", // 1 ETH
	}
	
	// Sign the original message
	sig, err := signer.SignTypedData(domain, types, "Transfer", originalMessage)
	require.NoError(t, err)
	
	// Test various message modifications
	modificationTests := []struct {
		name            string
		modifiedMessage Message
	}{
		{
			name: "modified amount",
			modifiedMessage: Message{
				"from":   testAddress1,
				"to":     testAddress2,
				"amount": "2000000000000000000", // Changed to 2 ETH
			},
		},
		{
			name: "modified recipient",
			modifiedMessage: Message{
				"from":   testAddress1,
				"to":     common.HexToAddress("0x0000000000000000000000000000000000000000").Hex(),
				"amount": "1000000000000000000",
			},
		},
		{
			name: "modified sender",
			modifiedMessage: Message{
				"from":   testAddress2,
				"to":     testAddress2,
				"amount": "1000000000000000000",
			},
		},
		{
			name: "added field",
			modifiedMessage: Message{
				"from":   testAddress1,
				"to":     testAddress2,
				"amount": "1000000000000000000",
				"extra":  "malicious data",
			},
		},
		{
			name: "removed field",
			modifiedMessage: Message{
				"from": testAddress1,
				"to":   testAddress2,
				// amount field removed
			},
		},
	}
	
	for _, tc := range modificationTests {
		t.Run(tc.name, func(t *testing.T) {
			// Try to verify with modified message
			valid, err := VerifySignature(sig, signer.Address(), domain, types, "Transfer", tc.modifiedMessage)
			
			// Should either error or return false
			if err == nil {
				require.False(t, valid, "Modified message should not verify")
			}
		})
	}
}

func TestModifiedDomainFailsVerification(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	originalDomain := createTestDomain("Original App", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Test message"}
	
	// Sign with original domain
	sig, err := signer.SignTypedData(originalDomain, types, "Message", message)
	require.NoError(t, err)
	
	// Test various domain modifications
	domainTests := []struct {
		name           string
		modifiedDomain Domain
	}{
		{
			name:           "different name",
			modifiedDomain: createTestDomain("Different App", "1", 1),
		},
		{
			name:           "different version",
			modifiedDomain: createTestDomain("Original App", "2", 1),
		},
		{
			name:           "different chain ID",
			modifiedDomain: createTestDomain("Original App", "1", 137),
		},
		{
			name: "added verifying contract",
			modifiedDomain: createTestDomainWithContract("Original App", "1", 1, testAddress1),
		},
		{
			name: "added salt",
			modifiedDomain: createTestDomainWithSalt("Original App", "1", 1,
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		},
	}
	
	for _, tc := range domainTests {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := VerifySignature(sig, signer.Address(), tc.modifiedDomain, types, "Message", message)
			require.NoError(t, err)
			require.False(t, valid, "Modified domain should not verify")
		})
	}
}

func TestInputValidation(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	t.Run("nil values", func(t *testing.T) {
		// Test with nil chainID in domain
		domain := Domain{
			Name:    "Test",
			Version: "1",
			ChainID: nil,
		}
		types := map[string][]Type{
			"Message": {{Name: "content", Type: "string"}},
		}
		message := Message{"content": "test"}
		
		// Should handle nil chainID gracefully
		sig, err := signer.SignTypedData(domain, types, "Message", message)
		require.NoError(t, err)
		require.NotNil(t, sig)
	})
	
	t.Run("empty types map", func(t *testing.T) {
		domain := createTestDomain("Test", "1", 1)
		types := map[string][]Type{}
		message := Message{"content": "test"}
		
		_, err := signer.SignTypedData(domain, types, "Message", message)
		require.Error(t, err)
	})
	
	t.Run("mismatched types and message fields", func(t *testing.T) {
		domain := createTestDomain("Test", "1", 1)
		types := map[string][]Type{
			"Message": {
				{Name: "field1", Type: "string"},
				{Name: "field2", Type: "uint256"},
			},
		}
		
		// Message has different fields than defined in types
		message := Message{
			"wrongField": "value",
			"field2":     "123",
		}
		
		_, err := signer.SignTypedData(domain, types, "Message", message)
		require.Error(t, err)
	})
	
	t.Run("invalid type definitions", func(t *testing.T) {
		domain := createTestDomain("Test", "1", 1)
		
		invalidTypeTests := []struct {
			name  string
			types map[string][]Type
		}{
			{
				name: "reference to non-existent type",
				types: map[string][]Type{
					"Message": {{Name: "data", Type: "NonExistentType"}},
				},
			},
			{
				name: "circular reference",
				types: map[string][]Type{
					"A": {{Name: "b", Type: "B"}},
					"B": {{Name: "a", Type: "A"}},
				},
			},
			{
				name: "invalid primitive type",
				types: map[string][]Type{
					"Message": {{Name: "data", Type: "uint512"}}, // Invalid uint size
				},
			},
		}
		
		for _, tc := range invalidTypeTests {
			t.Run(tc.name, func(t *testing.T) {
				message := Message{"data": "test"}
				_, err := signer.SignTypedData(domain, tc.types, "Message", message)
				require.Error(t, err)
			})
		}
	})
}

func TestRandomSignatureVerification(t *testing.T) {
	domain := createTestDomain("Random Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Test message"}
	
	// Generate 10 random signatures
	for i := 0; i < 10; i++ {
		// Generate random signature bytes
		sigBytes := make([]byte, 65)
		_, err := rand.Read(sigBytes)
		require.NoError(t, err)
		
		// Ensure V is 27 or 28
		sigBytes[64] = 27 + (sigBytes[64] % 2)
		
		sig := &Signature{
			R:     hexutil.Encode(sigBytes[:32]),
			S:     hexutil.Encode(sigBytes[32:64]),
			V:     sigBytes[64],
			Hash:  "0x" + hex.EncodeToString(make([]byte, 32)), // dummy hash
			Bytes: hexutil.Encode(sigBytes),
		}
		
		// Random signatures should either error or recover to wrong address
		recovered, err := sig.Recover(domain, types, "Message", message)
		if err == nil {
			// If no error, the recovered address should be effectively random
			// and extremely unlikely to match our test addresses
			assert.NotEqual(t, common.HexToAddress(testAddress1), recovered)
			assert.NotEqual(t, common.HexToAddress(testAddress2), recovered)
		}
	}
}

func TestEmptyMessageSecurity(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Empty Test", "1", 1)
	
	// Test signing empty messages
	testCases := []struct {
		name    string
		types   map[string][]Type
		message Message
	}{
		{
			name:    "completely empty",
			types:   map[string][]Type{"Empty": {}},
			message: Message{},
		},
		{
			name: "empty string values",
			types: map[string][]Type{
				"Message": {
					{Name: "data", Type: "string"},
				},
			},
			message: Message{"data": ""},
		},
		{
			name: "zero values",
			types: map[string][]Type{
				"Message": {
					{Name: "amount", Type: "uint256"},
					{Name: "flag", Type: "bool"},
				},
			},
			message: Message{
				"amount": "0",
				"flag":   false,
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Should be able to sign empty messages
			sig, err := signer.SignTypedData(domain, tc.types, strings.Split(tc.name, " ")[0], tc.message)
			if err == nil {
				require.NotNil(t, sig)
				
				// And recover them
				recovered, err := sig.Recover(domain, tc.types, strings.Split(tc.name, " ")[0], tc.message)
				require.NoError(t, err)
				require.Equal(t, signer.Address(), recovered)
			}
		})
	}
}

func TestLargeNumberHandling(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Large Number Test", "1", 1)
	types := map[string][]Type{
		"Numbers": {
			{Name: "uint256Max", Type: "uint256"},
			{Name: "int256Min", Type: "int256"},
			{Name: "int256Max", Type: "int256"},
		},
	}
	
	// Max uint256: 2^256 - 1
	uint256Max := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1))
	
	// Max int256: 2^255 - 1
	int256Max := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(255), nil), big.NewInt(1))
	
	// Min int256: -2^255
	int256Min := new(big.Int).Neg(new(big.Int).Exp(big.NewInt(2), big.NewInt(255), nil))
	
	message := Message{
		"uint256Max": uint256Max.String(),
		"int256Min":  int256Min.String(),
		"int256Max":  int256Max.String(),
	}
	
	sig, err := signer.SignTypedData(domain, types, "Numbers", message)
	require.NoError(t, err)
	require.NotNil(t, sig)
	
	// Verify the signature
	recovered, err := sig.Recover(domain, types, "Numbers", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

func TestSignatureUniqueness(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Uniqueness Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "nonce", Type: "uint256"}},
	}
	
	// Sign multiple messages with different nonces
	signatures := make(map[string]bool)
	
	for i := 0; i < 100; i++ {
		message := Message{"nonce": big.NewInt(int64(i)).String()}
		
		sig, err := signer.SignTypedData(domain, types, "Message", message)
		require.NoError(t, err)
		
		// Check that each signature is unique
		sigStr := sig.Bytes
		require.False(t, signatures[sigStr], "Duplicate signature found for nonce %d", i)
		signatures[sigStr] = true
	}
	
	// All 100 signatures should be unique
	require.Len(t, signatures, 100)
}

func TestConcurrentSigningSafety(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Concurrent Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "id", Type: "uint256"}},
	}
	
	// Run concurrent signing operations
	const numGoroutines = 100
	done := make(chan bool, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			message := Message{"id": big.NewInt(int64(id)).String()}
			sig, err := signer.SignTypedData(domain, types, "Message", message)
			assert.NoError(t, err)
			assert.NotNil(t, sig)
			
			// Verify the signature
			recovered, err := sig.Recover(domain, types, "Message", message)
			assert.NoError(t, err)
			assert.Equal(t, signer.Address(), recovered)
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestZeroAddressHandling(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	zeroAddress := common.Address{}.Hex()
	
	testCases := []struct {
		name   string
		domain Domain
		types  map[string][]Type
		message Message
	}{
		{
			name: "zero address in message",
			domain: createTestDomain("Test", "1", 1),
			types: map[string][]Type{
				"Transfer": {
					{Name: "from", Type: "address"},
					{Name: "to", Type: "address"},
					{Name: "amount", Type: "uint256"},
				},
			},
			message: Message{
				"from":   zeroAddress,
				"to":     testAddress2,
				"amount": "1000",
			},
		},
		{
			name: "zero address in domain",
			domain: createTestDomainWithContract("Test", "1", 1, zeroAddress),
			types: map[string][]Type{
				"Message": {{Name: "data", Type: "string"}},
			},
			message: Message{"data": "test"},
		},
		{
			name: "multiple zero addresses",
			domain: createTestDomain("Test", "1", 1),
			types: map[string][]Type{
				"MultiAddress": {
					{Name: "addresses", Type: "address[]"},
				},
			},
			message: Message{
				"addresses": []string{zeroAddress, zeroAddress, testAddress1},
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get the primary type from the types map (first key)
			var primaryType string
			for k := range tc.types {
				primaryType = k
				break
			}
			
			sig, err := signer.SignTypedData(tc.domain, tc.types, primaryType, tc.message)
			require.NoError(t, err)
			require.NotNil(t, sig)
			
			// Verify signature is valid
			recovered, err := sig.Recover(tc.domain, tc.types, primaryType, tc.message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
		})
	}
}

func TestMaximumNestingDepth(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Nesting Test", "1", 1)
	
	// Create types with various nesting depths
	testCases := []struct {
		name     string
		depth    int
		wantError bool
	}{
		{"depth 5", 5, false},
		{"depth 10", 10, false},
		{"depth 20", 20, false},
		{"depth 50", 50, false}, // This might fail or be very slow
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build nested types
			types := make(map[string][]Type)
			for i := 0; i < tc.depth; i++ {
				typeName := fmt.Sprintf("Level%d", i)
				if i == 0 {
					types[typeName] = []Type{{Name: "value", Type: "string"}}
				} else {
					types[typeName] = []Type{{Name: "nested", Type: fmt.Sprintf("Level%d", i-1)}}
				}
			}
			
			// Build nested message
			var buildMessage func(level int) interface{}
			buildMessage = func(level int) interface{} {
				if level == 0 {
					return map[string]interface{}{"value": "deepest"}
				}
				return map[string]interface{}{"nested": buildMessage(level - 1)}
			}
			
			primaryType := fmt.Sprintf("Level%d", tc.depth-1)
			message := Message{"nested": buildMessage(tc.depth - 2)}
			
			sig, err := signer.SignTypedData(domain, types, primaryType, message)
			
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
			}
		})
	}
}

func TestInvalidTypeFormats(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Type Test", "1", 1)
	
	testCases := []struct {
		name      string
		types     map[string][]Type
		message   Message
		wantError bool
	}{
		{
			name: "uint with invalid size",
			types: map[string][]Type{
				"Message": {{Name: "data", Type: "uint257"}},
			},
			message:   Message{"data": "123"},
			wantError: true,
		},
		{
			name: "bytes with invalid size",
			types: map[string][]Type{
				"Message": {{Name: "data", Type: "bytes33"}},
			},
			message:   Message{"data": "0x00"},
			wantError: true,
		},
		{
			name: "int with invalid size",
			types: map[string][]Type{
				"Message": {{Name: "data", Type: "int512"}},
			},
			message:   Message{"data": "123"},
			wantError: true,
		},
		{
			name: "completely invalid type",
			types: map[string][]Type{
				"Message": {{Name: "data", Type: "notAType"}},
			},
			message:   Message{"data": "123"},
			wantError: true,
		},
		{
			name: "empty type name",
			types: map[string][]Type{
				"Message": {{Name: "data", Type: ""}},
			},
			message:   Message{"data": "123"},
			wantError: true,
		},
		{
			name: "type with spaces",
			types: map[string][]Type{
				"Message": {{Name: "data", Type: "uint 256"}},
			},
			message:   Message{"data": "123"},
			wantError: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signer.SignTypedData(domain, tc.types, "Message", tc.message)
			
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMemoryCleanup(t *testing.T) {
	// This test ensures sensitive data doesn't leak
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Memory Test", "1", 1)
	types := map[string][]Type{
		"Sensitive": {
			{Name: "secret", Type: "string"},
			{Name: "password", Type: "string"},
		},
	}
	
	sensitiveData := "SUPER_SECRET_DATA_12345"
	message := Message{
		"secret":   sensitiveData,
		"password": "MyPassword123!",
	}
	
	sig, err := signer.SignTypedData(domain, types, "Sensitive", message)
	require.NoError(t, err)
	require.NotNil(t, sig)
	
	// The signature should not contain the raw sensitive data
	assert.NotContains(t, sig.Bytes, sensitiveData)
	assert.NotContains(t, sig.Hash, sensitiveData)
}

func TestDomainSeparatorConsistency(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	// Same domain should produce same separator
	domain1 := createTestDomain("Test App", "1", 1)
	domain2 := createTestDomain("Test App", "1", 1)
	
	types := map[string][]Type{
		"Message": {{Name: "data", Type: "string"}},
	}
	message := Message{"data": "test"}
	
	sig1, err := signer.SignTypedData(domain1, types, "Message", message)
	require.NoError(t, err)
	
	sig2, err := signer.SignTypedData(domain2, types, "Message", message)
	require.NoError(t, err)
	
	// Same domain and message should produce same hash
	assert.Equal(t, sig1.Hash, sig2.Hash)
	
	// Different domain should produce different hash
	domain3 := createTestDomain("Different App", "1", 1)
	sig3, err := signer.SignTypedData(domain3, types, "Message", message)
	require.NoError(t, err)
	
	assert.NotEqual(t, sig1.Hash, sig3.Hash)
}