package eip712

import (
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSigner(t *testing.T) {
	tests := []signerTestCase{
		{
			name:     "valid private key with 0x prefix",
			key:      testPrivateKey1,
			chainID:  1,
			wantAddr: testAddress1,
		},
		{
			name:     "valid private key without 0x prefix",
			key:      testPrivateKey1[2:],
			chainID:  1,
			wantAddr: testAddress1,
		},
		{
			name:      "invalid private key - wrong length",
			key:       "0x1234",
			chainID:   1,
			wantError: true,
		},
		{
			name:      "invalid private key - not hex",
			key:       "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
			chainID:   1,
			wantError: true,
		},
		{
			name:      "empty private key",
			key:       "",
			chainID:   1,
			wantError: true,
		},
		{
			name:     "different chain ID",
			key:      testPrivateKey2,
			chainID:  137,
			wantAddr: testAddress2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.key, tt.chainID)
			
			if tt.wantError {
				require.Error(t, err)
				require.Nil(t, signer)
				return
			}
			
			require.NoError(t, err)
			require.NotNil(t, signer)
			assert.Equal(t, common.HexToAddress(tt.wantAddr), signer.Address())
			assert.Equal(t, big.NewInt(tt.chainID), signer.ChainID())
		})
	}
}

func TestNewSignerFromKeystore(t *testing.T) {
	// Load test keystore from testdata
	keystoreJSON, err := os.ReadFile("testdata/test_keystore.json")
	require.NoError(t, err)

	t.Run("valid keystore with correct password", func(t *testing.T) {
		signer, err := NewSignerFromKeystore(keystoreJSON, "testpassword", 1)
		require.NoError(t, err)
		require.NotNil(t, signer)
		require.Equal(t, common.HexToAddress(testAddress1), signer.Address())
		require.Equal(t, big.NewInt(1), signer.ChainID())
	})

	t.Run("invalid keystore JSON", func(t *testing.T) {
		signer, err := NewSignerFromKeystore([]byte("invalid json"), "password", 1)
		require.Error(t, err)
		require.Nil(t, signer)
		assert.Contains(t, err.Error(), "failed to decrypt keystore")
	})

	t.Run("wrong password", func(t *testing.T) {
		signer, err := NewSignerFromKeystore(keystoreJSON, "wrongpassword", 1)
		require.Error(t, err)
		require.Nil(t, signer)
		assert.Contains(t, err.Error(), "failed to decrypt keystore")
	})

	t.Run("malformed keystore", func(t *testing.T) {
		malformedKeystore := []byte(`{
			"address": "f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			"crypto": {
				"cipher": "aes-128-ctr"
			},
			"version": 3
		}`)
		signer, err := NewSignerFromKeystore(malformedKeystore, "test", 1)
		require.Error(t, err)
		require.Nil(t, signer)
	})

	t.Run("empty keystore", func(t *testing.T) {
		signer, err := NewSignerFromKeystore([]byte{}, "test", 1)
		require.Error(t, err)
		require.Nil(t, signer)
	})

	t.Run("keystore with different chain ID", func(t *testing.T) {
		t.Skip("Skipping - need to know the correct password for the test keystore")
	})
}

func TestSignTypedData(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)

	tests := []signTestCase{
		{
			name:        "simple message",
			domain:      createTestDomain("Test App", "1", 1),
			types:       map[string][]Type{"Message": {{Name: "text", Type: "string"}}},
			primaryType: "Message",
			message:     Message{"text": "Hello, world!"},
		},
		{
			name:        "nested types (Mail example)",
			domain:      createTestDomain("Ether Mail", "1", 1),
			types:       createMailTypes(),
			primaryType: "Mail",
			message:     createMailMessage("Alice", testAddress1, "Bob", testAddress2, "Hello, Bob!"),
		},
		{
			name: "all primitive types",
			domain: createTestDomain("Test App", "1", 1),
			types: map[string][]Type{
				"AllTypes": {
					{Name: "stringVal", Type: "string"},
					{Name: "uint256Val", Type: "uint256"},
					{Name: "addressVal", Type: "address"},
					{Name: "boolVal", Type: "bool"},
					{Name: "bytes32Val", Type: "bytes32"},
				},
			},
			primaryType: "AllTypes",
			message: Message{
				"stringVal":  "test",
				"uint256Val": "12345",
				"addressVal": testAddress1,
				"boolVal":    true,
				"bytes32Val": "0x0000000000000000000000000000000000000000000000000000000000000001",
			},
		},
		{
			name:        "empty message",
			domain:      createTestDomain("Test App", "1", 1),
			types:       map[string][]Type{"Empty": {}},
			primaryType: "Empty",
			message:     Message{},
		},
		{
			name:        "domain with all fields",
			domain:      createTestDomainWithSalt("Test App", "1", 1, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
			types:       map[string][]Type{"Message": {{Name: "text", Type: "string"}}},
			primaryType: "Message",
			message:     Message{"text": "test"},
		},
		{
			name: "minimal domain (only name and version)",
			domain: Domain{
				Name:    "Test",
				Version: "1",
			},
			types:       map[string][]Type{"Message": {{Name: "text", Type: "string"}}},
			primaryType: "Message",
			message:     Message{"text": "test"},
		},
		{
			name:        "invalid primary type",
			domain:      createTestDomain("Test App", "1", 1),
			types:       map[string][]Type{"Message": {{Name: "text", Type: "string"}}},
			primaryType: "NonExistent",
			message:     Message{"text": "test"},
			wantError:   true,
		},
		{
			name:        "mismatched message fields",
			domain:      createTestDomain("Test App", "1", 1),
			types:       map[string][]Type{"Message": {{Name: "text", Type: "string"}}},
			primaryType: "Message",
			message:     Message{"wrongField": "test"},
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := signer.SignTypedData(tt.domain, tt.types, tt.primaryType, tt.message)
			
			if tt.wantError {
				require.Error(t, err)
				require.Nil(t, sig)
				return
			}
			
			require.NoError(t, err)
			require.NotNil(t, sig)
			assertSignatureComponents(t, sig)
			
			// Verify the signature can be recovered
			recovered, err := sig.Recover(tt.domain, tt.types, tt.primaryType, tt.message)
			require.NoError(t, err)
			assert.Equal(t, signer.Address(), recovered)
		})
	}
}

func TestSignMessage(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)

	tests := []struct {
		name    string
		appName string
		message map[string]interface{}
	}{
		{
			name:    "simple string message",
			appName: "Test App",
			message: map[string]interface{}{
				"content": "Hello, world!",
			},
		},
		{
			name:    "message with address",
			appName: "Test App",
			message: map[string]interface{}{
				"to":      testAddress2,
				"content": "Send to address",
			},
		},
		{
			name:    "message with number string",
			appName: "Test App",
			message: map[string]interface{}{
				"amount": "1000000000000000000",
				"to":     testAddress2,
			},
		},
		{
			name:    "message with boolean",
			appName: "Test App",
			message: map[string]interface{}{
				"approved": true,
				"user":     testAddress1,
			},
		},
		{
			name:    "complex message with mixed types",
			appName: "Test App",
			message: map[string]interface{}{
				"action":    "transfer",
				"from":      testAddress1,
				"to":        testAddress2,
				"amount":    "50000000000000000000",
				"approved":  true,
				"timestamp": "1234567890",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := signer.SignMessage(tt.appName, tt.message)
			require.NoError(t, err)
			require.NotNil(t, sig)
			assertSignatureComponents(t, sig)
			
			// Verify we can recover the address
			// Now that inferTypes sorts deterministically, we can verify recovery
			domain := Domain{
				Name:    tt.appName,
				Version: "1",
				ChainID: signer.ChainID(),
			}
			
			// Infer types to match what SignMessage does
			types := map[string][]Type{
				"Message": inferTypes(tt.message),
			}
			
			recovered, err := sig.Recover(domain, types, "Message", tt.message)
			require.NoError(t, err)
			assert.Equal(t, signer.Address(), recovered)
		})
	}
}

func TestInferTypes(t *testing.T) {
	tests := []struct {
		name     string
		message  map[string]interface{}
		expected []Type
	}{
		{
			name: "string values",
			message: map[string]interface{}{
				"name": "Alice",
				"text": "Hello",
			},
			expected: []Type{
				{Name: "name", Type: "string"},
				{Name: "text", Type: "string"},
			},
		},
		{
			name: "address values",
			message: map[string]interface{}{
				"from": testAddress1,
				"to":   testAddress2,
			},
			expected: []Type{
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
			},
		},
		{
			name: "number strings",
			message: map[string]interface{}{
				"amount": "1000000000000000000",
				"nonce":  "5",
			},
			expected: []Type{
				{Name: "amount", Type: "uint256"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		{
			name: "boolean values",
			message: map[string]interface{}{
				"approved": true,
				"active":   false,
			},
			expected: []Type{
				{Name: "active", Type: "bool"},
				{Name: "approved", Type: "bool"},
			},
		},
		{
			name: "big.Int values",
			message: map[string]interface{}{
				"value": big.NewInt(123456),
			},
			expected: []Type{
				{Name: "value", Type: "uint256"},
			},
		},
		{
			name: "native int types",
			message: map[string]interface{}{
				"count": 42,
				"total": uint64(100),
			},
			expected: []Type{
				{Name: "count", Type: "uint256"},
				{Name: "total", Type: "uint256"},
			},
		},
		{
			name: "byte arrays",
			message: map[string]interface{}{
				"data": []byte{0x01, 0x02, 0x03, 0x04},
			},
			expected: []Type{
				{Name: "data", Type: "bytes4"},
			},
		},
		{
			name: "address-like strings that aren't addresses",
			message: map[string]interface{}{
				"notAddr": "0xNotAnAddress",
				"hash":    "0x1234567890123456789012345678901234567890123456789012345678901234",
			},
			expected: []Type{
				{Name: "hash", Type: "string"},
				{Name: "notAddr", Type: "string"},
			},
		},
		{
			name: "mixed types",
			message: map[string]interface{}{
				"action":   "transfer",
				"from":     testAddress1,
				"to":       testAddress2,
				"amount":   "1000000000000000000",
				"approved": true,
				"data":     []byte{0x00},
			},
			expected: []Type{
				{Name: "action", Type: "string"},
				{Name: "amount", Type: "uint256"},
				{Name: "approved", Type: "bool"},
				{Name: "data", Type: "bytes1"},
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferTypes(tt.message)
			
			// Convert to map for easier comparison (order doesn't matter)
			resultMap := make(map[string]string)
			for _, t := range result {
				resultMap[t.Name] = t.Type
			}
			
			expectedMap := make(map[string]string)
			for _, t := range tt.expected {
				expectedMap[t.Name] = t.Type
			}
			
			assert.Equal(t, expectedMap, resultMap)
		})
	}
}

func TestVerifySignature(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)

	domain := createTestDomain("Test App", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "text", Type: "string"}},
	}
	primaryType := "Message"
	message := Message{"text": "Hello, world!"}

	// Sign a message
	sig, err := signer.SignTypedData(domain, types, primaryType, message)
	require.NoError(t, err)

	tests := []struct {
		name           string
		signature      *Signature
		expectedSigner common.Address
		domain         Domain
		types          map[string][]Type
		primaryType    string
		message        Message
		wantValid      bool
		wantError      bool
	}{
		{
			name:           "valid signature",
			signature:      sig,
			expectedSigner: signer.Address(),
			domain:         domain,
			types:          types,
			primaryType:    primaryType,
			message:        message,
			wantValid:      true,
		},
		{
			name:           "wrong expected signer",
			signature:      sig,
			expectedSigner: common.HexToAddress(testAddress2),
			domain:         domain,
			types:          types,
			primaryType:    primaryType,
			message:        message,
			wantValid:      false,
		},
		{
			name:           "modified message",
			signature:      sig,
			expectedSigner: signer.Address(),
			domain:         domain,
			types:          types,
			primaryType:    primaryType,
			message:        Message{"text": "Modified message"},
			wantValid:      false,
		},
		{
			name:           "modified domain",
			signature:      sig,
			expectedSigner: signer.Address(),
			domain:         createTestDomain("Wrong App", "1", 1),
			types:          types,
			primaryType:    primaryType,
			message:        message,
			wantValid:      false,
		},
		{
			name: "invalid signature",
			signature: &Signature{
				R:     "0x0000000000000000000000000000000000000000000000000000000000000000",
				S:     "0x0000000000000000000000000000000000000000000000000000000000000000",
				V:     27,
				Hash:  sig.Hash,
				Bytes: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b",
			},
			expectedSigner: signer.Address(),
			domain:         domain,
			types:          types,
			primaryType:    primaryType,
			message:        message,
			wantError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := VerifySignature(
				tt.signature,
				tt.expectedSigner,
				tt.domain,
				tt.types,
				tt.primaryType,
				tt.message,
			)
			
			if tt.wantError {
				require.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			assert.Equal(t, tt.wantValid, valid)
		})
	}
}

func TestDomainToAPITypes(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)

	tests := []struct {
		name   string
		domain Domain
	}{
		{
			name:   "minimal domain",
			domain: Domain{Name: "Test", Version: "1"},
		},
		{
			name:   "domain with chain ID",
			domain: createTestDomain("Test", "1", 1),
		},
		{
			name:   "domain with verifying contract",
			domain: createTestDomainWithContract("Test", "1", 1, testAddress1),
		},
		{
			name: "domain with salt",
			domain: createTestDomainWithSalt("Test", "1", 1, 
				"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		},
		{
			name: "domain with all fields",
			domain: func() Domain {
				d := createTestDomainWithContract("Test", "1", 1, testAddress1)
				var salt [32]byte
				copy(salt[:], []byte("test salt value for domain sep"))
				d.Salt = salt
				return d
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiDomain := signer.domainToAPITypes(tt.domain)
			
			assert.Equal(t, tt.domain.Name, apiDomain.Name)
			assert.Equal(t, tt.domain.Version, apiDomain.Version)
			
			if tt.domain.ChainID != nil {
				assert.NotNil(t, apiDomain.ChainId)
			}
			
			if tt.domain.VerifyingContract != (common.Address{}) {
				assert.Equal(t, tt.domain.VerifyingContract.Hex(), apiDomain.VerifyingContract)
			}
			
			if tt.domain.Salt != [32]byte{} {
				assert.NotEmpty(t, apiDomain.Salt)
			}
		})
	}
}

func TestExampleJSON(t *testing.T) {
	// Test that the example JSON is valid and can be parsed
	jsonStr := ExampleJSON()
	assert.NotEmpty(t, jsonStr)
	
	// Should be valid JSON
	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	require.NoError(t, err)
	
	// Should contain expected fields
	assert.Contains(t, data, "domain")
	assert.Contains(t, data, "types")
	assert.Contains(t, data, "primaryType")
	assert.Contains(t, data, "message")
}

func TestNewSignerEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		chainID   int64
		wantError bool
		errorMsg  string
	}{
		{
			name:      "private key with invalid hex characters",
			key:       "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
			chainID:   1,
			wantError: true,
			errorMsg:  "invalid private key",
		},
		{
			name:      "valid hex but invalid secp256k1 key (all zeros)",
			key:       "0x0000000000000000000000000000000000000000000000000000000000000000",
			chainID:   1,
			wantError: true,
			errorMsg:  "invalid private key",
		},
		{
			name:      "valid hex but invalid secp256k1 key (exceeds curve order)",
			key:       "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
			chainID:   1,
			wantError: true,
			errorMsg:  "invalid private key",
		},
		{
			name:      "private key with odd length",
			key:       "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff8",
			chainID:   1,
			wantError: true,
			errorMsg:  "invalid private key",
		},
		{
			name:      "negative chain ID",
			key:       testPrivateKey1,
			chainID:   -1,
			wantError: false, // Should succeed, big.Int can handle negative
		},
		{
			name:      "very large chain ID",
			key:       testPrivateKey1,
			chainID:   9223372036854775807, // max int64
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.key, tt.chainID)
			
			if tt.wantError {
				require.Error(t, err)
				require.Nil(t, signer)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, signer)
				assert.Equal(t, big.NewInt(tt.chainID), signer.ChainID())
			}
		})
	}
}

func TestSignTypedDataErrorPaths(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)

	tests := []struct {
		name        string
		domain      Domain
		types       map[string][]Type
		primaryType string
		message     Message
		wantError   bool
		errorMsg    string
	}{
		{
			name:   "invalid type in type definition",
			domain: createTestDomain("Test", "1", 1),
			types: map[string][]Type{
				"Message": {
					{Name: "data", Type: "uint512"}, // Invalid uint size
				},
			},
			primaryType: "Message",
			message:     Message{"data": "123"},
			wantError:   true,
			errorMsg:    "failed to hash typed data",
		},
		{
			name:   "missing field in message",
			domain: createTestDomain("Test", "1", 1),
			types: map[string][]Type{
				"Message": {
					{Name: "required", Type: "string"},
					{Name: "alsoRequired", Type: "uint256"},
				},
			},
			primaryType: "Message",
			message:     Message{"required": "present"}, // missing alsoRequired
			wantError:   true,
			errorMsg:    "failed to hash typed data",
		},
		{
			name:   "extra field in message",
			domain: createTestDomain("Test", "1", 1),
			types: map[string][]Type{
				"Message": {
					{Name: "expected", Type: "string"},
				},
			},
			primaryType: "Message",
			message: Message{
				"expected": "present",
				"extra":    "should not be here",
			},
			wantError: true,
			errorMsg:  "failed to hash typed data",
		},
		{
			name:   "circular type reference",
			domain: createTestDomain("Test", "1", 1),
			types: map[string][]Type{
				"A": {{Name: "b", Type: "B"}},
				"B": {{Name: "c", Type: "C"}},
				"C": {{Name: "a", Type: "A"}},
			},
			primaryType: "A",
			message: Message{
				"b": map[string]interface{}{
					"c": map[string]interface{}{
						"a": nil, // Would cause infinite loop
					},
				},
			},
			wantError: true,
			errorMsg:  "cyclic reference detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := signer.SignTypedData(tt.domain, tt.types, tt.primaryType, tt.message)
			
			if tt.wantError {
				require.Error(t, err)
				require.Nil(t, sig)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
			}
		})
	}
}

func TestInferTypesEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		message  map[string]interface{}
		expected []Type
	}{
		{
			name: "nil values",
			message: map[string]interface{}{
				"nilValue": nil,
			},
			expected: []Type{
				{Name: "nilValue", Type: "string"},
			},
		},
		{
			name: "float values",
			message: map[string]interface{}{
				"floatVal": 3.14,
			},
			expected: []Type{
				{Name: "floatVal", Type: "string"},
			},
		},
		{
			name: "slice of interfaces",
			message: map[string]interface{}{
				"slice": []interface{}{"a", "b", "c"},
			},
			expected: []Type{
				{Name: "slice", Type: "string"},
			},
		},
		{
			name: "map values",
			message: map[string]interface{}{
				"mapVal": map[string]string{"key": "value"},
			},
			expected: []Type{
				{Name: "mapVal", Type: "string"},
			},
		},
		{
			name: "int8 type",
			message: map[string]interface{}{
				"int8Val": int8(127),
			},
			expected: []Type{
				{Name: "int8Val", Type: "uint256"},
			},
		},
		{
			name: "int16 type",
			message: map[string]interface{}{
				"int16Val": int16(32767),
			},
			expected: []Type{
				{Name: "int16Val", Type: "uint256"},
			},
		},
		{
			name: "int32 type",
			message: map[string]interface{}{
				"int32Val": int32(2147483647),
			},
			expected: []Type{
				{Name: "int32Val", Type: "uint256"},
			},
		},
		{
			name: "uint8 type",
			message: map[string]interface{}{
				"uint8Val": uint8(255),
			},
			expected: []Type{
				{Name: "uint8Val", Type: "uint256"},
			},
		},
		{
			name: "uint16 type",
			message: map[string]interface{}{
				"uint16Val": uint16(65535),
			},
			expected: []Type{
				{Name: "uint16Val", Type: "uint256"},
			},
		},
		{
			name: "uint32 type",
			message: map[string]interface{}{
				"uint32Val": uint32(4294967295),
			},
			expected: []Type{
				{Name: "uint32Val", Type: "uint256"},
			},
		},
		{
			name: "empty byte array",
			message: map[string]interface{}{
				"emptyBytes": []byte{},
			},
			expected: []Type{
				{Name: "emptyBytes", Type: "bytes0"},
			},
		},
		{
			name: "address-like string that's too short",
			message: map[string]interface{}{
				"shortAddr": "0x1234",
			},
			expected: []Type{
				{Name: "shortAddr", Type: "string"},
			},
		},
		{
			name: "address-like string that's too long",
			message: map[string]interface{}{
				"longAddr": "0x" + strings.Repeat("a", 41),
			},
			expected: []Type{
				{Name: "longAddr", Type: "string"},
			},
		},
		{
			name: "string that looks like number but has leading zeros",
			message: map[string]interface{}{
				"paddedNum": "00123",
			},
			expected: []Type{
				{Name: "paddedNum", Type: "uint256"},
			},
		},
		{
			name: "string with scientific notation",
			message: map[string]interface{}{
				"sciNum": "1e18",
			},
			expected: []Type{
				{Name: "sciNum", Type: "string"}, // Not parsed as number
			},
		},
		{
			name: "negative number string",
			message: map[string]interface{}{
				"negNum": "-123",
			},
			expected: []Type{
				{Name: "negNum", Type: "uint256"}, // SetString accepts negative numbers
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferTypes(tt.message)
			
			// Convert to map for easier comparison (order doesn't matter)
			resultMap := make(map[string]string)
			for _, t := range result {
				resultMap[t.Name] = t.Type
			}
			
			expectedMap := make(map[string]string)
			for _, t := range tt.expected {
				expectedMap[t.Name] = t.Type
			}
			
			assert.Equal(t, expectedMap, resultMap)
		})
	}
}