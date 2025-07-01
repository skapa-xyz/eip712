package eip712

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestFastSignerCompatibility ensures the fast signer produces identical results
func TestFastSignerCompatibility(t *testing.T) {
	testCases := []struct {
		name        string
		domain      Domain
		types       map[string][]Type
		primaryType string
		message     Message
	}{
		{
			name:   "Simple message",
			domain: createTestDomain("Test App", "1", 1),
			types: map[string][]Type{
				"Message": {{Name: "content", Type: "string"}},
			},
			primaryType: "Message",
			message:     Message{"content": "Hello, World!"},
		},
		{
			name:   "Complex types",
			domain: createTestDomain("Mail App", "1", 1),
			types:  createMailTypes(),
			primaryType: "Mail",
			message: createMailMessage("Alice", testAddress1, "Bob", testAddress2, "Hello Bob!"),
		},
		{
			name:   "Array types",
			domain: createTestDomain("Array App", "1", 1),
			types: map[string][]Type{
				"Data": {
					{Name: "items", Type: "string[]"},
					{Name: "values", Type: "uint256[]"},
				},
			},
			primaryType: "Data",
			message: Message{
				"items":  []string{"a", "b", "c"},
				"values": []string{"1", "2", "3"},
			},
		},
		{
			name:   "Nested types",
			domain: createTestDomain("Nested App", "1", 1),
			types: map[string][]Type{
				"Inner": {{Name: "value", Type: "string"}},
				"Outer": {{Name: "inner", Type: "Inner"}, {Name: "id", Type: "uint256"}},
			},
			primaryType: "Outer",
			message: Message{
				"inner": map[string]interface{}{"value": "test"},
				"id":    "123",
			},
		},
		{
			name: "All primitive types",
			domain: createTestDomain("Primitives", "1", 1),
			types: map[string][]Type{
				"AllTypes": {
					{Name: "addr", Type: "address"},
					{Name: "flag", Type: "bool"},
					{Name: "data", Type: "bytes"},
					{Name: "data32", Type: "bytes32"},
					{Name: "num", Type: "uint256"},
					{Name: "text", Type: "string"},
				},
			},
			primaryType: "AllTypes",
			message: Message{
				"addr":   testAddress1,
				"flag":   true,
				"data":   []byte{1, 2, 3, 4},
				"data32": "0x1234567890123456789012345678901234567890123456789012345678901234",
				"num":    "42",
				"text":   "Hello",
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create signers
			originalSigner, err := NewSigner(testPrivateKey1, 1)
			if err != nil {
				t.Fatal(err)
			}
			
			fastSigner, err := NewFastSigner(testPrivateKey1, 1)
			if err != nil {
				t.Fatal(err)
			}
			
			// Sign with original
			originalSig, err := originalSigner.SignTypedData(tc.domain, tc.types, tc.primaryType, tc.message)
			if err != nil {
				t.Fatalf("Original signing failed: %v", err)
			}
			
			// Sign with fast
			fastSig, err := fastSigner.SignTypedDataFast(tc.domain, tc.types, tc.primaryType, tc.message)
			if err != nil {
				t.Fatalf("Fast signing failed: %v", err)
			}
			
			// Compare hashes
			if originalSig.Hash != fastSig.Hash {
				t.Errorf("Hash mismatch:\nOriginal: %s\nFast:     %s", originalSig.Hash, fastSig.Hash)
			}
			
			// Compare signatures
			if originalSig.Bytes != fastSig.Bytes {
				t.Errorf("Signature mismatch:\nOriginal: %s\nFast:     %s", originalSig.Bytes, fastSig.Bytes)
			}
			
			// Test recovery
			originalRecovered, err := originalSig.Recover(tc.domain, tc.types, tc.primaryType, tc.message)
			if err != nil {
				t.Fatalf("Original recovery failed: %v", err)
			}
			
			fastRecovered, err := RecoverSignatureFast(fastSig, tc.domain, tc.types, tc.primaryType, tc.message)
			if err != nil {
				t.Fatalf("Fast recovery failed: %v", err)
			}
			
			if originalRecovered != fastRecovered {
				t.Errorf("Recovered address mismatch:\nOriginal: %s\nFast:     %s", 
					originalRecovered.Hex(), fastRecovered.Hex())
			}
		})
	}
}

// TestFastSignerLargeData tests with large datasets
func TestFastSignerLargeData(t *testing.T) {
	// Create large array
	items := make([]string, 100)
	for i := range items {
		items[i] = "item"
	}
	
	domain := createTestDomain("Large Data", "1", 1)
	types := map[string][]Type{
		"Data": {{Name: "items", Type: "string[]"}},
	}
	message := Message{"items": items}
	
	// Test both signers
	originalSigner, _ := NewSigner(testPrivateKey1, 1)
	fastSigner, _ := NewFastSigner(testPrivateKey1, 1)
	
	originalSig, err := originalSigner.SignTypedData(domain, types, "Data", message)
	if err != nil {
		t.Fatalf("Original signing failed: %v", err)
	}
	
	fastSig, err := fastSigner.SignTypedDataFast(domain, types, "Data", message)
	if err != nil {
		t.Fatalf("Fast signing failed: %v", err)
	}
	
	if originalSig.Hash != fastSig.Hash {
		t.Errorf("Hash mismatch for large data")
	}
}

// TestFastSignerEdgeCases tests edge cases
func TestFastSignerEdgeCases(t *testing.T) {
	fastSigner, _ := NewFastSigner(testPrivateKey1, 1)
	
	t.Run("Empty arrays", func(t *testing.T) {
		domain := createTestDomain("Test", "1", 1)
		types := map[string][]Type{
			"Data": {{Name: "items", Type: "string[]"}},
		}
		message := Message{"items": []string{}}
		
		_, err := fastSigner.SignTypedDataFast(domain, types, "Data", message)
		if err != nil {
			t.Fatalf("Failed to sign empty array: %v", err)
		}
	})
	
	t.Run("Missing field", func(t *testing.T) {
		domain := createTestDomain("Test", "1", 1)
		types := map[string][]Type{
			"Data": {{Name: "value", Type: "string"}},
		}
		message := Message{} // Missing "value" field
		
		_, err := fastSigner.SignTypedDataFast(domain, types, "Data", message)
		if err == nil {
			t.Error("Expected error for missing field")
		}
	})
}

// TestFastPermit tests EIP-2612 permit signing
func TestFastPermit(t *testing.T) {
	originalSigner, _ := NewSigner(testPrivateKey1, 1)
	fastSigner, _ := NewFastSigner(testPrivateKey1, 1)
	
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress(testAddress2)
	value := big.NewInt(1000000)
	nonce := big.NewInt(0)
	deadline := big.NewInt(1893456000)
	
	originalSig, err := originalSigner.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
	if err != nil {
		t.Fatalf("Original permit signing failed: %v", err)
	}
	
	fastSig, err := fastSigner.SignPermitFast(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
	if err != nil {
		t.Fatalf("Fast permit signing failed: %v", err)
	}
	
	if originalSig.Hash != fastSig.Hash {
		t.Errorf("Permit hash mismatch")
	}
}