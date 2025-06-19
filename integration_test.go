package eip712

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullWorkflow(t *testing.T) {
	// Create signer → Sign message → Verify signature → Recover address
	
	// Step 1: Create signer
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	require.Equal(t, common.HexToAddress(testAddress1), signer.Address())
	
	// Step 2: Create and sign a complex message
	domain := Domain{
		Name:              "Integration Test",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: common.HexToAddress("0x1234567890123456789012345678901234567890"),
	}
	
	types := map[string][]Type{
		"Person": {
			{Name: "name", Type: "string"},
			{Name: "age", Type: "uint256"},
			{Name: "wallet", Type: "address"},
		},
		"Transaction": {
			{Name: "from", Type: "Person"},
			{Name: "to", Type: "Person"},
			{Name: "amount", Type: "uint256"},
			{Name: "deadline", Type: "uint256"},
			{Name: "memo", Type: "string"},
		},
	}
	
	message := Message{
		"from": map[string]interface{}{
			"name":   "Alice",
			"age":    "30",
			"wallet": testAddress1,
		},
		"to": map[string]interface{}{
			"name":   "Bob",
			"age":    "25",
			"wallet": testAddress2,
		},
		"amount":   "1000000000000000000",
		"deadline": fmt.Sprintf("%d", time.Now().Add(24*time.Hour).Unix()),
		"memo":     "Payment for services",
	}
	
	sig, err := signer.SignTypedData(domain, types, "Transaction", message)
	require.NoError(t, err)
	assertSignatureComponents(t, sig)
	
	// Step 3: Verify the signature
	valid, err := VerifySignature(sig, signer.Address(), domain, types, "Transaction", message)
	require.NoError(t, err)
	require.True(t, valid)
	
	// Step 4: Recover the address
	recovered, err := sig.Recover(domain, types, "Transaction", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
	
	// Step 5: Verify wrong signer fails
	valid, err = VerifySignature(sig, common.HexToAddress(testAddress2), domain, types, "Transaction", message)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestMultipleSigners(t *testing.T) {
	// Test with multiple signers signing different messages
	privateKeys := []string{
		testPrivateKey1,
		testPrivateKey2,
		"0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
		"0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
	}
	
	signers := make([]*Signer, len(privateKeys))
	for i, pk := range privateKeys {
		signer, err := NewSigner(pk, 1)
		require.NoError(t, err)
		signers[i] = signer
	}
	
	domain := createTestDomain("Multi-Signer Test", "1", 1)
	types := map[string][]Type{
		"Message": {
			{Name: "from", Type: "address"},
			{Name: "content", Type: "string"},
			{Name: "nonce", Type: "uint256"},
		},
	}
	
	signatures := make([]*Signature, len(signers))
	messages := make([]Message, len(signers))
	
	// Each signer signs their own message
	for i, signer := range signers {
		message := Message{
			"from":    signer.Address().Hex(),
			"content": fmt.Sprintf("Message from signer %d", i),
			"nonce":   fmt.Sprintf("%d", i),
		}
		messages[i] = message
		
		sig, err := signer.SignTypedData(domain, types, "Message", message)
		require.NoError(t, err)
		signatures[i] = sig
	}
	
	// Verify all signatures
	for i, sig := range signatures {
		recovered, err := sig.Recover(domain, types, "Message", messages[i])
		require.NoError(t, err)
		require.Equal(t, signers[i].Address(), recovered)
		
		// Verify signature doesn't match with wrong message
		wrongIndex := (i + 1) % len(messages)
		recovered2, err := sig.Recover(domain, types, "Message", messages[wrongIndex])
		require.NoError(t, err)
		require.NotEqual(t, signers[i].Address(), recovered2)
	}
}

func TestConcurrentSigning(t *testing.T) {
	// Test that signing is thread-safe
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Concurrent Test", "1", 1)
	types := map[string][]Type{
		"Order": {
			{Name: "orderId", Type: "uint256"},
			{Name: "timestamp", Type: "uint256"},
		},
	}
	
	numGoroutines := 50
	signaturesPerGoroutine := 20
	
	var wg sync.WaitGroup
	signatures := make(chan *Signature, numGoroutines*signaturesPerGoroutine)
	errors := make(chan error, numGoroutines*signaturesPerGoroutine)
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < signaturesPerGoroutine; j++ {
				message := Message{
					"orderId":   fmt.Sprintf("%d", goroutineID*1000+j),
					"timestamp": fmt.Sprintf("%d", time.Now().UnixNano()),
				}
				
				sig, err := signer.SignTypedData(domain, types, "Order", message)
				if err != nil {
					errors <- err
					continue
				}
				signatures <- sig
			}
		}(i)
	}
	
	wg.Wait()
	close(signatures)
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Fatalf("Concurrent signing error: %v", err)
	}
	
	// Count signatures
	signatureCount := 0
	for sig := range signatures {
		assertSignatureComponents(t, sig)
		signatureCount++
	}
	
	require.Equal(t, numGoroutines*signaturesPerGoroutine, signatureCount)
}

func TestErrorHandling(t *testing.T) {
	// Test all error paths
	
	t.Run("invalid private key", func(t *testing.T) {
		_, err := NewSigner("invalid", 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid private key")
	})
	
	t.Run("sign with invalid types", func(t *testing.T) {
		signer, err := NewSigner(testPrivateKey1, 1)
		require.NoError(t, err)
		
		domain := createTestDomain("Error Test", "1", 1)
		types := map[string][]Type{
			"Message": {{Name: "data", Type: "InvalidType"}},
		}
		message := Message{"data": "test"}
		
		_, err = signer.SignTypedData(domain, types, "Message", message)
		require.Error(t, err)
	})
	
	t.Run("recover with invalid signature", func(t *testing.T) {
		sig := &Signature{
			R:     "invalid",
			S:     "invalid",
			V:     27,
			Bytes: "invalid",
		}
		
		domain := createTestDomain("Error Test", "1", 1)
		types := map[string][]Type{"Message": {{Name: "data", Type: "string"}}}
		message := Message{"data": "test"}
		
		_, err := sig.Recover(domain, types, "Message", message)
		require.Error(t, err)
	})
	
	t.Run("sign with missing primary type", func(t *testing.T) {
		signer, err := NewSigner(testPrivateKey1, 1)
		require.NoError(t, err)
		
		domain := createTestDomain("Error Test", "1", 1)
		types := map[string][]Type{
			"Message": {{Name: "data", Type: "string"}},
		}
		message := Message{"data": "test"}
		
		_, err = signer.SignTypedData(domain, types, "NonExistent", message)
		require.Error(t, err)
	})
}

func TestRealWorldScenarios(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	t.Run("NFT marketplace listing", func(t *testing.T) {
		domain := Domain{
			Name:              "OpenSea",
			Version:           "1",
			ChainID:           big.NewInt(1),
			VerifyingContract: common.HexToAddress("0x00000000006c3852cbEf3e08E8dF289169EdE581"),
		}
		
		types := map[string][]Type{
			"Asset": {
				{Name: "tokenId", Type: "uint256"},
				{Name: "tokenAddress", Type: "address"},
			},
			"Order": {
				{Name: "offerer", Type: "address"},
				{Name: "asset", Type: "Asset"},
				{Name: "price", Type: "uint256"},
				{Name: "expiry", Type: "uint256"},
				{Name: "nonce", Type: "uint256"},
			},
		}
		
		message := Message{
			"offerer": signer.Address().Hex(),
			"asset": map[string]interface{}{
				"tokenId":      "12345",
				"tokenAddress": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", // BAYC
			},
			"price":  "50000000000000000000", // 50 ETH
			"expiry": fmt.Sprintf("%d", time.Now().Add(7*24*time.Hour).Unix()),
			"nonce":  "1",
		}
		
		sig, err := signer.SignTypedData(domain, types, "Order", message)
		require.NoError(t, err)
		assertSignatureComponents(t, sig)
		
		// Verify the listing
		recovered, err := sig.Recover(domain, types, "Order", message)
		require.NoError(t, err)
		require.Equal(t, signer.Address(), recovered)
	})
	
	t.Run("DeFi governance vote", func(t *testing.T) {
		domain := Domain{
			Name:    "Compound Governor",
			Version: "1",
			ChainID: big.NewInt(1),
		}
		
		types := map[string][]Type{
			"Vote": {
				{Name: "proposalId", Type: "uint256"},
				{Name: "support", Type: "bool"},
				{Name: "reason", Type: "string"},
				{Name: "voter", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		}
		
		message := Message{
			"proposalId": "123",
			"support":    true,
			"reason":     "I support this proposal because it improves protocol efficiency",
			"voter":      signer.Address().Hex(),
			"nonce":      "0",
		}
		
		sig, err := signer.SignTypedData(domain, types, "Vote", message)
		require.NoError(t, err)
		assertSignatureComponents(t, sig)
	})
	
	t.Run("Multi-signature wallet operation", func(t *testing.T) {
		domain := Domain{
			Name:              "Gnosis Safe",
			Version:           "1.3.0",
			ChainID:           big.NewInt(1),
			VerifyingContract: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		}
		
		types := map[string][]Type{
			"Transaction": {
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		}
		
		message := Message{
			"to":             testAddress2,
			"value":          "1000000000000000000",
			"data":           "0x",
			"operation":      "0",
			"safeTxGas":      "0",
			"baseGas":        "0",
			"gasPrice":       "0",
			"gasToken":       "0x0000000000000000000000000000000000000000",
			"refundReceiver": "0x0000000000000000000000000000000000000000",
			"nonce":          "12",
		}
		
		sig, err := signer.SignTypedData(domain, types, "Transaction", message)
		require.NoError(t, err)
		assertSignatureComponents(t, sig)
	})
}

func TestDocumentationExamples(t *testing.T) {
	// Ensure all examples in documentation actually work
	
	t.Run("README example", func(t *testing.T) {
		// Parse the example JSON
		exampleJSON := ExampleJSON()
		var example map[string]interface{}
		err := json.Unmarshal([]byte(exampleJSON), &example)
		require.NoError(t, err)
		
		// Extract domain
		domainData := example["domain"].(map[string]interface{})
		domain := Domain{
			Name:    domainData["name"].(string),
			Version: domainData["version"].(string),
			ChainID: big.NewInt(int64(domainData["chainId"].(float64))),
		}
		
		// Extract and convert types
		typesData := example["types"].(map[string]interface{})
		types := make(map[string][]Type)
		for typeName, fields := range typesData {
			fieldsArray := fields.([]interface{})
			types[typeName] = make([]Type, len(fieldsArray))
			for i, field := range fieldsArray {
				fieldMap := field.(map[string]interface{})
				types[typeName][i] = Type{
					Name: fieldMap["name"].(string),
					Type: fieldMap["type"].(string),
				}
			}
		}
		
		// Extract message
		message := Message(example["message"].(map[string]interface{}))
		primaryType := example["primaryType"].(string)
		
		// Create signer and sign
		signer, err := NewSigner(testPrivateKey1, 1)
		require.NoError(t, err)
		
		sig, err := signer.SignTypedData(domain, types, primaryType, message)
		require.NoError(t, err)
		assertSignatureComponents(t, sig)
		
		// Verify
		recovered, err := sig.Recover(domain, types, primaryType, message)
		require.NoError(t, err)
		require.Equal(t, signer.Address(), recovered)
	})
	
	t.Run("SignMessage example", func(t *testing.T) {
		signer, err := NewSigner(testPrivateKey1, 1)
		require.NoError(t, err)
		
		// Simple message signing
		message := map[string]interface{}{
			"action": "Transfer",
			"amount": "1000000000000000000",
			"to":     testAddress2,
		}
		
		sig, err := signer.SignMessage("My App", message)
		require.NoError(t, err)
		assertSignatureComponents(t, sig)
	})
}

func TestSignatureFormat(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Format Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "test"}
	
	sig, err := signer.SignTypedData(domain, types, "Message", message)
	require.NoError(t, err)
	
	// Check signature format
	t.Run("R component", func(t *testing.T) {
		require.Regexp(t, `^0x[0-9a-fA-F]{64}$`, sig.R)
		r, err := hexutil.Decode(sig.R)
		require.NoError(t, err)
		require.Len(t, r, 32)
	})
	
	t.Run("S component", func(t *testing.T) {
		require.Regexp(t, `^0x[0-9a-fA-F]{64}$`, sig.S)
		s, err := hexutil.Decode(sig.S)
		require.NoError(t, err)
		require.Len(t, s, 32)
	})
	
	t.Run("V component", func(t *testing.T) {
		require.True(t, sig.V == 27 || sig.V == 28)
	})
	
	t.Run("Hash format", func(t *testing.T) {
		require.Regexp(t, `^0x[0-9a-fA-F]{64}$`, sig.Hash)
		hash, err := hexutil.Decode(sig.Hash)
		require.NoError(t, err)
		require.Len(t, hash, 32)
	})
	
	t.Run("Full signature", func(t *testing.T) {
		require.Regexp(t, `^0x[0-9a-fA-F]{130}$`, sig.Bytes)
		sigBytes, err := hexutil.Decode(sig.Bytes)
		require.NoError(t, err)
		require.Len(t, sigBytes, 65)
		
		// Verify components match
		assert.Equal(t, sig.R, hexutil.Encode(sigBytes[:32]))
		assert.Equal(t, sig.S, hexutil.Encode(sigBytes[32:64]))
		assert.Equal(t, sig.V, sigBytes[64])
	})
}

func TestChainIDHandling(t *testing.T) {
	privateKey := testPrivateKey1
	domain := Domain{
		Name:    "Chain Test",
		Version: "1",
	}
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "test"}
	
	// Test that different chain IDs produce different signatures
	chainIDs := []int64{1, 5, 137, 42161}
	signatures := make(map[string]int64)
	
	for _, chainID := range chainIDs {
		signer, err := NewSigner(privateKey, chainID)
		require.NoError(t, err)
		
		// Update domain with chain ID
		domain.ChainID = big.NewInt(chainID)
		
		sig, err := signer.SignTypedData(domain, types, "Message", message)
		require.NoError(t, err)
		
		// Check for uniqueness
		if existingChainID, exists := signatures[sig.Bytes]; exists {
			t.Errorf("Chain ID %d produced same signature as chain ID %d", chainID, existingChainID)
		}
		signatures[sig.Bytes] = chainID
	}
	
	require.Len(t, signatures, len(chainIDs))
}