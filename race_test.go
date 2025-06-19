// +build race

package eip712

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRaceConditions tests for race conditions in concurrent operations
func TestRaceConditions(t *testing.T) {
	// Create multiple signers
	signer1, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	signer2, err := NewSigner(testPrivateKey2, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Race Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "id", Type: "uint256"}, {Name: "data", Type: "string"}},
	}
	
	const numOperations = 100
	var wg sync.WaitGroup
	wg.Add(numOperations * 4) // 4 operations per iteration
	
	// Run multiple goroutines performing different operations
	for i := 0; i < numOperations; i++ {
		// Goroutine 1: Sign with signer1
		go func(id int) {
			defer wg.Done()
			message := Message{
				"id":   fmt.Sprintf("%d", id),
				"data": "signer1 data",
			}
			sig, err := signer1.SignTypedData(domain, types, "Message", message)
			require.NoError(t, err)
			require.NotNil(t, sig)
		}(i)
		
		// Goroutine 2: Sign with signer2
		go func(id int) {
			defer wg.Done()
			message := Message{
				"id":   fmt.Sprintf("%d", id),
				"data": "signer2 data",
			}
			sig, err := signer2.SignTypedData(domain, types, "Message", message)
			require.NoError(t, err)
			require.NotNil(t, sig)
		}(i)
		
		// Goroutine 3: Verify signatures
		go func(id int) {
			defer wg.Done()
			message := Message{
				"id":   fmt.Sprintf("%d", id),
				"data": "verify data",
			}
			sig, err := signer1.SignTypedData(domain, types, "Message", message)
			require.NoError(t, err)
			
			recovered, err := sig.Recover(domain, types, "Message", message)
			require.NoError(t, err)
			require.Equal(t, signer1.Address(), recovered)
		}(i)
		
		// Goroutine 4: Type inference
		go func(id int) {
			defer wg.Done()
			message := map[string]interface{}{
				"string":  "test",
				"number":  fmt.Sprintf("%d", id),
				"address": testAddress1,
				"bool":    true,
			}
			types := inferTypes(message)
			require.Len(t, types, 4)
		}(i)
	}
	
	wg.Wait()
}

// TestConcurrentDomainOperations tests concurrent operations with different domains
func TestConcurrentDomainOperations(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domains := []Domain{
		createTestDomain("App1", "1", 1),
		createTestDomain("App2", "1", 1),
		createTestDomain("App3", "1", 1),
		createTestDomainWithContract("App4", "1", 1, testAddress1),
		createTestDomainWithSalt("App5", "1", 1, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}
	
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "concurrent test"}
	
	var wg sync.WaitGroup
	const numIterations = 20
	
	for _, domain := range domains {
		for i := 0; i < numIterations; i++ {
			wg.Add(1)
			go func(d Domain, iteration int) {
				defer wg.Done()
				
				sig, err := signer.SignTypedData(d, types, "Message", message)
				require.NoError(t, err)
				require.NotNil(t, sig)
				
				// Verify the signature
				recovered, err := sig.Recover(d, types, "Message", message)
				require.NoError(t, err)
				require.Equal(t, signer.Address(), recovered)
			}(domain, i)
		}
	}
	
	wg.Wait()
}

// TestConcurrentSignatureRecovery tests concurrent signature recovery operations
func TestConcurrentSignatureRecovery(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Recovery Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "data", Type: "string"}},
	}
	message := Message{"data": "test"}
	
	// Create a signature
	sig, err := signer.SignTypedData(domain, types, "Message", message)
	require.NoError(t, err)
	
	var wg sync.WaitGroup
	const numGoroutines = 100
	
	// Multiple goroutines recovering the same signature
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			recovered, err := sig.Recover(domain, types, "Message", message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
			
			// Also test VerifySignature
			valid, err := VerifySignature(sig, signer.Address(), domain, types, "Message", message)
			require.NoError(t, err)
			require.True(t, valid)
		}()
	}
	
	wg.Wait()
}