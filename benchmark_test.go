package eip712

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func BenchmarkSignTypedData(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Benchmark App", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Benchmark message"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedData(domain, types, "Message", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignatureRecovery(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Benchmark App", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Benchmark message"}
	
	sig, err := signer.SignTypedData(domain, types, "Message", message)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sig.Recover(domain, types, "Message", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTypeInference(b *testing.B) {
	messages := []map[string]interface{}{
		{
			"text":    "Hello world",
			"number":  "123456789",
			"address": testAddress1,
			"flag":    true,
		},
		{
			"action":    "transfer",
			"from":      testAddress1,
			"to":        testAddress2,
			"amount":    "1000000000000000000",
			"timestamp": "1234567890",
		},
		{
			"data": []byte{0x01, 0x02, 0x03, 0x04},
			"hash": "0x1234567890123456789012345678901234567890123456789012345678901234",
			"user": testAddress1,
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inferTypes(messages[i%len(messages)])
	}
}

func BenchmarkSignMessage(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	message := map[string]interface{}{
		"action": "benchmark",
		"value":  "1000",
		"to":     testAddress2,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignMessage("Benchmark App", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignPermit(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress(testAddress2)
	value := new(big.Int).SetUint64(1000000)
	nonce := big.NewInt(0)
	deadline := big.NewInt(1893456000)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComplexTypes(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Complex Benchmark", "1", 1)
	types := createMailTypes()
	message := createMailMessage("Alice", testAddress1, "Bob", testAddress2, "Benchmark mail")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedData(domain, types, "Mail", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeeplyNestedTypes(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Nested Benchmark", "1", 1)
	
	types := map[string][]Type{
		"Level3": {{Name: "value", Type: "string"}},
		"Level2": {{Name: "data", Type: "Level3"}, {Name: "id", Type: "uint256"}},
		"Level1": {{Name: "nested", Type: "Level2"}, {Name: "owner", Type: "address"}},
	}
	
	message := Message{
		"nested": map[string]interface{}{
			"id": "123",
			"data": map[string]interface{}{
				"value": "Deep value",
			},
		},
		"owner": testAddress1,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedData(domain, types, "Level1", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArrayTypes(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Array Benchmark", "1", 1)
	types := map[string][]Type{
		"Message": {
			{Name: "items", Type: "string[]"},
			{Name: "values", Type: "uint256[]"},
		},
	}
	
	// Create arrays of different sizes
	items := make([]string, 100)
	values := make([]string, 100)
	for i := 0; i < 100; i++ {
		items[i] = "item"
		values[i] = "1000"
	}
	
	message := Message{
		"items":  items,
		"values": values,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedData(domain, types, "Message", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLargeMessage(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Large Message Benchmark", "1", 1)
	types := map[string][]Type{
		"LargeMessage": {
			{Name: "content", Type: "string"},
			{Name: "metadata", Type: "string"},
		},
	}
	
	// Create a large message (10KB of text)
	largeContent := strings.Repeat("a", 10000)
	message := Message{
		"content":  largeContent,
		"metadata": "Large message benchmark",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedData(domain, types, "LargeMessage", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Verify Benchmark", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Verify benchmark"}
	
	sig, err := signer.SignTypedData(domain, types, "Message", message)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifySignature(sig, signer.Address(), domain, types, "Message", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewSigner(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainHashing(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	// Test different domain configurations
	domains := []Domain{
		// Minimal domain
		{Name: "Test", Version: "1"},
		// With chain ID
		createTestDomain("Test", "1", 1),
		// With verifying contract
		createTestDomainWithContract("Test", "1", 1, testAddress1),
		// With salt
		createTestDomainWithSalt("Test", "1", 1, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		// All fields
		func() Domain {
			d := createTestDomainWithContract("Test", "1", 1, testAddress1)
			var salt [32]byte
			copy(salt[:], []byte("benchmark salt value"))
			d.Salt = salt
			return d
		}(),
	}
	
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "test"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domain := domains[i%len(domains)]
		_, err := signer.SignTypedData(domain, types, "Message", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Comparative benchmarks for different message sizes
func BenchmarkMessageSizes(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Size Benchmark", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	
	sizes := []int{10, 100, 1000, 10000}
	
	for _, size := range sizes {
		content := strings.Repeat("x", size)
		message := Message{"content": content}
		
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := signer.SignTypedData(domain, types, "Message", message)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark concurrent signing
func BenchmarkConcurrentSigning(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Concurrent Benchmark", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}, {Name: "nonce", Type: "uint256"}},
	}
	
	b.RunParallel(func(pb *testing.PB) {
		nonce := 0
		for pb.Next() {
			message := Message{
				"content": "Concurrent test",
				"nonce":   fmt.Sprintf("%d", nonce),
			}
			nonce++
			
			_, err := signer.SignTypedData(domain, types, "Message", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}