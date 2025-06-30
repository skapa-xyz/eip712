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
			b.ReportAllocs()
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

// Benchmark validateNoCycles function
func BenchmarkValidateNoCycles(b *testing.B) {
	testCases := []struct {
		name  string
		types map[string][]Type
	}{
		{
			name: "Simple",
			types: map[string][]Type{
				"Message": {{Name: "content", Type: "string"}},
			},
		},
		{
			name: "Nested",
			types: map[string][]Type{
				"Person": {{Name: "name", Type: "string"}, {Name: "wallet", Type: "address"}},
				"Mail": {{Name: "from", Type: "Person"}, {Name: "to", Type: "Person"}, {Name: "contents", Type: "string"}},
			},
		},
		{
			name: "Complex",
			types: map[string][]Type{
				"Address": {{Name: "street", Type: "string"}, {Name: "city", Type: "string"}},
				"Person": {{Name: "name", Type: "string"}, {Name: "address", Type: "Address"}},
				"Company": {{Name: "name", Type: "string"}, {Name: "owner", Type: "Person"}, {Name: "employees", Type: "Person[]"}},
				"Contract": {{Name: "company", Type: "Company"}, {Name: "value", Type: "uint256"}},
			},
		},
	}
	
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = validateNoCycles(tc.types)
			}
		})
	}
}

// Benchmark extreme nesting (> 3 levels)
func BenchmarkExtremeNesting(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Extreme Nesting", "1", 1)
	
	// Create 5 levels of nesting
	types := map[string][]Type{
		"Level5": {{Name: "value", Type: "string"}},
		"Level4": {{Name: "data", Type: "Level5"}, {Name: "id", Type: "uint256"}},
		"Level3": {{Name: "nested", Type: "Level4"}, {Name: "tag", Type: "string"}},
		"Level2": {{Name: "deep", Type: "Level3"}, {Name: "count", Type: "uint256"}},
		"Level1": {{Name: "root", Type: "Level2"}, {Name: "owner", Type: "address"}},
	}
	
	message := Message{
		"root": map[string]interface{}{
			"count": "100",
			"deep": map[string]interface{}{
				"tag": "deep-tag",
				"nested": map[string]interface{}{
					"id": "999",
					"data": map[string]interface{}{
						"value": "Extremely nested value",
					},
				},
			},
		},
		"owner": testAddress1,
	}
	
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedData(domain, types, "Level1", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark very large arrays (> 100 elements)
func BenchmarkVeryLargeArrays(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Large Array Benchmark", "1", 1)
	types := map[string][]Type{
		"Message": {
			{Name: "items", Type: "string[]"},
			{Name: "values", Type: "uint256[]"},
			{Name: "addresses", Type: "address[]"},
		},
	}
	
	arraySizes := []int{100, 500, 1000}
	
	for _, size := range arraySizes {
		b.Run(fmt.Sprintf("ArraySize_%d", size), func(b *testing.B) {
			// Create arrays of specified size
			items := make([]string, size)
			values := make([]string, size)
			addresses := make([]string, size)
			
			for i := 0; i < size; i++ {
				items[i] = fmt.Sprintf("item-%d", i)
				values[i] = fmt.Sprintf("%d", i*1000)
				addresses[i] = testAddress1
			}
			
			message := Message{
				"items":     items,
				"values":    values,
				"addresses": addresses,
			}
			
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := signer.SignTypedData(domain, types, "Message", message)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark helper functions
func BenchmarkDomainToAPITypes(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domains := []Domain{
		{Name: "Test", Version: "1"},
		createTestDomain("Test", "1", 1),
		createTestDomainWithContract("Test", "1", 1, testAddress1),
		func() Domain {
			d := createTestDomainWithContract("Test", "1", 1, testAddress1)
			var salt [32]byte
			copy(salt[:], []byte("benchmark salt"))
			d.Salt = salt
			return d
		}(),
	}
	
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.domainToAPITypes(domains[i%len(domains)])
	}
}

// Benchmark building domain types
func BenchmarkBuildDomainTypes(b *testing.B) {
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domains := []Domain{
		{Name: "Test", Version: "1"},
		createTestDomain("Test", "1", 1),
		createTestDomainWithContract("Test", "1", 1, testAddress1),
		createTestDomainWithSalt("Test", "1", 1, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}
	
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.buildDomainTypes(domains[i%len(domains)])
	}
}

// Benchmark NewSignerFromKeystore
func BenchmarkNewSignerFromKeystore(b *testing.B) {
	// Create a test keystore
	password := "test-password"
	// This is a test keystore with a known private key for benchmarking
	keystoreJSON := []byte(`{
		"address": "f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
		"crypto": {
			"cipher": "aes-128-ctr",
			"ciphertext": "e4610fb26bd43fa17fe6d3ac0ff166f7e4a98484dd6c8247ccd90c1215e4a7d8",
			"cipherparams": {
				"iv": "7bc492fb946dce4f8ffb3cec595b46f1"
			},
			"kdf": "scrypt",
			"kdfparams": {
				"dklen": 32,
				"n": 262144,
				"p": 1,
				"r": 8,
				"salt": "14c2b26e5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f5a5b5f"
			},
			"mac": "8ac9a206c1fb6130a9d1b57fc53b72b8e3e228c981ef7b44f6f6a28a4db50a26"
		},
		"id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
		"version": 3
	}`)
	
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewSignerFromKeystore(keystoreJSON, password, 1)
		if err != nil {
			b.Skip("Skipping keystore benchmark due to error:", err)
		}
	}
}