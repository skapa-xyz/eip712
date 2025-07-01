package eip712

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Benchmark SignPermit optimizations
func BenchmarkSignPermitOptimizations(b *testing.B) {
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress(testAddress2)
	value := big.NewInt(1000000)
	nonce := big.NewInt(0)
	deadline := big.NewInt(1893456000)
	
	b.Run("Original", func(b *testing.B) {
		signer, _ := NewSigner(testPrivateKey1, 1)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
		}
	})
	
	b.Run("FastSigner", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignPermitFast(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
		}
	})
	
	b.Run("FastOptimized", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignPermitFastOptimized(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
		}
	})
}

// Benchmark SignMessage optimizations
func BenchmarkSignMessageOptimizations(b *testing.B) {
	messages := []map[string]interface{}{
		{
			"action": "transfer",
			"from":   testAddress1,
			"to":     testAddress2,
			"amount": "1000000000000000000",
		},
		{
			"type":   "order",
			"maker":  testAddress1,
			"taker":  testAddress2,
			"amount": "1000",
			"price":  "2000",
		},
		{
			"text":      "Hello World!",
			"user":      testAddress1,
			"timestamp": "1234567890",
		},
	}
	
	b.Run("Original", func(b *testing.B) {
		signer, _ := NewSigner(testPrivateKey1, 1)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignMessage("Test App", messages[i%len(messages)])
		}
	})
	
	b.Run("FastSigner", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignMessageFast("Test App", messages[i%len(messages)])
		}
	})
	
	b.Run("FastOptimized", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignMessageFastOptimized("Test App", messages[i%len(messages)])
		}
	})
	
	b.Run("FastOptimized_Cached", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		// Pre-warm cache
		for _, msg := range messages {
			_, _ = signer.SignMessageFastOptimized("Test App", msg)
		}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignMessageFastOptimized("Test App", messages[i%len(messages)])
		}
	})
}

// Benchmark type inference
func BenchmarkTypeInferenceOptimizations(b *testing.B) {
	messages := []map[string]interface{}{
		{
			"address": testAddress1,
			"amount":  "1000000",
			"flag":    true,
		},
		{
			"text":   "Hello",
			"number": "42",
			"bytes":  []byte{1, 2, 3, 4},
		},
		{
			"array": []interface{}{"a", "b", "c"},
			"mixed": testAddress2,
			"value": "999999999",
		},
	}
	
	b.Run("Original", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = inferTypes(messages[i%len(messages)])
		}
	})
	
	b.Run("Optimized", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = inferTypesOptimizedWithCache(messages[i%len(messages)])
		}
	})
	
	b.Run("Optimized_Cached", func(b *testing.B) {
		// Pre-warm cache
		for _, msg := range messages {
			_ = inferTypesOptimizedWithCache(msg)
		}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = inferTypesOptimizedWithCache(messages[i%len(messages)])
		}
	})
}

// Benchmark signature recovery optimizations
func BenchmarkRecoveryOptimizations(b *testing.B) {
	domain := createTestDomain("Test", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Test message"}
	
	signer, _ := NewSigner(testPrivateKey1, 1)
	sig, _ := signer.SignTypedData(domain, types, "Message", message)
	
	b.Run("Original", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = sig.Recover(domain, types, "Message", message)
		}
	})
	
	b.Run("FastOptimized", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = RecoverFastOptimized(sig, domain, types, "Message", message)
		}
	})
}

// Benchmark NewSigner optimizations
func BenchmarkNewSignerOptimizations(b *testing.B) {
	b.Run("Original", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = NewSigner(testPrivateKey1, 1)
		}
	})
	
	b.Run("Optimized", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = NewSignerOptimized(testPrivateKey1, 1)
		}
	})
	
	b.Run("FastSigner", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = NewFastSigner(testPrivateKey1, 1)
		}
	})
	
	b.Run("FastSignerOptimized", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = NewFastSignerOptimized(testPrivateKey1, 1)
		}
	})
}

// Benchmark showing overall improvements
func BenchmarkLowHangingFruitSummary(b *testing.B) {
	// Setup common data
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress(testAddress2)
	value := big.NewInt(1000000)
	nonce := big.NewInt(0)
	deadline := big.NewInt(1893456000)
	
	message := map[string]interface{}{
		"action": "transfer",
		"from":   testAddress1,
		"to":     testAddress2,
		"amount": "1000000000000000000",
	}
	
	b.Run("AllOriginal", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			signer, _ := NewSigner(testPrivateKey1, 1)
			
			// SignPermit
			_, _ = signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
			
			// SignMessage
			_, _ = signer.SignMessage("Test App", message)
		}
	})
	
	b.Run("AllOptimized", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			signer, _ := NewFastSignerOptimized(testPrivateKey1, 1)
			
			// SignPermit
			_, _ = signer.SignPermitFastOptimized(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
			
			// SignMessage
			_, _ = signer.SignMessageFastOptimized("Test App", message)
		}
	})
}