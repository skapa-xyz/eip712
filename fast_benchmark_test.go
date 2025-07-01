package eip712

import (
	"fmt"
	"testing"
)

// Benchmark comparing fast vs original implementation for arrays
func BenchmarkFastVsOriginalArrays(b *testing.B) {
	arraySizes := []int{100, 500, 1000}
	
	for _, size := range arraySizes {
		b.Run(fmt.Sprintf("Original_ArraySize_%d", size), func(b *testing.B) {
			signer, err := NewSigner(testPrivateKey1, 1)
			if err != nil {
				b.Fatal(err)
			}
			
			domain := createTestDomain("Array Benchmark", "1", 1)
			types := map[string][]Type{
				"Message": {
					{Name: "items", Type: "string[]"},
					{Name: "values", Type: "uint256[]"},
					{Name: "addresses", Type: "address[]"},
				},
			}
			
			// Create arrays
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
		
		b.Run(fmt.Sprintf("Fast_ArraySize_%d", size), func(b *testing.B) {
			signer, err := NewFastSigner(testPrivateKey1, 1)
			if err != nil {
				b.Fatal(err)
			}
			
			domain := createTestDomain("Array Benchmark", "1", 1)
			types := map[string][]Type{
				"Message": {
					{Name: "items", Type: "string[]"},
					{Name: "values", Type: "uint256[]"},
					{Name: "addresses", Type: "address[]"},
				},
			}
			
			// Create arrays
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
				_, err := signer.SignTypedDataFast(domain, types, "Message", message)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark comparing fast vs original for deep nesting
func BenchmarkFastVsOriginalNesting(b *testing.B) {
	b.Run("Original_DeepNesting", func(b *testing.B) {
		signer, err := NewSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		domain := createTestDomain("Nesting Benchmark", "1", 1)
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
	})
	
	b.Run("Fast_DeepNesting", func(b *testing.B) {
		signer, err := NewFastSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		domain := createTestDomain("Nesting Benchmark", "1", 1)
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
			_, err := signer.SignTypedDataFast(domain, types, "Level1", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Benchmark simple messages
func BenchmarkFastVsOriginalSimple(b *testing.B) {
	b.Run("Original_Simple", func(b *testing.B) {
		signer, err := NewSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		domain := createTestDomain("Simple Benchmark", "1", 1)
		types := map[string][]Type{
			"Message": {{Name: "content", Type: "string"}},
		}
		message := Message{"content": "Hello, World!"}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignTypedData(domain, types, "Message", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("Fast_Simple", func(b *testing.B) {
		signer, err := NewFastSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		domain := createTestDomain("Simple Benchmark", "1", 1)
		types := map[string][]Type{
			"Message": {{Name: "content", Type: "string"}},
		}
		message := Message{"content": "Hello, World!"}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignTypedDataFast(domain, types, "Message", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Benchmark cache effectiveness
func BenchmarkFastCacheEffectiveness(b *testing.B) {
	signer, err := NewFastSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Cache Benchmark", "1", 1)
	types := map[string][]Type{
		"Order": {
			{Name: "id", Type: "uint256"},
			{Name: "maker", Type: "address"},
			{Name: "taker", Type: "address"},
			{Name: "amount", Type: "uint256"},
			{Name: "price", Type: "uint256"},
		},
	}
	
	b.Run("First_Run", func(b *testing.B) {
		// Clear cache by creating new types
		uniqueTypes := map[string][]Type{
			"UniqueOrder": types["Order"],
		}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			message := Message{
				"id":     fmt.Sprintf("%d", i),
				"maker":  testAddress1,
				"taker":  testAddress2,
				"amount": "1000",
				"price":  "2000",
			}
			
			_, err := signer.SignTypedDataFast(domain, uniqueTypes, "UniqueOrder", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("Cached_Run", func(b *testing.B) {
		// Warm up cache
		message := Message{
			"id":     "0",
			"maker":  testAddress1,
			"taker":  testAddress2,
			"amount": "1000",
			"price":  "2000",
		}
		_, _ = signer.SignTypedDataFast(domain, types, "Order", message)
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			message := Message{
				"id":     fmt.Sprintf("%d", i),
				"maker":  testAddress1,
				"taker":  testAddress2,
				"amount": "1000",
				"price":  "2000",
			}
			
			_, err := signer.SignTypedDataFast(domain, types, "Order", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Benchmark SignMessage
func BenchmarkFastSignMessage(b *testing.B) {
	b.Run("Original", func(b *testing.B) {
		signer, err := NewSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		message := map[string]interface{}{
			"action": "transfer",
			"from":   testAddress1,
			"to":     testAddress2,
			"amount": "1000000000000000000",
		}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignMessage("Test App", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("Fast", func(b *testing.B) {
		signer, err := NewFastSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		message := map[string]interface{}{
			"action": "transfer",
			"from":   testAddress1,
			"to":     testAddress2,
			"amount": "1000000000000000000",
		}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignMessageFast("Test App", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Benchmark signature recovery
func BenchmarkFastRecovery(b *testing.B) {
	domain := createTestDomain("Recovery Benchmark", "1", 1)
	types := map[string][]Type{
		"Message": {{Name: "content", Type: "string"}},
	}
	message := Message{"content": "Test message"}
	
	// Create signatures
	signer, _ := NewSigner(testPrivateKey1, 1)
	sig, _ := signer.SignTypedData(domain, types, "Message", message)
	
	fastSigner, _ := NewFastSigner(testPrivateKey1, 1)
	fastSig, _ := fastSigner.SignTypedDataFast(domain, types, "Message", message)
	
	b.Run("Original", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := sig.Recover(domain, types, "Message", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("Fast", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := RecoverSignatureFast(fastSig, domain, types, "Message", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}