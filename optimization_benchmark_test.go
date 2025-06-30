package eip712

import (
	"fmt"
	"strings"
	"testing"
)

// Benchmark optimized vs original for large arrays
func BenchmarkOptimizedVsOriginalLargeArrays(b *testing.B) {
	arraySizes := []int{100, 500, 1000}
	
	for _, size := range arraySizes {
		b.Run(fmt.Sprintf("Original_ArraySize_%d", size), func(b *testing.B) {
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
		
		b.Run(fmt.Sprintf("Optimized_ArraySize_%d", size), func(b *testing.B) {
			signer, err := NewOptimizedSigner(testPrivateKey1, 1)
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
			
			// Pre-compute types for better performance
			_ = signer.PrecomputeTypes(types)
			
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
				_, err := signer.SignTypedDataOptimized(domain, types, "Message", message)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark optimized vs original for deep nesting
func BenchmarkOptimizedVsOriginalDeepNesting(b *testing.B) {
	b.Run("Original_DeepNesting", func(b *testing.B) {
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
	})
	
	b.Run("Optimized_DeepNesting", func(b *testing.B) {
		signer, err := NewOptimizedSigner(testPrivateKey1, 1)
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
		
		// Pre-compute types
		_ = signer.PrecomputeTypes(types)
		
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
			_, err := signer.SignTypedDataOptimized(domain, types, "Level1", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Benchmark multiple signatures with same types (cache effectiveness)
func BenchmarkCacheEffectiveness(b *testing.B) {
	b.Run("Original_MultipleSignatures", func(b *testing.B) {
		signer, err := NewSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		domain := createTestDomain("Cache Test", "1", 1)
		types := map[string][]Type{
			"Order": {
				{Name: "id", Type: "uint256"},
				{Name: "maker", Type: "address"},
				{Name: "taker", Type: "address"},
				{Name: "amount", Type: "uint256"},
				{Name: "price", Type: "uint256"},
			},
		}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			message := Message{
				"id":     fmt.Sprintf("%d", i),
				"maker":  testAddress1,
				"taker":  testAddress2,
				"amount": "1000000000000000000",
				"price":  "2000",
			}
			
			_, err := signer.SignTypedData(domain, types, "Order", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("Optimized_MultipleSignatures", func(b *testing.B) {
		signer, err := NewOptimizedSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		domain := createTestDomain("Cache Test", "1", 1)
		types := map[string][]Type{
			"Order": {
				{Name: "id", Type: "uint256"},
				{Name: "maker", Type: "address"},
				{Name: "taker", Type: "address"},
				{Name: "amount", Type: "uint256"},
				{Name: "price", Type: "uint256"},
			},
		}
		
		// Pre-compute types
		_ = signer.PrecomputeTypes(types)
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			message := Message{
				"id":     fmt.Sprintf("%d", i),
				"maker":  testAddress1,
				"taker":  testAddress2,
				"amount": "1000000000000000000",
				"price":  "2000",
			}
			
			_, err := signer.SignTypedDataOptimized(domain, types, "Order", message)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Benchmark SignMessage optimizations
func BenchmarkOptimizedSignMessage(b *testing.B) {
	messages := []map[string]interface{}{
		{
			"action": "transfer",
			"from":   testAddress1,
			"to":     testAddress2,
			"amount": "1000000000000000000",
		},
		{
			"type":      "order",
			"maker":     testAddress1,
			"taker":     testAddress2,
			"baseToken": testAddress1,
			"quoteToken": testAddress2,
			"amount":     "1000",
			"price":      "2000",
		},
		{
			"text": strings.Repeat("Hello World! ", 100),
			"user": testAddress1,
			"timestamp": "1234567890",
		},
	}
	
	b.Run("Original", func(b *testing.B) {
		signer, err := NewSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignMessage("Benchmark App", messages[i%len(messages)])
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("Optimized", func(b *testing.B) {
		signer, err := NewOptimizedSigner(testPrivateKey1, 1)
		if err != nil {
			b.Fatal(err)
		}
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := signer.SignMessageOptimized("Benchmark App", messages[i%len(messages)])
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}