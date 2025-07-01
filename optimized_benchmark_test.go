package eip712

import (
	"fmt"
	"testing"
)

// Optimized benchmark for deeply nested types
func BenchmarkDeeplyNestedTypesFast(b *testing.B) {
	signer, err := NewFastSigner(testPrivateKey1, 1)
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
	
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedDataFast(domain, types, "Level1", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Optimized benchmark for complex types (Mail example)
func BenchmarkComplexTypesFast(b *testing.B) {
	signer, err := NewFastSigner(testPrivateKey1, 1)
	if err != nil {
		b.Fatal(err)
	}
	
	domain := createTestDomain("Complex Benchmark", "1", 1)
	types := createMailTypes()
	message := createMailMessage("Alice", testAddress1, "Bob", testAddress2, "Benchmark mail")
	
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedDataFast(domain, types, "Mail", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Optimized benchmark for array types
func BenchmarkArrayTypesFast(b *testing.B) {
	signer, err := NewFastSigner(testPrivateKey1, 1)
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
	
	// Create arrays of 100 elements
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
	
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signer.SignTypedDataFast(domain, types, "Message", message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Comparison benchmark for all three cases
func BenchmarkWorstPerformersComparison(b *testing.B) {
	// Test deeply nested types
	b.Run("DeeplyNested_Original", func(b *testing.B) {
		signer, _ := NewSigner(testPrivateKey1, 1)
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
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignTypedData(domain, types, "Level1", message)
		}
	})
	
	b.Run("DeeplyNested_Fast", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
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
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignTypedDataFast(domain, types, "Level1", message)
		}
	})
	
	// Test complex types
	b.Run("ComplexTypes_Original", func(b *testing.B) {
		signer, _ := NewSigner(testPrivateKey1, 1)
		domain := createTestDomain("Complex Benchmark", "1", 1)
		types := createMailTypes()
		message := createMailMessage("Alice", testAddress1, "Bob", testAddress2, "Benchmark mail")
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignTypedData(domain, types, "Mail", message)
		}
	})
	
	b.Run("ComplexTypes_Fast", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		domain := createTestDomain("Complex Benchmark", "1", 1)
		types := createMailTypes()
		message := createMailMessage("Alice", testAddress1, "Bob", testAddress2, "Benchmark mail")
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignTypedDataFast(domain, types, "Mail", message)
		}
	})
	
	// Test array types
	b.Run("ArrayTypes_Original", func(b *testing.B) {
		signer, _ := NewSigner(testPrivateKey1, 1)
		domain := createTestDomain("Array Benchmark", "1", 1)
		types := map[string][]Type{
			"Message": {
				{Name: "items", Type: "string[]"},
				{Name: "values", Type: "uint256[]"},
			},
		}
		
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
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignTypedData(domain, types, "Message", message)
		}
	})
	
	b.Run("ArrayTypes_Fast", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		domain := createTestDomain("Array Benchmark", "1", 1)
		types := map[string][]Type{
			"Message": {
				{Name: "items", Type: "string[]"},
				{Name: "values", Type: "uint256[]"},
			},
		}
		
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
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignTypedDataFast(domain, types, "Message", message)
		}
	})
}

// Benchmark with pre-warmed cache
func BenchmarkWithPrewarmedCache(b *testing.B) {
	b.Run("ComplexTypes_PreWarmed", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		domain := createTestDomain("Complex Benchmark", "1", 1)
		types := createMailTypes()
		message := createMailMessage("Alice", testAddress1, "Bob", testAddress2, "Benchmark mail")
		
		// Pre-warm the cache
		_, _ = signer.SignTypedDataFast(domain, types, "Mail", message)
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignTypedDataFast(domain, types, "Mail", message)
		}
	})
	
	b.Run("ArrayTypes_PreWarmed", func(b *testing.B) {
		signer, _ := NewFastSigner(testPrivateKey1, 1)
		domain := createTestDomain("Array Benchmark", "1", 1)
		types := map[string][]Type{
			"Message": {
				{Name: "items", Type: "string[]"},
				{Name: "values", Type: "uint256[]"},
			},
		}
		
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
		
		// Pre-warm the cache
		_, _ = signer.SignTypedDataFast(domain, types, "Message", message)
		
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = signer.SignTypedDataFast(domain, types, "Message", message)
		}
	})
}

// Benchmark to show improvement percentages
func BenchmarkImprovementSummary(b *testing.B) {
	// Run a smaller set to calculate improvement percentages
	scenarios := []struct {
		name      string
		setupFunc func() (Domain, map[string][]Type, string, Message)
	}{
		{
			name: "SimpleMessage",
			setupFunc: func() (Domain, map[string][]Type, string, Message) {
				return createTestDomain("Test", "1", 1),
					map[string][]Type{"Message": {{Name: "content", Type: "string"}}},
					"Message",
					Message{"content": "Hello"}
			},
		},
		{
			name: "ComplexNested",
			setupFunc: func() (Domain, map[string][]Type, string, Message) {
				return createTestDomain("Complex", "1", 1),
					createMailTypes(),
					"Mail",
					createMailMessage("Alice", testAddress1, "Bob", testAddress2, "Test")
			},
		},
		{
			name: "LargeArray",
			setupFunc: func() (Domain, map[string][]Type, string, Message) {
				items := make([]string, 100)
				for i := range items {
					items[i] = fmt.Sprintf("item%d", i)
				}
				return createTestDomain("Array", "1", 1),
					map[string][]Type{"Data": {{Name: "items", Type: "string[]"}}},
					"Data",
					Message{"items": items}
			},
		},
	}
	
	for _, scenario := range scenarios {
		domain, types, primaryType, message := scenario.setupFunc()
		
		b.Run(scenario.name+"_Original", func(b *testing.B) {
			signer, _ := NewSigner(testPrivateKey1, 1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = signer.SignTypedData(domain, types, primaryType, message)
			}
		})
		
		b.Run(scenario.name+"_Fast", func(b *testing.B) {
			signer, _ := NewFastSigner(testPrivateKey1, 1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = signer.SignTypedDataFast(domain, types, primaryType, message)
			}
		})
	}
}