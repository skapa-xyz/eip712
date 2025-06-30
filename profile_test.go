package eip712

import (
	"runtime/pprof"
	"testing"
	"os"
)

func TestProfileArrays(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling in short mode")
	}
	
	// Run array benchmark
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		t.Fatal(err)
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
	
	// Run multiple iterations for profiling
	for i := 0; i < 1000; i++ {
		_, err := signer.SignTypedData(domain, types, "Message", message)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestProfileNestedTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling in short mode")
	}
	
	// Create memory profile
	f, err := os.Create("mem_nested.prof")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	
	signer, err := NewSigner(testPrivateKey1, 1)
	if err != nil {
		t.Fatal(err)
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
	
	// Run multiple iterations
	for i := 0; i < 1000; i++ {
		_, err := signer.SignTypedData(domain, types, "Level1", message)
		if err != nil {
			t.Fatal(err)
		}
	}
	
	// Write heap profile
	if err := pprof.WriteHeapProfile(f); err != nil {
		t.Fatal(err)
	}
}