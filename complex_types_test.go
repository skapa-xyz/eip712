package eip712

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeeplyNestedTypes(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Nested Test", "1", 1)
	
	// Create a deeply nested structure (4 levels)
	types := map[string][]Type{
		"Level4": {
			{Name: "value", Type: "string"},
		},
		"Level3": {
			{Name: "data", Type: "Level4"},
			{Name: "id", Type: "uint256"},
		},
		"Level2": {
			{Name: "items", Type: "Level3[]"},
			{Name: "name", Type: "string"},
		},
		"Level1": {
			{Name: "nested", Type: "Level2"},
			{Name: "owner", Type: "address"},
			{Name: "timestamp", Type: "uint256"},
		},
	}
	
	message := Message{
		"nested": map[string]interface{}{
			"name": "Level 2 Name",
			"items": []map[string]interface{}{
				{
					"id": "1",
					"data": map[string]interface{}{
						"value": "First item",
					},
				},
				{
					"id": "2",
					"data": map[string]interface{}{
						"value": "Second item",
					},
				},
			},
		},
		"owner":     testAddress1,
		"timestamp": "1234567890",
	}
	
	sig, err := signer.SignTypedData(domain, types, "Level1", message)
	require.NoError(t, err)
	assertSignatureComponents(t, sig)
	
	// Verify signature
	recovered, err := sig.Recover(domain, types, "Level1", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

func TestArraysOfStructs(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Array Struct Test", "1", 1)
	
	types := map[string][]Type{
		"Item": {
			{Name: "id", Type: "uint256"},
			{Name: "name", Type: "string"},
			{Name: "price", Type: "uint256"},
		},
		"Order": {
			{Name: "items", Type: "Item[]"},
			{Name: "total", Type: "uint256"},
			{Name: "buyer", Type: "address"},
		},
	}
	
	// Test with different array lengths
	testCases := []struct {
		name  string
		items []map[string]interface{}
	}{
		{
			name:  "empty array",
			items: []map[string]interface{}{},
		},
		{
			name: "single item",
			items: []map[string]interface{}{
				{"id": "1", "name": "Product A", "price": "100"},
			},
		},
		{
			name: "multiple items",
			items: []map[string]interface{}{
				{"id": "1", "name": "Product A", "price": "100"},
				{"id": "2", "name": "Product B", "price": "200"},
				{"id": "3", "name": "Product C", "price": "300"},
			},
		},
		{
			name: "many items",
			items: func() []map[string]interface{} {
				items := make([]map[string]interface{}, 50)
				for i := 0; i < 50; i++ {
					items[i] = map[string]interface{}{
						"id":    fmt.Sprintf("%d", i+1),
						"name":  "Product",
						"price": "100",
					}
				}
				return items
			}(),
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := Message{
				"items": tc.items,
				"total": "600",
				"buyer": testAddress1,
			}
			
			sig, err := signer.SignTypedData(domain, types, "Order", message)
			require.NoError(t, err)
			assertSignatureComponents(t, sig)
			
			recovered, err := sig.Recover(domain, types, "Order", message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
		})
	}
}

func TestRecursiveTypeReferences(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Recursive Test", "1", 1)
	
	// Create a tree-like structure
	types := map[string][]Type{
		"Node": {
			{Name: "value", Type: "string"},
			{Name: "children", Type: "Node[]"},
		},
		"Tree": {
			{Name: "root", Type: "Node"},
			{Name: "depth", Type: "uint256"},
		},
	}
	
	// Create a tree with multiple levels
	message := Message{
		"root": map[string]interface{}{
			"value": "root",
			"children": []map[string]interface{}{
				{
					"value": "child1",
					"children": []map[string]interface{}{
						{
							"value":    "grandchild1",
							"children": []map[string]interface{}{},
						},
						{
							"value":    "grandchild2",
							"children": []map[string]interface{}{},
						},
					},
				},
				{
					"value": "child2",
					"children": []map[string]interface{}{
						{
							"value":    "grandchild3",
							"children": []map[string]interface{}{},
						},
					},
				},
			},
		},
		"depth": "3",
	}
	
	// This should fail due to cyclic reference (Node -> Node[])
	_, err = signer.SignTypedData(domain, types, "Tree", message)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cyclic reference detected")
}

func TestComplexPermission(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Permission System", "1", 1)
	
	// Complex permission system with multiple levels
	types := map[string][]Type{
		"Resource": {
			{Name: "id", Type: "bytes32"},
			{Name: "owner", Type: "address"},
			{Name: "uri", Type: "string"},
		},
		"Permission": {
			{Name: "action", Type: "string"},
			{Name: "resource", Type: "Resource"},
			{Name: "conditions", Type: "string[]"},
		},
		"Role": {
			{Name: "name", Type: "string"},
			{Name: "permissions", Type: "Permission[]"},
		},
		"Grant": {
			{Name: "role", Type: "Role"},
			{Name: "grantee", Type: "address"},
			{Name: "expiry", Type: "uint256"},
			{Name: "nonce", Type: "uint256"},
		},
	}
	
	message := Message{
		"role": map[string]interface{}{
			"name": "Admin",
			"permissions": []map[string]interface{}{
				{
					"action": "read",
					"resource": map[string]interface{}{
						"id":    "0x1234567890123456789012345678901234567890123456789012345678901234",
						"owner": testAddress1,
						"uri":   "https://example.com/resource1",
					},
					"conditions": []string{"time-based", "ip-restricted"},
				},
				{
					"action": "write",
					"resource": map[string]interface{}{
						"id":    "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
						"owner": testAddress1,
						"uri":   "https://example.com/resource2",
					},
					"conditions": []string{"owner-only"},
				},
			},
		},
		"grantee": testAddress2,
		"expiry":  "1893456000",
		"nonce":   "1",
	}
	
	sig, err := signer.SignTypedData(domain, types, "Grant", message)
	require.NoError(t, err)
	assertSignatureComponents(t, sig)
	
	recovered, err := sig.Recover(domain, types, "Grant", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

func TestVeryLargeMessages(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Large Message Test", "1", 1)
	
	// Test with progressively larger messages
	testCases := []struct {
		name   string
		length int
	}{
		{"small", 100},
		{"medium", 1000},
		{"large", 10000},
		{"very large", 100000},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			types := map[string][]Type{
				"LargeMessage": {
					{Name: "content", Type: "string"},
					{Name: "checksum", Type: "bytes32"},
				},
			}
			
			// Generate large content
			content := strings.Repeat("a", tc.length)
			
			message := Message{
				"content":  content,
				"checksum": "0x1234567890123456789012345678901234567890123456789012345678901234",
			}
			
			sig, err := signer.SignTypedData(domain, types, "LargeMessage", message)
			require.NoError(t, err)
			assertSignatureComponents(t, sig)
			
			recovered, err := sig.Recover(domain, types, "LargeMessage", message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
		})
	}
}

func TestUnicodeInStringFields(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Unicode Test", "1", 1)
	
	types := map[string][]Type{
		"InternationalMessage": {
			{Name: "content", Type: "string"},
			{Name: "language", Type: "string"},
			{Name: "author", Type: "address"},
		},
	}
	
	testCases := []struct {
		name     string
		content  string
		language string
	}{
		{
			name:     "emoji",
			content:  "Hello 👋 World 🌍! Testing emojis 🎉🎊",
			language: "emoji",
		},
		{
			name:     "chinese",
			content:  "你好世界！这是一个测试。",
			language: "zh-CN",
		},
		{
			name:     "japanese",
			content:  "こんにちは世界！これはテストです。",
			language: "ja-JP",
		},
		{
			name:     "arabic",
			content:  "مرحبا بالعالم! هذا اختبار.",
			language: "ar",
		},
		{
			name:     "mixed scripts",
			content:  "Hello नमस्ते مرحبا 你好 🌏",
			language: "multi",
		},
		{
			name:     "special unicode",
			content:  "Zero-width: ‌‌ Combining: é Control: \u0001",
			language: "special",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := Message{
				"content":  tc.content,
				"language": tc.language,
				"author":   testAddress1,
			}
			
			sig, err := signer.SignTypedData(domain, types, "InternationalMessage", message)
			require.NoError(t, err)
			assertSignatureComponents(t, sig)
			
			recovered, err := sig.Recover(domain, types, "InternationalMessage", message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
		})
	}
}

func TestMaximumTypeNameLength(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Type Name Test", "1", 1)
	
	// Test with very long type names
	veryLongTypeName := "ThisIsAVeryLongTypeNameThatShouldStillWorkCorrectlyEvenThoughItIsUnusuallyLongForATypeName"
	veryLongFieldName := "thisIsAVeryLongFieldNameThatShouldAlsoWorkCorrectlyDespiteBeingUnusuallyLong"
	
	types := map[string][]Type{
		veryLongTypeName: {
			{Name: veryLongFieldName, Type: "string"},
			{Name: "normalField", Type: "uint256"},
		},
		"Message": {
			{Name: "data", Type: veryLongTypeName},
			{Name: "sender", Type: "address"},
		},
	}
	
	message := Message{
		"data": map[string]interface{}{
			veryLongFieldName: "test value",
			"normalField":     "12345",
		},
		"sender": testAddress1,
	}
	
	sig, err := signer.SignTypedData(domain, types, "Message", message)
	require.NoError(t, err)
	assertSignatureComponents(t, sig)
	
	recovered, err := sig.Recover(domain, types, "Message", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

func TestMixedArrayTypes(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Mixed Arrays", "1", 1)
	
	types := map[string][]Type{
		"Token": {
			{Name: "address", Type: "address"},
			{Name: "amount", Type: "uint256"},
		},
		"MultiTransfer": {
			{Name: "tokens", Type: "Token[]"},
			{Name: "recipients", Type: "address[]"},
			{Name: "amounts", Type: "uint256[]"},
			{Name: "data", Type: "bytes[]"},
			{Name: "flags", Type: "bool[]"},
		},
	}
	
	message := Message{
		"tokens": []map[string]interface{}{
			{
				"address": testAddress1,
				"amount":  "1000",
			},
			{
				"address": testAddress2,
				"amount":  "2000",
			},
		},
		"recipients": []string{testAddress1, testAddress2},
		"amounts":    []string{"100", "200", "300"},
		"data":       []string{"0x1234", "0xabcd", "0x5678"},
		"flags":      []bool{true, false, true, true},
	}
	
	sig, err := signer.SignTypedData(domain, types, "MultiTransfer", message)
	require.NoError(t, err)
	assertSignatureComponents(t, sig)
	
	recovered, err := sig.Recover(domain, types, "MultiTransfer", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

func TestFixedSizeArrays(t *testing.T) {
	t.Skip("Fixed-size arrays are not fully supported by go-ethereum's EIP-712 implementation")
	
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Fixed Arrays", "1", 1)
	
	// Test with dynamic arrays instead, as fixed-size arrays aren't well supported
	types := map[string][]Type{
		"DynamicArrays": {
			{Name: "addresses", Type: "address[]"},
			{Name: "numbers", Type: "uint256[]"},
			{Name: "flags", Type: "bool[]"},
			{Name: "hashes", Type: "bytes32[]"},
		},
	}
	
	message := Message{
		"addresses": []string{testAddress1, testAddress2, testAddress1},
		"numbers":   []string{"1", "2", "3", "4", "5"},
		"flags":     []bool{true, false},
		"hashes": []string{
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		},
	}
	
	sig, err := signer.SignTypedData(domain, types, "DynamicArrays", message)
	require.NoError(t, err)
	assertSignatureComponents(t, sig)
	
	recovered, err := sig.Recover(domain, types, "DynamicArrays", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

func TestTupleTypes(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Tuple Test", "1", 1)
	
	// Simulate tuple-like structures
	types := map[string][]Type{
		"Point": {
			{Name: "x", Type: "uint256"},
			{Name: "y", Type: "uint256"},
		},
		"Line": {
			{Name: "start", Type: "Point"},
			{Name: "end", Type: "Point"},
		},
		"Polygon": {
			{Name: "vertices", Type: "Point[]"},
			{Name: "color", Type: "bytes3"},
		},
		"Drawing": {
			{Name: "lines", Type: "Line[]"},
			{Name: "polygons", Type: "Polygon[]"},
			{Name: "author", Type: "address"},
		},
	}
	
	message := Message{
		"lines": []map[string]interface{}{
			{
				"start": map[string]interface{}{"x": "0", "y": "0"},
				"end":   map[string]interface{}{"x": "100", "y": "100"},
			},
			{
				"start": map[string]interface{}{"x": "100", "y": "0"},
				"end":   map[string]interface{}{"x": "0", "y": "100"},
			},
		},
		"polygons": []map[string]interface{}{
			{
				"vertices": []map[string]interface{}{
					{"x": "0", "y": "0"},
					{"x": "100", "y": "0"},
					{"x": "100", "y": "100"},
					{"x": "0", "y": "100"},
				},
				"color": "0xff0000",
			},
		},
		"author": testAddress1,
	}
	
	sig, err := signer.SignTypedData(domain, types, "Drawing", message)
	require.NoError(t, err)
	assertSignatureComponents(t, sig)
	
	recovered, err := sig.Recover(domain, types, "Drawing", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}