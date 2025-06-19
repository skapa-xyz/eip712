package eip712

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCyclicStructureDetection(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	domain := createTestDomain("Cyclic Test", "1", 1)
	
	t.Run("direct cycle", func(t *testing.T) {
		// Type A references itself
		types := map[string][]Type{
			"A": {
				{Name: "self", Type: "A"},
				{Name: "value", Type: "uint256"},
			},
		}
		
		message := Message{
			"self":  nil,
			"value": "123",
		}
		
		_, err := signer.SignTypedData(domain, types, "A", message)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cyclic reference detected")
	})
	
	t.Run("indirect cycle", func(t *testing.T) {
		// A -> B -> C -> A
		types := map[string][]Type{
			"A": {{Name: "b", Type: "B"}},
			"B": {{Name: "c", Type: "C"}},
			"C": {{Name: "a", Type: "A"}},
		}
		
		message := Message{
			"b": map[string]interface{}{
				"c": map[string]interface{}{
					"a": nil,
				},
			},
		}
		
		_, err := signer.SignTypedData(domain, types, "A", message)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cyclic reference detected")
	})
	
	t.Run("no cycle with shared reference", func(t *testing.T) {
		// A -> B, A -> C, B -> D, C -> D (diamond pattern, no cycle)
		types := map[string][]Type{
			"A": {
				{Name: "b", Type: "B"},
				{Name: "c", Type: "C"},
			},
			"B": {{Name: "d", Type: "D"}},
			"C": {{Name: "d", Type: "D"}},
			"D": {{Name: "value", Type: "uint256"}},
		}
		
		message := Message{
			"b": map[string]interface{}{
				"d": map[string]interface{}{"value": "1"},
			},
			"c": map[string]interface{}{
				"d": map[string]interface{}{"value": "2"},
			},
		}
		
		// This should not error
		sig, err := signer.SignTypedData(domain, types, "A", message)
		require.NoError(t, err)
		require.NotNil(t, sig)
	})
	
	t.Run("array of cyclic type", func(t *testing.T) {
		// Type with array that creates cycle
		types := map[string][]Type{
			"Node": {
				{Name: "children", Type: "Node[]"},
				{Name: "value", Type: "uint256"},
			},
		}
		
		message := Message{
			"children": []interface{}{},
			"value":    "123",
		}
		
		_, err := signer.SignTypedData(domain, types, "Node", message)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cyclic reference detected")
	})
}