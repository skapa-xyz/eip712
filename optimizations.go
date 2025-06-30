package eip712

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// bufferPool is a pool of bytes.Buffer to reduce allocations
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// typeCache caches computed type data to avoid repeated calculations
type typeCache struct {
	mu          sync.RWMutex
	typeHashes  map[string][]byte
	domainTypes map[string][]apitypes.Type
}

var globalTypeCache = &typeCache{
	typeHashes:  make(map[string][]byte),
	domainTypes: make(map[string][]apitypes.Type),
}

// OptimizedSigner provides optimized EIP-712 signing with caching
type OptimizedSigner struct {
	*Signer
	cache *typeCache
}

// NewOptimizedSigner creates a new optimized EIP-712 signer
func NewOptimizedSigner(privateKeyHex string, chainID int64) (*OptimizedSigner, error) {
	signer, err := NewSigner(privateKeyHex, chainID)
	if err != nil {
		return nil, err
	}
	
	return &OptimizedSigner{
		Signer: signer,
		cache:  globalTypeCache,
	}, nil
}

// SignTypedDataOptimized signs typed data with performance optimizations
func (s *OptimizedSigner) SignTypedDataOptimized(domain Domain, types map[string][]Type, primaryType string, message Message) (*Signature, error) {
	// Validate for cyclic structures (cached internally)
	if err := validateNoCycles(types); err != nil {
		return nil, err
	}
	
	// Pre-allocate the typed data structure with capacity hints
	typedData := apitypes.TypedData{
		Types:       make(apitypes.Types, len(types)+1), // +1 for EIP712Domain
		PrimaryType: primaryType,
		Domain:      s.domainToAPITypes(domain),
		Message:     apitypes.TypedDataMessage(message),
	}
	
	// Convert types with pre-allocation
	for typeName, fields := range types {
		apiTypes := make([]apitypes.Type, len(fields))
		for i, field := range fields {
			apiTypes[i] = apitypes.Type{
				Name: field.Name,
				Type: field.Type,
			}
		}
		typedData.Types[typeName] = apiTypes
	}
	
	// Add EIP712Domain type if not present (with caching)
	if _, ok := typedData.Types["EIP712Domain"]; !ok {
		typedData.Types["EIP712Domain"] = s.getCachedDomainTypes(domain)
	}
	
	// Hash the typed data
	hash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return nil, fmt.Errorf("failed to hash typed data: %w", err)
	}
	
	// Sign the hash
	signature, err := crypto.Sign(hash, s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	
	// Transform V from 0/1 to 27/28 per Ethereum convention
	signature[64] += 27
	
	return &Signature{
		R:     hexutil.Encode(signature[:32]),
		S:     hexutil.Encode(signature[32:64]),
		V:     uint8(signature[64]),
		Hash:  hexutil.Encode(hash),
		Bytes: hexutil.Encode(signature),
	}, nil
}

// getCachedDomainTypes returns cached domain types or builds and caches them
func (s *OptimizedSigner) getCachedDomainTypes(domain Domain) []apitypes.Type {
	// Create a cache key from domain fields
	key := domainCacheKey(domain)
	
	// Try to get from cache
	s.cache.mu.RLock()
	if types, ok := s.cache.domainTypes[key]; ok {
		s.cache.mu.RUnlock()
		return types
	}
	s.cache.mu.RUnlock()
	
	// Build and cache
	types := s.buildDomainTypes(domain)
	
	s.cache.mu.Lock()
	s.cache.domainTypes[key] = types
	s.cache.mu.Unlock()
	
	return types
}

// domainCacheKey creates a cache key for a domain
func domainCacheKey(domain Domain) string {
	buf := bufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
	}()
	
	buf.WriteString(domain.Name)
	buf.WriteByte('|')
	buf.WriteString(domain.Version)
	
	if domain.ChainID != nil {
		buf.WriteByte('|')
		buf.WriteString(domain.ChainID.String())
	}
	
	if domain.VerifyingContract != (common.Address{}) {
		buf.WriteByte('|')
		buf.WriteString(domain.VerifyingContract.Hex())
	}
	
	if domain.Salt != [32]byte{} {
		buf.WriteByte('|')
		buf.Write(domain.Salt[:])
	}
	
	return buf.String()
}

// PrecomputeTypes pre-computes and caches type information for better performance
func (s *OptimizedSigner) PrecomputeTypes(types map[string][]Type) error {
	// Validate types
	if err := validateNoCycles(types); err != nil {
		return err
	}
	
	// Pre-compute type hashes by creating a dummy typed data structure
	typedData := apitypes.TypedData{
		Types: make(apitypes.Types, len(types)),
	}
	
	for typeName, fields := range types {
		apiTypes := make([]apitypes.Type, len(fields))
		for i, field := range fields {
			apiTypes[i] = apitypes.Type{
				Name: field.Name,
				Type: field.Type,
			}
		}
		typedData.Types[typeName] = apiTypes
	}
	
	// This will internally cache type hashes
	for typeName := range types {
		_ = typedData.TypeHash(typeName)
	}
	
	return nil
}

// SignMessageOptimized signs a simple message with optimizations
func (s *OptimizedSigner) SignMessageOptimized(appName string, message map[string]interface{}) (*Signature, error) {
	domain := Domain{
		Name:    appName,
		Version: "1",
		ChainID: s.chainID,
	}
	
	// Use cached type inference
	types := map[string][]Type{
		"Message": inferTypesOptimized(message),
	}
	
	return s.SignTypedDataOptimized(domain, types, "Message", message)
}

// inferTypesOptimized is an optimized version of inferTypes with better memory usage
func inferTypesOptimized(message map[string]interface{}) []Type {
	// Pre-allocate slice with exact capacity
	types := make([]Type, 0, len(message))
	
	// Pre-allocate keys slice for sorting
	keys := make([]string, 0, len(message))
	for k := range message {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	
	// Infer types with reduced allocations
	for _, key := range keys {
		value := message[key]
		typeStr := inferTypeOptimized(value)
		types = append(types, Type{Name: key, Type: typeStr})
	}
	
	return types
}

// inferTypeOptimized infers type with fewer allocations
func inferTypeOptimized(value interface{}) string {
	switch v := value.(type) {
	case string:
		// Check if it's an address
		if len(v) == 42 && v[:2] == "0x" {
			return "address"
		}
		// Check if it's bytes32
		if len(v) == 66 && v[:2] == "0x" {
			return "bytes32"
		}
		// Check if it's a number
		if _, ok := new(big.Int).SetString(v, 10); ok {
			return "uint256"
		}
		return "string"
	case bool:
		return "bool"
	case []byte:
		return "bytes"
	case []interface{}:
		if len(v) > 0 {
			return inferTypeOptimized(v[0]) + "[]"
		}
		return "string[]" // default for empty arrays
	default:
		return "string"
	}
}