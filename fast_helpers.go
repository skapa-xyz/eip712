package eip712

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Pre-defined common types to avoid repeated allocations
var (
	permitTypes = map[string][]Type{
		"Permit": {
			{Name: "owner", Type: "address"},
			{Name: "spender", Type: "address"},
			{Name: "value", Type: "uint256"},
			{Name: "nonce", Type: "uint256"},
			{Name: "deadline", Type: "uint256"},
		},
	}
	
	// Cache for inferred types to avoid repeated inference
	inferredTypesCache = &struct {
		sync.RWMutex
		cache map[string][]Type
	}{
		cache: make(map[string][]Type),
	}
)

// SignPermitFastOptimized is an optimized version of SignPermit with minimal allocations
func (s *FastSigner) SignPermitFastOptimized(
	tokenContract common.Address,
	tokenName string,
	tokenVersion string,
	spender common.Address,
	value *big.Int,
	nonce *big.Int,
	deadline *big.Int,
) (*Signature, error) {
	// Use a domain struct with minimal allocations
	domain := Domain{
		Name:              tokenName,
		Version:           tokenVersion,
		ChainID:           s.chainID,
		VerifyingContract: tokenContract,
	}
	
	// Pre-allocate message map with exact capacity
	message := make(Message, 5)
	message["owner"] = s.address.Hex()
	message["spender"] = spender.Hex()
	message["value"] = value.String()
	message["nonce"] = nonce.String()
	message["deadline"] = deadline.String()
	
	// Use pre-defined types (no allocation)
	return s.SignTypedDataFast(domain, permitTypes, "Permit", message)
}

// SignMessageFastOptimized signs a message with optimized type inference
func (s *FastSigner) SignMessageFastOptimized(appName string, message map[string]interface{}) (*Signature, error) {
	domain := Domain{
		Name:    appName,
		Version: "1",
		ChainID: s.chainID,
	}
	
	// Use optimized type inference
	types := map[string][]Type{
		"Message": inferTypesOptimizedWithCache(message),
	}
	
	return s.SignTypedDataFast(domain, types, "Message", message)
}

// inferTypesOptimizedWithCache is an optimized version with caching and fewer allocations
func inferTypesOptimizedWithCache(message map[string]interface{}) []Type {
	// Create a cache key from message structure
	cacheKey := generateTypesCacheKey(message)
	
	// Check cache first
	inferredTypesCache.RLock()
	if cached, ok := inferredTypesCache.cache[cacheKey]; ok {
		inferredTypesCache.RUnlock()
		return cached
	}
	inferredTypesCache.RUnlock()
	
	// Pre-allocate with exact capacity
	types := make([]Type, 0, len(message))
	
	// Pre-allocate keys array for sorting
	keys := make([]string, 0, len(message))
	for k := range message {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	
	// Infer types with optimized type detection
	for _, key := range keys {
		value := message[key]
		fieldType := inferTypeOptimizedSingle(value)
		types = append(types, Type{
			Name: key,
			Type: fieldType,
		})
	}
	
	// Cache the result
	inferredTypesCache.Lock()
	inferredTypesCache.cache[cacheKey] = types
	inferredTypesCache.Unlock()
	
	return types
}

// inferTypeOptimizedSingle infers type for a single value with optimizations
func inferTypeOptimizedSingle(value interface{}) string {
	switch v := value.(type) {
	case string:
		// Fast path for common cases
		if len(v) == 42 && v[0] == '0' && v[1] == 'x' {
			// Likely an address, do full check
			if common.IsHexAddress(v) {
				return "address"
			}
		}
		
		// Check if it's a number (optimize for common case)
		if len(v) > 0 && v[0] >= '0' && v[0] <= '9' {
			if _, ok := new(big.Int).SetString(v, 10); ok {
				return "uint256"
			}
		}
		
		return "string"
		
	case *big.Int:
		return "uint256"
		
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return "uint256"
		
	case bool:
		return "bool"
		
	case []byte:
		return fmt.Sprintf("bytes%d", len(v))
		
	case []interface{}:
		if len(v) > 0 {
			// Infer from first element
			return inferTypeOptimizedSingle(v[0]) + "[]"
		}
		return "string[]"
		
	default:
		return "string"
	}
}

// generateTypesCacheKey creates a deterministic cache key from message fields
func generateTypesCacheKey(message map[string]interface{}) string {
	// Use a buffer pool for key generation
	buf := bufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
	}()
	
	// Sort keys for deterministic ordering
	keys := make([]string, 0, len(message))
	for k := range message {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	
	// Build cache key from field names and types
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte('|')
		}
		buf.WriteString(key)
		buf.WriteByte(':')
		buf.WriteString(fmt.Sprintf("%T", message[key]))
	}
	
	return buf.String()
}

// RecoverFastOptimized is an optimized signature recovery
func RecoverFastOptimized(
	sig *Signature,
	domain Domain,
	types map[string][]Type,
	primaryType string,
	message Message,
) (common.Address, error) {
	// Use the fast encoder for recovery
	return RecoverSignatureFast(sig, domain, types, primaryType, message)
}

// VerifyFastOptimized is an optimized signature verification
func VerifyFastOptimized(
	sig *Signature,
	expectedSigner common.Address,
	domain Domain,
	types map[string][]Type,
	primaryType string,
	message Message,
) (bool, error) {
	// Use the fast verification
	return VerifySignatureFast(sig, expectedSigner, domain, types, primaryType, message)
}

// FastSignerOptimized extends FastSigner with additional optimizations
type FastSignerOptimized struct {
	*FastSigner
	// Pre-computed values
	addressHex string
}

// NewFastSignerOptimized creates an optimized fast signer
func NewFastSignerOptimized(privateKeyHex string, chainID int64) (*FastSignerOptimized, error) {
	signer, err := NewFastSigner(privateKeyHex, chainID)
	if err != nil {
		return nil, err
	}
	
	return &FastSignerOptimized{
		FastSigner: signer,
		addressHex: signer.address.Hex(), // Pre-compute address hex
	}, nil
}

// NewSignerOptimized creates a signer with minimal allocations
func NewSignerOptimized(privateKeyHex string, chainID int64) (*Signer, error) {
	// Remove 0x prefix if present without allocation
	if len(privateKeyHex) >= 2 && privateKeyHex[0] == '0' && privateKeyHex[1] == 'x' {
		privateKeyHex = privateKeyHex[2:]
	}
	
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	
	// Direct address computation
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("error casting public key to ECDSA")
	}
	
	return &Signer{
		privateKey: privateKey,
		address:    crypto.PubkeyToAddress(*publicKeyECDSA),
		chainID:    big.NewInt(chainID),
	}, nil
}