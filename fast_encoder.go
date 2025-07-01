package eip712

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// Cache structures for performance
type encoderCache struct {
	mu           sync.RWMutex
	typeHashes   map[string][]byte
	encodedTypes map[string]string
	dependencies map[string][]string
}

var globalEncoderCache = &encoderCache{
	typeHashes:   make(map[string][]byte),
	encodedTypes: make(map[string]string),
	dependencies: make(map[string][]string),
}

// Buffer pool to reduce allocations
var encoderBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// FastTypedDataEncoder is an optimized EIP-712 encoder
type FastTypedDataEncoder struct {
	Types       map[string][]Type
	PrimaryType string
	Domain      Domain
	Message     Message
	cache       *encoderCache
}

// NewFastTypedDataEncoder creates a new optimized encoder
func NewFastTypedDataEncoder(domain Domain, types map[string][]Type, primaryType string, message Message) *FastTypedDataEncoder {
	return &FastTypedDataEncoder{
		Types:       types,
		PrimaryType: primaryType,
		Domain:      domain,
		Message:     message,
		cache:       globalEncoderCache,
	}
}

// Hash computes the EIP-712 hash of the typed data
func (e *FastTypedDataEncoder) Hash() ([]byte, error) {
	// Validate types
	if err := e.validate(); err != nil {
		return nil, err
	}
	
	// Build domain types if not present
	if _, ok := e.Types["EIP712Domain"]; !ok {
		e.Types["EIP712Domain"] = e.buildDomainTypes()
	}
	
	// Hash domain
	domainSeparator, err := e.hashStruct("EIP712Domain", e.domainToMap())
	if err != nil {
		return nil, fmt.Errorf("failed to hash domain: %w", err)
	}
	
	// Hash message
	messageHash, err := e.hashStruct(e.PrimaryType, e.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to hash message: %w", err)
	}
	
	// Combine according to EIP-712
	rawData := []byte{0x19, 0x01}
	rawData = append(rawData, domainSeparator...)
	rawData = append(rawData, messageHash...)
	
	return crypto.Keccak256(rawData), nil
}

// hashStruct computes the hash of a struct
func (e *FastTypedDataEncoder) hashStruct(primaryType string, data map[string]interface{}) ([]byte, error) {
	encoded, err := e.encodeData(primaryType, data)
	if err != nil {
		return nil, err
	}
	return crypto.Keccak256(encoded), nil
}

// encodeData encodes the data according to EIP-712
func (e *FastTypedDataEncoder) encodeData(primaryType string, data map[string]interface{}) ([]byte, error) {
	// Get buffer from pool
	buf := encoderBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		encoderBufferPool.Put(buf)
	}()
	
	// Add type hash
	typeHash, err := e.typeHash(primaryType)
	if err != nil {
		return nil, err
	}
	buf.Write(typeHash)
	
	// Get fields for this type
	fields, ok := e.Types[primaryType]
	if !ok {
		return nil, fmt.Errorf("type %s not found", primaryType)
	}
	
	// Encode each field
	for _, field := range fields {
		value, exists := data[field.Name]
		if !exists {
			return nil, fmt.Errorf("field %s not found in data", field.Name)
		}
		
		encoded, err := e.encodeValue(field.Type, value)
		if err != nil {
			return nil, fmt.Errorf("failed to encode field %s: %w", field.Name, err)
		}
		buf.Write(encoded)
	}
	
	// Return a copy to avoid issues with buffer reuse
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// encodeValue encodes a single value
func (e *FastTypedDataEncoder) encodeValue(fieldType string, value interface{}) ([]byte, error) {
	// Handle arrays
	if strings.HasSuffix(fieldType, "[]") {
		return e.encodeArray(fieldType, value)
	}
	
	// Handle structs
	if _, ok := e.Types[fieldType]; ok {
		return e.encodeStruct(fieldType, value)
	}
	
	// Handle primitives
	return e.encodePrimitive(fieldType, value)
}

// encodeArray encodes an array value with optimizations
func (e *FastTypedDataEncoder) encodeArray(fieldType string, value interface{}) ([]byte, error) {
	// Get element type
	elementType := strings.TrimSuffix(fieldType, "[]")
	
	// Convert to slice
	slice := reflect.ValueOf(value)
	if slice.Kind() != reflect.Slice {
		return nil, fmt.Errorf("expected slice for array type %s", fieldType)
	}
	
	// Pre-allocate buffer for better performance
	buf := encoderBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		encoderBufferPool.Put(buf)
	}()
	
	// For large arrays, pre-allocate capacity
	if slice.Len() > 100 {
		buf.Grow(slice.Len() * 32) // Assume ~32 bytes per element
	}
	
	// Encode each element
	for i := 0; i < slice.Len(); i++ {
		elem := slice.Index(i).Interface()
		
		// Handle string elements in arrays specially
		if elementType == "string" {
			if str, ok := elem.(string); ok {
				hash := crypto.Keccak256([]byte(str))
				buf.Write(hash)
				continue
			}
		}
		
		encoded, err := e.encodeValue(elementType, elem)
		if err != nil {
			return nil, fmt.Errorf("failed to encode array element %d: %w", i, err)
		}
		buf.Write(encoded)
	}
	
	// Hash the concatenated array data
	return crypto.Keccak256(buf.Bytes()), nil
}

// encodeStruct encodes a struct value
func (e *FastTypedDataEncoder) encodeStruct(fieldType string, value interface{}) ([]byte, error) {
	// Convert to map
	var data map[string]interface{}
	switch v := value.(type) {
	case map[string]interface{}:
		data = v
	case Message:
		data = v
	default:
		return nil, fmt.Errorf("invalid struct value type: %T", value)
	}
	
	// Hash the struct
	return e.hashStruct(fieldType, data)
}

// encodePrimitive encodes primitive values with optimizations
func (e *FastTypedDataEncoder) encodePrimitive(fieldType string, value interface{}) ([]byte, error) {
	result := make([]byte, 32)
	
	switch fieldType {
	case "address":
		addr, err := toAddress(value)
		if err != nil {
			return nil, err
		}
		copy(result[12:], addr.Bytes())
		return result, nil
		
	case "bool":
		if toBool(value) {
			result[31] = 1
		}
		return result, nil
		
	case "string":
		str := toString(value)
		return crypto.Keccak256([]byte(str)), nil
		
	case "bytes":
		b, err := toBytes(value)
		if err != nil {
			return nil, err
		}
		return crypto.Keccak256(b), nil
		
	default:
		// Handle bytes32, uint256, int256, etc.
		if strings.HasPrefix(fieldType, "bytes") {
			return e.encodeFixedBytes(fieldType, value)
		}
		if strings.HasPrefix(fieldType, "uint") || strings.HasPrefix(fieldType, "int") {
			return e.encodeInteger(fieldType, value)
		}
		return nil, fmt.Errorf("unsupported type: %s", fieldType)
	}
}

// encodeFixedBytes encodes fixed-size byte arrays
func (e *FastTypedDataEncoder) encodeFixedBytes(fieldType string, value interface{}) ([]byte, error) {
	size := 32 // default to bytes32
	if fieldType != "bytes32" {
		// Parse size from type
		matches := regexp.MustCompile(`^bytes(\d+)$`).FindStringSubmatch(fieldType)
		if len(matches) != 2 {
			return nil, fmt.Errorf("invalid bytes type: %s", fieldType)
		}
		var err error
		size, err = strconv.Atoi(matches[1])
		if err != nil || size < 1 || size > 32 {
			return nil, fmt.Errorf("invalid bytes size: %s", matches[1])
		}
	}
	
	b, err := toBytes(value)
	if err != nil {
		return nil, err
	}
	
	if len(b) > size {
		return nil, fmt.Errorf("bytes too long for %s", fieldType)
	}
	
	// Pad to 32 bytes
	result := make([]byte, 32)
	copy(result, b)
	return result, nil
}

// encodeInteger encodes integer values
func (e *FastTypedDataEncoder) encodeInteger(fieldType string, value interface{}) ([]byte, error) {
	n, err := toBigInt(value)
	if err != nil {
		return nil, err
	}
	
	// Check bounds based on type
	if strings.HasPrefix(fieldType, "uint") {
		if n.Sign() < 0 {
			return nil, fmt.Errorf("negative value for unsigned type %s", fieldType)
		}
	}
	
	// Convert to 32-byte array
	return math.U256Bytes(n), nil
}

// typeHash returns the cached type hash or computes it
func (e *FastTypedDataEncoder) typeHash(typeName string) ([]byte, error) {
	// Check cache first
	e.cache.mu.RLock()
	if hash, ok := e.cache.typeHashes[typeName]; ok {
		e.cache.mu.RUnlock()
		return hash, nil
	}
	e.cache.mu.RUnlock()
	
	// Compute type hash
	encoded, err := e.encodeType(typeName)
	if err != nil {
		return nil, err
	}
	
	hash := crypto.Keccak256([]byte(encoded))
	
	// Cache the result
	e.cache.mu.Lock()
	e.cache.typeHashes[typeName] = hash
	e.cache.mu.Unlock()
	
	return hash, nil
}

// encodeType encodes the type definition
func (e *FastTypedDataEncoder) encodeType(typeName string) (string, error) {
	// Check cache first
	e.cache.mu.RLock()
	if encoded, ok := e.cache.encodedTypes[typeName]; ok {
		e.cache.mu.RUnlock()
		return encoded, nil
	}
	e.cache.mu.RUnlock()
	
	// Get dependencies
	deps := e.dependencies(typeName)
	
	// Build encoded type
	var parts []string
	
	// Primary type first
	fields, ok := e.Types[typeName]
	if !ok {
		return "", fmt.Errorf("type %s not found", typeName)
	}
	
	fieldParts := make([]string, len(fields))
	for i, field := range fields {
		fieldParts[i] = field.Type + " " + field.Name
	}
	parts = append(parts, typeName+"("+strings.Join(fieldParts, ",")+")")
	
	// Then dependencies in alphabetical order
	for _, dep := range deps {
		if dep == typeName {
			continue
		}
		fields := e.Types[dep]
		fieldParts := make([]string, len(fields))
		for i, field := range fields {
			fieldParts[i] = field.Type + " " + field.Name
		}
		parts = append(parts, dep+"("+strings.Join(fieldParts, ",")+")")
	}
	
	encoded := strings.Join(parts, "")
	
	// Cache the result
	e.cache.mu.Lock()
	e.cache.encodedTypes[typeName] = encoded
	e.cache.mu.Unlock()
	
	return encoded, nil
}

// dependencies returns sorted dependencies with caching
func (e *FastTypedDataEncoder) dependencies(typeName string) []string {
	// Check cache first
	e.cache.mu.RLock()
	if deps, ok := e.cache.dependencies[typeName]; ok {
		e.cache.mu.RUnlock()
		return deps
	}
	e.cache.mu.RUnlock()
	
	// Compute dependencies
	deps := make(map[string]bool)
	e.findDependencies(typeName, deps)
	
	// Convert to sorted slice
	result := make([]string, 0, len(deps))
	for dep := range deps {
		result = append(result, dep)
	}
	sort.Strings(result)
	
	// Cache the result
	e.cache.mu.Lock()
	e.cache.dependencies[typeName] = result
	e.cache.mu.Unlock()
	
	return result
}

// findDependencies recursively finds type dependencies
func (e *FastTypedDataEncoder) findDependencies(typeName string, deps map[string]bool) {
	if deps[typeName] {
		return
	}
	
	fields, ok := e.Types[typeName]
	if !ok {
		return
	}
	
	deps[typeName] = true
	
	for _, field := range fields {
		// Remove array suffix if present
		fieldType := strings.TrimSuffix(field.Type, "[]")
		
		// Check if it's a custom type
		if _, ok := e.Types[fieldType]; ok {
			e.findDependencies(fieldType, deps)
		}
	}
}

// validate ensures the typed data is valid
func (e *FastTypedDataEncoder) validate() error {
	return validateNoCycles(e.Types)
}

// buildDomainTypes builds the EIP712Domain type definition
func (e *FastTypedDataEncoder) buildDomainTypes() []Type {
	types := []Type{
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
	}
	
	if e.Domain.ChainID != nil {
		types = append(types, Type{Name: "chainId", Type: "uint256"})
	}
	
	if e.Domain.VerifyingContract != (common.Address{}) {
		types = append(types, Type{Name: "verifyingContract", Type: "address"})
	}
	
	if e.Domain.Salt != [32]byte{} {
		types = append(types, Type{Name: "salt", Type: "bytes32"})
	}
	
	return types
}

// domainToMap converts domain to map for encoding
func (e *FastTypedDataEncoder) domainToMap() map[string]interface{} {
	m := make(map[string]interface{})
	m["name"] = e.Domain.Name
	m["version"] = e.Domain.Version
	
	if e.Domain.ChainID != nil {
		m["chainId"] = e.Domain.ChainID.String()
	}
	
	if e.Domain.VerifyingContract != (common.Address{}) {
		m["verifyingContract"] = e.Domain.VerifyingContract.Hex()
	}
	
	if e.Domain.Salt != [32]byte{} {
		m["salt"] = "0x" + hex.EncodeToString(e.Domain.Salt[:])
	}
	
	return m
}

// Helper conversion functions optimized for common cases

func toAddress(value interface{}) (common.Address, error) {
	switch v := value.(type) {
	case common.Address:
		return v, nil
	case string:
		if !common.IsHexAddress(v) {
			return common.Address{}, fmt.Errorf("invalid address: %s", v)
		}
		return common.HexToAddress(v), nil
	default:
		return common.Address{}, fmt.Errorf("invalid address type: %T", value)
	}
}

func toBool(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	default:
		return false
	}
}

func toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", value)
	}
}

func toBytes(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	case string:
		if strings.HasPrefix(v, "0x") {
			return hex.DecodeString(v[2:])
		}
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("invalid bytes type: %T", value)
	}
}

func toBigInt(value interface{}) (*big.Int, error) {
	switch v := value.(type) {
	case *big.Int:
		return v, nil
	case string:
		n := new(big.Int)
		if strings.HasPrefix(v, "0x") {
			_, ok := n.SetString(v[2:], 16)
			if !ok {
				return nil, fmt.Errorf("invalid hex number: %s", v)
			}
		} else {
			_, ok := n.SetString(v, 10)
			if !ok {
				return nil, fmt.Errorf("invalid decimal number: %s", v)
			}
		}
		return n, nil
	case int64:
		return big.NewInt(v), nil
	case uint64:
		return new(big.Int).SetUint64(v), nil
	default:
		return nil, fmt.Errorf("invalid integer type: %T", value)
	}
}