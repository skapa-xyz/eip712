// Package eip712 provides a simple interface for EIP-712 typed data signing.
//
// Thread Safety: While the Signer type itself is safe for concurrent use, the
// underlying go-ethereum library has race conditions when processing shared
// *big.Int values. To avoid races:
//   - Create separate Signer instances for concurrent operations
//   - Use string values instead of *big.Int in messages
//   - Clone *big.Int values before sharing across goroutines
//   - See RACE_CONDITIONS.md for detailed information
//
// Example of safe concurrent usage:
//
//	// SAFE: Each goroutine has its own signer
//	go func() {
//	    signer, _ := NewSigner(privateKey, 1)
//	    signer.SignTypedData(...)
//	}()
//
//	// UNSAFE: Shared signer across goroutines
//	signer, _ := NewSigner(privateKey, 1)
//	go func() { signer.SignTypedData(...) }()  // Race condition!
//	go func() { signer.SignTypedData(...) }()  // Race condition!
//
// Security Notes:
//   - Private keys are stored in memory and not zeroed after use
//   - This package does not implement replay attack protection - applications
//     should implement their own nonce management
//   - Always validate input data before signing
package eip712

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// Signer provides a simple interface for EIP-712 signing
type Signer struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
	chainID    *big.Int
}

// NewSigner creates a new EIP-712 signer from a private key
//
// Example:
//
//	signer, err := NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", 1)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(signer.Address()) // 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
func NewSigner(privateKeyHex string, chainID int64) (*Signer, error) {
	// Remove 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("error casting public key to ECDSA")
	}
	
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	
	return &Signer{
		privateKey: privateKey,
		address:    address,
		chainID:    big.NewInt(chainID),
	}, nil
}

// NewSignerFromKeystore creates a new signer from an encrypted keystore file
func NewSignerFromKeystore(keystoreJSON []byte, password string, chainID int64) (*Signer, error) {
	key, err := keystore.DecryptKey(keystoreJSON, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keystore: %w", err)
	}
	
	return &Signer{
		privateKey: key.PrivateKey,
		address:    key.Address,
		chainID:    big.NewInt(chainID),
	}, nil
}

// Address returns the signer's Ethereum address
func (s *Signer) Address() common.Address {
	return s.address
}

// ChainID returns the chain ID used for signing
func (s *Signer) ChainID() *big.Int {
	return s.chainID
}

// Domain represents the EIP-712 domain separator
type Domain struct {
	Name              string         `json:"name"`
	Version           string         `json:"version"`
	ChainID           *big.Int       `json:"chainId,omitempty"`
	VerifyingContract common.Address `json:"verifyingContract,omitempty"`
	Salt              [32]byte       `json:"salt,omitempty"`
}

// Message represents a simple wrapper for EIP-712 messages
type Message map[string]interface{}

// SignTypedData signs an EIP-712 typed data message
//
// Example:
//
//	domain := Domain{
//	    Name:    "Example App",
//	    Version: "1",
//	    ChainID: big.NewInt(1),
//	}
//	
//	types := map[string][]Type{
//	    "Person": {
//	        {Name: "name", Type: "string"},
//	        {Name: "wallet", Type: "address"},
//	    },
//	    "Mail": {
//	        {Name: "from", Type: "Person"},
//	        {Name: "to", Type: "Person"},
//	        {Name: "contents", Type: "string"},
//	    },
//	}
//	
//	message := Message{
//	    "from": map[string]interface{}{
//	        "name": "Alice",
//	        "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
//	    },
//	    "to": map[string]interface{}{
//	        "name": "Bob", 
//	        "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
//	    },
//	    "contents": "Hello, Bob!",
//	}
//	
//	sig, err := signer.SignTypedData(domain, types, "Mail", message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Signature: %s\n", sig.Bytes)
func (s *Signer) SignTypedData(domain Domain, types map[string][]Type, primaryType string, message Message) (*Signature, error) {
	// Validate for cyclic structures
	if err := validateNoCycles(types); err != nil {
		return nil, err
	}
	// Convert to apitypes format
	typedData := apitypes.TypedData{
		Types:       make(apitypes.Types),
		PrimaryType: primaryType,
		Domain:      s.domainToAPITypes(domain),
		Message:     apitypes.TypedDataMessage(message),
	}
	
	// Convert types
	for typeName, fields := range types {
		typedData.Types[typeName] = make([]apitypes.Type, len(fields))
		for i, field := range fields {
			typedData.Types[typeName][i] = apitypes.Type{
				Name: field.Name,
				Type: field.Type,
			}
		}
	}
	
	// Add EIP712Domain type if not present
	if _, ok := typedData.Types["EIP712Domain"]; !ok {
		typedData.Types["EIP712Domain"] = s.buildDomainTypes(domain)
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

// Type represents an EIP-712 type field
type Type struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Signature contains the signature components
type Signature struct {
	R     string `json:"r"`
	S     string `json:"s"`
	V     uint8  `json:"v"`
	Hash  string `json:"hash"`
	Bytes string `json:"signature"`
}

// Recover recovers the signer address from the signature
//
// Example:
//
//	// After receiving a signature from a user
//	recoveredAddr, err := sig.Recover(domain, types, "Mail", message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	
//	// Verify it matches the expected signer
//	if recoveredAddr == expectedAddress {
//	    fmt.Println("Signature is valid!")
//	}
func (sig *Signature) Recover(domain Domain, types map[string][]Type, primaryType string, message Message) (common.Address, error) {
	// Recreate the typed data for hashing
	typedData := apitypes.TypedData{
		Types:       make(apitypes.Types),
		PrimaryType: primaryType,
		Domain:      domainToAPITypesStatic(domain),
		Message:     apitypes.TypedDataMessage(message),
	}
	
	// Convert types
	for typeName, fields := range types {
		typedData.Types[typeName] = make([]apitypes.Type, len(fields))
		for i, field := range fields {
			typedData.Types[typeName][i] = apitypes.Type{
				Name: field.Name,
				Type: field.Type,
			}
		}
	}
	
	// Add EIP712Domain type if not present
	if _, ok := typedData.Types["EIP712Domain"]; !ok {
		typedData.Types["EIP712Domain"] = buildDomainTypesStatic(domain)
	}
	
	// Hash the typed data
	hash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to hash typed data: %w", err)
	}
	
	// Decode signature
	sigBytes, err := hexutil.Decode(sig.Bytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid signature hex: %w", err)
	}
	
	if len(sigBytes) != 65 {
		return common.Address{}, errors.New("signature must be 65 bytes")
	}
	
	// Transform V from 27/28 to 0/1 for recovery
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}
	
	// Recover public key
	pubKey, err := crypto.SigToPub(hash, sigBytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}
	
	return crypto.PubkeyToAddress(*pubKey), nil
}

// Helper functions

func (s *Signer) domainToAPITypes(domain Domain) apitypes.TypedDataDomain {
	d := apitypes.TypedDataDomain{
		Name:    domain.Name,
		Version: domain.Version,
	}
	
	if domain.ChainID != nil {
		d.ChainId = (*math.HexOrDecimal256)(domain.ChainID)
	}
	
	if domain.VerifyingContract != (common.Address{}) {
		d.VerifyingContract = domain.VerifyingContract.Hex()
	}
	
	if domain.Salt != [32]byte{} {
		d.Salt = hexutil.Encode(domain.Salt[:])
	}
	
	return d
}

func domainToAPITypesStatic(domain Domain) apitypes.TypedDataDomain {
	d := apitypes.TypedDataDomain{
		Name:    domain.Name,
		Version: domain.Version,
	}
	
	if domain.ChainID != nil {
		d.ChainId = (*math.HexOrDecimal256)(domain.ChainID)
	}
	
	if domain.VerifyingContract != (common.Address{}) {
		d.VerifyingContract = domain.VerifyingContract.Hex()
	}
	
	if domain.Salt != [32]byte{} {
		d.Salt = hexutil.Encode(domain.Salt[:])
	}
	
	return d
}

func (s *Signer) buildDomainTypes(domain Domain) []apitypes.Type {
	return buildDomainTypesStatic(domain)
}

func buildDomainTypesStatic(domain Domain) []apitypes.Type {
	types := []apitypes.Type{
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
	}
	
	if domain.ChainID != nil {
		types = append(types, apitypes.Type{Name: "chainId", Type: "uint256"})
	}
	
	if domain.VerifyingContract != (common.Address{}) {
		types = append(types, apitypes.Type{Name: "verifyingContract", Type: "address"})
	}
	
	if domain.Salt != [32]byte{} {
		types = append(types, apitypes.Type{Name: "salt", Type: "bytes32"})
	}
	
	return types
}

// Quick signing functions for common use cases

// SignMessage signs a simple message with minimal configuration.
// It automatically infers types from the message values.
//
// Example:
//
//	message := map[string]interface{}{
//	    "action": "Transfer",
//	    "from": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
//	    "to": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
//	    "amount": "1000000000000000000", // 1 ETH in wei
//	}
//	
//	sig, err := signer.SignMessage("MyDApp", message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Signature: %s\n", sig.Bytes)
func (s *Signer) SignMessage(appName string, message map[string]interface{}) (*Signature, error) {
	domain := Domain{
		Name:    appName,
		Version: "1",
		ChainID: s.chainID,
	}
	
	// Infer types from message
	types := map[string][]Type{
		"Message": inferTypes(message),
	}
	
	return s.SignTypedData(domain, types, "Message", message)
}

// SignPermit signs an EIP-2612 permit message for gasless token approvals
//
// Example:
//
//	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") // USDC
//	spender := common.HexToAddress("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")      // Uniswap Router
//	value := new(big.Int).Mul(big.NewInt(100), big.NewInt(1000000))                   // 100 USDC (6 decimals)
//	nonce := big.NewInt(0)                                                             // Get from contract
//	deadline := big.NewInt(time.Now().Add(30 * time.Minute).Unix())
//	
//	sig, err := signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	
//	// Use sig.V, sig.R, sig.S in your contract's permit() call
//	fmt.Printf("v: %d, r: %s, s: %s\n", sig.V, sig.R, sig.S)
func (s *Signer) SignPermit(
	tokenContract common.Address,
	tokenName string,
	tokenVersion string,
	spender common.Address,
	value *big.Int,
	nonce *big.Int,
	deadline *big.Int,
) (*Signature, error) {
	domain := Domain{
		Name:              tokenName,
		Version:           tokenVersion,
		ChainID:           s.chainID,
		VerifyingContract: tokenContract,
	}
	
	types := map[string][]Type{
		"Permit": {
			{Name: "owner", Type: "address"},
			{Name: "spender", Type: "address"},
			{Name: "value", Type: "uint256"},
			{Name: "nonce", Type: "uint256"},
			{Name: "deadline", Type: "uint256"},
		},
	}
	
	message := Message{
		"owner":    s.address.Hex(),
		"spender":  spender.Hex(),
		"value":    value.String(),
		"nonce":    nonce.String(),
		"deadline": deadline.String(),
	}
	
	return s.SignTypedData(domain, types, "Permit", message)
}

// inferTypes attempts to infer EIP-712 types from a message
func inferTypes(message map[string]interface{}) []Type {
	types := make([]Type, 0, len(message))
	
	for name, value := range message {
		var fieldType string
		
		switch v := value.(type) {
		case string:
			// Check if it's an address
			if common.IsHexAddress(v) {
				fieldType = "address"
			} else if _, ok := new(big.Int).SetString(v, 10); ok {
				fieldType = "uint256"
			} else {
				fieldType = "string"
			}
		case *big.Int:
			fieldType = "uint256"
		case int, int8, int16, int32, int64:
			fieldType = "uint256"
		case uint, uint8, uint16, uint32, uint64:
			fieldType = "uint256"
		case bool:
			fieldType = "bool"
		case []byte:
			fieldType = fmt.Sprintf("bytes%d", len(v))
		default:
			fieldType = "string"
		}
		
		types = append(types, Type{
			Name: name,
			Type: fieldType,
		})
	}
	
	// Sort types by name to ensure deterministic ordering
	sort.Slice(types, func(i, j int) bool {
		return types[i].Name < types[j].Name
	})
	
	return types
}

// VerifySignature verifies an EIP-712 signature against an expected signer
func VerifySignature(
	signature *Signature,
	expectedSigner common.Address,
	domain Domain,
	types map[string][]Type,
	primaryType string,
	message Message,
) (bool, error) {
	recoveredAddr, err := signature.Recover(domain, types, primaryType, message)
	if err != nil {
		return false, err
	}
	
	return recoveredAddr == expectedSigner, nil
}

// Example usage helper
func ExampleJSON() string {
	example := map[string]interface{}{
		"domain": Domain{
			Name:    "Example App",
			Version: "1",
			ChainID: big.NewInt(1),
		},
		"types": map[string][]Type{
			"Person": {
				{Name: "name", Type: "string"},
				{Name: "wallet", Type: "address"},
			},
			"Mail": {
				{Name: "from", Type: "Person"},
				{Name: "to", Type: "Person"},
				{Name: "contents", Type: "string"},
			},
		},
		"primaryType": "Mail",
		"message": Message{
			"from": map[string]interface{}{
				"name":   "Alice",
				"wallet": "0x0000000000000000000000000000000000000001",
			},
			"to": map[string]interface{}{
				"name":   "Bob",
				"wallet": "0x0000000000000000000000000000000000000002",
			},
			"contents": "Hello, Bob!",
		},
	}
	
	jsonBytes, _ := json.MarshalIndent(example, "", "  ")
	return string(jsonBytes)
}

// validateNoCycles checks for cyclic references in type definitions
func validateNoCycles(types map[string][]Type) error {
	// Track visited types and types in current path
	visited := make(map[string]bool)
	inPath := make(map[string]bool)
	
	// Check each type for cycles
	for typeName := range types {
		if err := checkCycle(typeName, types, visited, inPath); err != nil {
			return err
		}
	}
	
	return nil
}

// checkCycle performs DFS to detect cycles in type definitions
func checkCycle(typeName string, types map[string][]Type, visited, inPath map[string]bool) error {
	if inPath[typeName] {
		return fmt.Errorf("cyclic reference detected in type: %s", typeName)
	}
	
	if visited[typeName] {
		return nil
	}
	
	visited[typeName] = true
	inPath[typeName] = true
	
	// Check all fields of this type
	if fields, ok := types[typeName]; ok {
		for _, field := range fields {
			// Extract base type (remove array notation)
			baseType := strings.TrimSuffix(field.Type, "[]")
			
			// Check if it's a custom type (not a primitive)
			if _, isCustom := types[baseType]; isCustom {
				if err := checkCycle(baseType, types, visited, inPath); err != nil {
					return err
				}
			}
		}
	}
	
	inPath[typeName] = false
	return nil
}
