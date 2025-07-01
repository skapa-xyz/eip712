package eip712

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// FastSigner provides high-performance EIP-712 signing using the optimized encoder
type FastSigner struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
	chainID    *big.Int
}

// NewFastSigner creates a new fast EIP-712 signer
func NewFastSigner(privateKeyHex string, chainID int64) (*FastSigner, error) {
	signer, err := NewSigner(privateKeyHex, chainID)
	if err != nil {
		return nil, err
	}
	
	return &FastSigner{
		privateKey: signer.privateKey,
		address:    signer.address,
		chainID:    signer.chainID,
	}, nil
}

// SignTypedDataFast signs typed data using the optimized encoder
func (s *FastSigner) SignTypedDataFast(domain Domain, types map[string][]Type, primaryType string, message Message) (*Signature, error) {
	// Create fast encoder
	encoder := NewFastTypedDataEncoder(domain, types, primaryType, message)
	
	// Get hash
	hash, err := encoder.Hash()
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

// Address returns the signer's address
func (s *FastSigner) Address() common.Address {
	return s.address
}

// ChainID returns the chain ID
func (s *FastSigner) ChainID() *big.Int {
	return new(big.Int).Set(s.chainID)
}

// SignMessageFast signs a simple message using the optimized encoder
func (s *FastSigner) SignMessageFast(appName string, message map[string]interface{}) (*Signature, error) {
	domain := Domain{
		Name:    appName,
		Version: "1",
		ChainID: s.chainID,
	}
	
	// Infer types
	types := map[string][]Type{
		"Message": inferTypes(message),
	}
	
	return s.SignTypedDataFast(domain, types, "Message", message)
}

// SignPermitFast signs an EIP-2612 permit message using the optimized encoder
func (s *FastSigner) SignPermitFast(
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
	
	return s.SignTypedDataFast(domain, types, "Permit", message)
}

// VerifySignatureFast verifies a signature using the optimized encoder
func VerifySignatureFast(
	sig *Signature,
	expectedSigner common.Address,
	domain Domain,
	types map[string][]Type,
	primaryType string,
	message Message,
) (bool, error) {
	// Recover the address
	recoveredAddr, err := RecoverSignatureFast(sig, domain, types, primaryType, message)
	if err != nil {
		return false, err
	}
	
	// Compare addresses
	return recoveredAddr == expectedSigner, nil
}

// RecoverSignatureFast recovers the signer address using the optimized encoder
func RecoverSignatureFast(
	sig *Signature,
	domain Domain,
	types map[string][]Type,
	primaryType string,
	message Message,
) (common.Address, error) {
	// Create fast encoder
	encoder := NewFastTypedDataEncoder(domain, types, primaryType, message)
	
	// Get hash
	hash, err := encoder.Hash()
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to hash typed data: %w", err)
	}
	
	// Decode signature
	sigBytes, err := hexutil.Decode(sig.Bytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid signature hex: %w", err)
	}
	
	if len(sigBytes) != 65 {
		return common.Address{}, fmt.Errorf("signature must be 65 bytes")
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