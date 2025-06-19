package eip712

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestSignPermit(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") // USDC
	spender := common.HexToAddress(testAddress2)
	value := new(big.Int).SetUint64(1000000) // 1 USDC (6 decimals)
	nonce := big.NewInt(0)
	deadline := big.NewInt(time.Now().Add(24 * time.Hour).Unix())
	
	sig, err := signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assertSignatureComponents(t, sig)
	
	// Verify the signature
	domain := Domain{
		Name:              "USD Coin",
		Version:           "2",
		ChainID:           signer.ChainID(),
		VerifyingContract: tokenContract,
	}
	
	types := createPermitTypes()
	message := createPermitMessage(
		signer.Address().Hex(),
		spender.Hex(),
		value,
		nonce,
		deadline,
	)
	
	recovered, err := sig.Recover(domain, types, "Permit", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

func TestEIP2612CompliantPermit(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	// Test with different token configurations
	testCases := []struct {
		name         string
		tokenName    string
		tokenVersion string
		tokenAddress string
		decimals     uint8
	}{
		{
			name:         "USDC",
			tokenName:    "USD Coin",
			tokenVersion: "2",
			tokenAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
			decimals:     6,
		},
		{
			name:         "DAI",
			tokenName:    "Dai Stablecoin",
			tokenVersion: "1",
			tokenAddress: "0x6B175474E89094C44Da98b954EedeAC495271d0F",
			decimals:     18,
		},
		{
			name:         "Custom Token",
			tokenName:    "My Token",
			tokenVersion: "1",
			tokenAddress: testAddress1,
			decimals:     18,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenContract := common.HexToAddress(tc.tokenAddress)
			spender := common.HexToAddress(testAddress2)
			
			// Value in token decimals
			value := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(tc.decimals)), nil) // 1 token
			nonce := big.NewInt(0)
			deadline := big.NewInt(1893456000) // Far future
			
			// Create domain manually to match token configuration
			domain := Domain{
				Name:              tc.tokenName,
				Version:           tc.tokenVersion,
				ChainID:           signer.ChainID(),
				VerifyingContract: tokenContract,
			}
			
			types := createPermitTypes()
			message := createPermitMessage(
				signer.Address().Hex(),
				spender.Hex(),
				value,
				nonce,
				deadline,
			)
			
			sig, err := signer.SignTypedData(domain, types, "Permit", message)
			require.NoError(t, err)
			assertSignatureComponents(t, sig)
			
			// Verify
			recovered, err := sig.Recover(domain, types, "Permit", message)
			require.NoError(t, err)
			require.Equal(t, signer.Address(), recovered)
		})
	}
}

func TestPermitDeadlineValidation(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress(testAddress2)
	value := new(big.Int).SetUint64(1000000)
	nonce := big.NewInt(0)
	
	testCases := []struct {
		name     string
		deadline *big.Int
	}{
		{
			name:     "current timestamp",
			deadline: big.NewInt(time.Now().Unix()),
		},
		{
			name:     "past deadline",
			deadline: big.NewInt(time.Now().Add(-24 * time.Hour).Unix()),
		},
		{
			name:     "far future deadline",
			deadline: big.NewInt(time.Now().Add(365 * 24 * time.Hour).Unix()),
		},
		{
			name:     "max uint256",
			deadline: new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1)),
		},
		{
			name:     "zero deadline",
			deadline: big.NewInt(0),
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, tc.deadline)
			require.NoError(t, err)
			require.NotNil(t, sig)
			assertSignatureComponents(t, sig)
		})
	}
}

func TestPermitWithDifferentNonces(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress(testAddress2)
	value := new(big.Int).SetUint64(1000000)
	deadline := big.NewInt(1893456000)
	
	signatures := make(map[string]*Signature)
	
	// Sign permits with different nonces
	for i := 0; i < 10; i++ {
		nonce := big.NewInt(int64(i))
		sig, err := signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
		require.NoError(t, err)
		
		// Each nonce should produce a unique signature
		require.NotContains(t, signatures, sig.Bytes)
		signatures[sig.Bytes] = sig
	}
	
	// All signatures should be different
	require.Len(t, signatures, 10)
}

func TestPermitValueRanges(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress(testAddress2)
	nonce := big.NewInt(0)
	deadline := big.NewInt(1893456000)
	
	testCases := []struct {
		name  string
		value *big.Int
	}{
		{
			name:  "zero value",
			value: big.NewInt(0),
		},
		{
			name:  "small value",
			value: big.NewInt(1),
		},
		{
			name:  "typical value (1 token with 6 decimals)",
			value: big.NewInt(1000000),
		},
		{
			name:  "large value (1M tokens with 6 decimals)",
			value: new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1000000)),
		},
		{
			name:  "max uint256",
			value: new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1)),
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := signer.SignPermit(tokenContract, "USD Coin", "2", spender, tc.value, nonce, deadline)
			require.NoError(t, err)
			require.NotNil(t, sig)
			assertSignatureComponents(t, sig)
		})
	}
}

func TestPermitDifferentSpenders(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	value := new(big.Int).SetUint64(1000000)
	nonce := big.NewInt(0)
	deadline := big.NewInt(1893456000)
	
	testAddresses := []string{
		testAddress2,
		"0x0000000000000000000000000000000000000000",
		"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"0x1111111111111111111111111111111111111111",
		tokenContract.Hex(), // Self-permit
	}
	
	signatures := make(map[string]*Signature)
	
	for _, addr := range testAddresses {
		spender := common.HexToAddress(addr)
		sig, err := signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
		require.NoError(t, err)
		
		// Different spenders should produce different signatures
		require.NotContains(t, signatures, sig.Bytes)
		signatures[sig.Bytes] = sig
	}
	
	require.Len(t, signatures, len(testAddresses))
}

func TestPermitCrossChain(t *testing.T) {
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := common.HexToAddress(testAddress2)
	value := new(big.Int).SetUint64(1000000)
	nonce := big.NewInt(0)
	deadline := big.NewInt(1893456000)
	
	chainIDs := []int64{1, 137, 42161, 10, 56} // Mainnet, Polygon, Arbitrum, Optimism, BSC
	signatures := make(map[string]*Signature)
	
	for _, chainID := range chainIDs {
		signer, err := NewSigner(testPrivateKey1, chainID)
		require.NoError(t, err)
		
		sig, err := signer.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
		require.NoError(t, err)
		
		// Different chain IDs should produce different signatures
		require.NotContains(t, signatures, sig.Bytes)
		signatures[sig.Bytes] = sig
		
		// Verify the signature includes chain ID
		domain := Domain{
			Name:              "USD Coin",
			Version:           "2",
			ChainID:           big.NewInt(chainID),
			VerifyingContract: tokenContract,
		}
		
		types := createPermitTypes()
		message := createPermitMessage(
			signer.Address().Hex(),
			spender.Hex(),
			value,
			nonce,
			deadline,
		)
		
		recovered, err := sig.Recover(domain, types, "Permit", message)
		require.NoError(t, err)
		require.Equal(t, signer.Address(), recovered)
	}
	
	require.Len(t, signatures, len(chainIDs))
}

func TestPermitBatchSigning(t *testing.T) {
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	// Simulate batch permit signing for multiple tokens
	tokens := []struct {
		name     string
		version  string
		contract string
	}{
		{"USD Coin", "2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
		{"Dai Stablecoin", "1", "0x6B175474E89094C44Da98b954EedeAC495271d0F"},
		{"Tether USD", "1", "0xdAC17F958D2ee523a2206206994597C13D831ec7"},
	}
	
	spender := common.HexToAddress(testAddress2)
	value := new(big.Int).SetUint64(1000000)
	deadline := big.NewInt(1893456000)
	
	permits := make([]*Signature, len(tokens))
	
	for i, token := range tokens {
		tokenContract := common.HexToAddress(token.contract)
		nonce := big.NewInt(int64(i)) // Different nonce for each token
		
		// Can't use SignPermit directly as it hardcodes "USD Coin"
		// So we'll create the domain and sign manually
		domain := Domain{
			Name:              token.name,
			Version:           token.version,
			ChainID:           signer.ChainID(),
			VerifyingContract: tokenContract,
		}
		
		types := createPermitTypes()
		message := createPermitMessage(
			signer.Address().Hex(),
			spender.Hex(),
			value,
			nonce,
			deadline,
		)
		
		sig, err := signer.SignTypedData(domain, types, "Permit", message)
		require.NoError(t, err)
		permits[i] = sig
	}
	
	// All permits should be valid
	for i, permit := range permits {
		require.NotNil(t, permit)
		assertSignatureComponents(t, permit)
		
		// Verify each permit
		token := tokens[i]
		tokenContract := common.HexToAddress(token.contract)
		nonce := big.NewInt(int64(i))
		
		domain := Domain{
			Name:              token.name,
			Version:           token.version,
			ChainID:           signer.ChainID(),
			VerifyingContract: tokenContract,
		}
		
		types := createPermitTypes()
		message := createPermitMessage(
			signer.Address().Hex(),
			spender.Hex(),
			value,
			nonce,
			deadline,
		)
		
		recovered, err := permit.Recover(domain, types, "Permit", message)
		require.NoError(t, err)
		require.Equal(t, signer.Address(), recovered)
	}
}

func TestPermitRealWorldExample(t *testing.T) {
	// This test demonstrates a real-world permit signing scenario
	signer, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	// Real USDC contract on mainnet
	usdcContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	
	// Uniswap V2 Router as spender
	uniswapRouter := common.HexToAddress("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
	
	// Approve 100 USDC (6 decimals)
	value := new(big.Int).Mul(big.NewInt(100), big.NewInt(1000000))
	
	// Get current nonce (in real scenario, this would be fetched from chain)
	nonce := big.NewInt(0)
	
	// Set deadline to 30 minutes from now
	deadline := big.NewInt(time.Now().Add(30 * time.Minute).Unix())
	
	// Create the permit signature
	// Note: In real use, we'd need to use the actual token name/version
	domain := Domain{
		Name:              "USD Coin",
		Version:           "2",
		ChainID:           big.NewInt(1),
		VerifyingContract: usdcContract,
	}
	
	types := createPermitTypes()
	message := createPermitMessage(
		signer.Address().Hex(),
		uniswapRouter.Hex(),
		value,
		nonce,
		deadline,
	)
	
	sig, err := signer.SignTypedData(domain, types, "Permit", message)
	require.NoError(t, err)
	require.NotNil(t, sig)
	
	// In a real scenario, this signature would be sent to a smart contract
	// that would call permit() followed by the actual operation (e.g., swap)
	
	t.Logf("Permit signature for 100 USDC:")
	t.Logf("  r: %s", sig.R)
	t.Logf("  s: %s", sig.S)
	t.Logf("  v: %d", sig.V)
	t.Logf("  deadline: %s", deadline.String())
	
	// Verify the signature
	recovered, err := sig.Recover(domain, types, "Permit", message)
	require.NoError(t, err)
	require.Equal(t, signer.Address(), recovered)
}

func TestPermitGaslessApproval(t *testing.T) {
	// Test the gasless approval use case where a relayer submits the permit
	owner, err := NewSigner(testPrivateKey1, 1)
	require.NoError(t, err)
	
	relayer, err := NewSigner(testPrivateKey2, 1)
	require.NoError(t, err)
	
	tokenContract := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	spender := relayer.Address() // Relayer is the spender
	value := new(big.Int).SetUint64(1000000)
	nonce := big.NewInt(0)
	deadline := big.NewInt(time.Now().Add(5 * time.Minute).Unix())
	
	// Owner signs permit offline
	sig, err := owner.SignPermit(tokenContract, "USD Coin", "2", spender, value, nonce, deadline)
	require.NoError(t, err)
	
	// Verify that the signature is from the owner, not the relayer
	domain := Domain{
		Name:              "USD Coin",
		Version:           "2",
		ChainID:           owner.ChainID(),
		VerifyingContract: tokenContract,
	}
	
	types := createPermitTypes()
	message := createPermitMessage(
		owner.Address().Hex(),
		spender.Hex(),
		value,
		nonce,
		deadline,
	)
	
	recovered, err := sig.Recover(domain, types, "Permit", message)
	require.NoError(t, err)
	require.Equal(t, owner.Address(), recovered)
	require.NotEqual(t, relayer.Address(), recovered)
	
	// In practice, the relayer would now submit this signature to the blockchain
	// along with their transaction, paying the gas fees
}