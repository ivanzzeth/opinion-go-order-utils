# opinion-go-order-utils

Golang utilities used to generate and sign orders for Opinion Labs' CTF Exchange on BNB Chain

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Usage](#usage)
  - [Creating a Signer](#creating-a-signer)
  - [Building Orders](#building-orders)
  - [Building Signed Orders](#building-signed-orders)
  - [Building Order Hash](#building-order-hash)
  - [Building Order Signature](#building-order-signature)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Contributions](#contributions)

## Installation

```bash
go get github.com/ivanzzeth/opinion-go-order-utils
```

## Quick Start

```go
package main

import (
    "fmt"
    "math/big"

    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ivanzzeth/ethsig"
    "github.com/ivanzzeth/opinion-go-order-utils/pkg/builder"
    "github.com/ivanzzeth/opinion-go-order-utils/pkg/model"
    polymarketcontracts "github.com/ivanzzeth/polymarket-go-contracts"
)

func main() {
    // Load your private key
    privateKey, _ := crypto.HexToECDSA("your_private_key_hex")

    // Create a signer
    ethSigner := ethsig.NewEthPrivateKeySigner(privateKey)
    makerAddress := ethSigner.GetAddress()

    // Create order builder for BNB Chain (chain ID 56)
    chainId := big.NewInt(56)
    orderBuilder := builder.NewExchangeOrderBuilderImpl(chainId, nil)

    // Build and sign an order
    signedOrder, err := orderBuilder.BuildSignedOrder(ethSigner, &model.OrderData{
        Maker:         makerAddress.Hex(),
        Taker:         common.HexToAddress("0x0").Hex(),
        TokenId:       "1234",
        MakerAmount:   "1000000", // 1 USDC (6 decimals)
        TakerAmount:   "500000",  // 0.5 USDC worth of outcome tokens
        Side:          model.BUY,
        FeeRateBps:    "100",     // 1% fee
        Nonce:         "0",
        Signer:        makerAddress.Hex(),
        SignatureType: polymarketcontracts.SignatureTypePolyGnosisSafe,
    }, model.CTFExchange)

    if err != nil {
        panic(err)
    }

    fmt.Printf("Order signed successfully: %x\n", signedOrder.Signature)
}
```

## Core Concepts

### Signer Interface

The `Signer` interface abstracts the signing mechanism, allowing you to use different signing strategies. The signer must implement `ethsig.TypedDataSigner` and `ethsig.AddressGetter` interfaces for EIP-712 typed data signing.

### Order Data

`OrderData` is used to specify the parameters of an order:

- **Maker**: Address of the order maker (source of funds)
- **Taker**: Address of the order taker (`0x0` for public orders)
- **TokenId**: Token ID of the CTF ERC1155 asset
- **MakerAmount**: Maximum amount of tokens to be sold
- **TakerAmount**: Minimum amount of tokens to be received
- **Side**: Either `model.BUY` or `model.SELL`
- **FeeRateBps**: Fee rate in basis points (100 = 1%)
- **Nonce**: Nonce for onchain cancellations
- **Signer**: Optional, defaults to maker address
- **Expiration**: Optional, timestamp after which order expires (0 = no expiration)
- **SignatureType**: Signature type from `polymarket-go-contracts` package (e.g., `SignatureTypePolyGnosisSafe`)

### Verifying Contracts

Two types of exchanges are supported:

- `model.CTFExchange`: Standard CTF Exchange
- `model.NegRiskCTFExchange`: Negative Risk CTF Exchange

## Usage

### Creating a Signer

#### Using Ethereum Private Key

```go
import (
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ivanzzeth/ethsig"
)

// From hex string
privateKey, err := crypto.HexToECDSA("your_private_key_without_0x_prefix")
if err != nil {
    panic(err)
}

ethSigner := ethsig.NewEthPrivateKeySigner(privateKey)

// Get the address associated with this signer
address := ethSigner.GetAddress()
```

#### Custom Signer Implementation

You can implement your own signer by implementing the `Signer` interface which requires:
- `ethsig.TypedDataSigner`: For EIP-712 typed data signing
- `ethsig.AddressGetter`: For getting the signer's address

```go
import (
    "github.com/ivanzzeth/ethsig"
    "github.com/ivanzzeth/ethsig/eip712"
)

type MyCustomSigner struct {
    // your fields
}

func (s *MyCustomSigner) SignTypedData(typedData eip712.TypedData) ([]byte, error) {
    // your EIP-712 signing logic
}

func (s *MyCustomSigner) GetAddress() common.Address {
    // return your address
}
```

### Building Orders

Create an order builder and build an order without signing:

```go
import (
    "math/big"
    "github.com/ivanzzeth/opinion-go-order-utils/pkg/builder"
    "github.com/ivanzzeth/opinion-go-order-utils/pkg/model"
)

chainId := big.NewInt(56) // BNB Chain mainnet
orderBuilder := builder.NewExchangeOrderBuilderImpl(chainId, nil)

order, err := orderBuilder.BuildOrder(&model.OrderData{
    Maker:       "0xYourMakerAddress",
    Taker:       "0x0000000000000000000000000000000000000000",
    TokenId:     "1234",
    MakerAmount: "1000000",
    TakerAmount: "500000",
    Side:        model.BUY,
    FeeRateBps:  "100",
    Nonce:       "0",
})
```

### Building Signed Orders

Build and sign an order in one step:

```go
signedOrder, err := orderBuilder.BuildSignedOrder(
    ethSigner,
    &model.OrderData{
        Maker:       "0xYourMakerAddress",
        Taker:       "0x0000000000000000000000000000000000000000",
        TokenId:     "1234",
        MakerAmount: "1000000",
        TakerAmount: "500000",
        Side:        model.BUY,
        FeeRateBps:  "100",
        Nonce:       "0",
        Expiration:  "1735689600", // Optional: Unix timestamp
    },
    model.CTFExchange,
)

if err != nil {
    panic(err)
}

// Access order details
fmt.Printf("Salt: %s\n", signedOrder.Salt.String())
fmt.Printf("Signature: %x\n", signedOrder.Signature)
```

### Building Order Hash

Generate the EIP-712 hash of an order:

```go
order, _ := orderBuilder.BuildOrder(&model.OrderData{...})

orderHash, err := orderBuilder.BuildOrderHash(order, model.CTFExchange)
if err != nil {
    panic(err)
}

fmt.Printf("Order hash: %x\n", orderHash)
```

### Building Order Signature

Sign an order hash separately:

```go
orderHash, _ := orderBuilder.BuildOrderHash(order, model.CTFExchange)

signature, err := orderBuilder.BuildOrderSignature(ethSigner, orderHash)
if err != nil {
    panic(err)
}

fmt.Printf("Signature: %x\n", signature)
```


## API Reference

### Builder Package

#### `NewExchangeOrderBuilderImpl(chainId *big.Int, saltGenerator func() int64)`

Creates a new order builder instance.

- `chainId`: The chain ID (e.g., 56 for BNB Chain mainnet)
- `saltGenerator`: Optional function to generate salt values (defaults to random)

#### `BuildOrder(orderData *model.OrderData) (*model.Order, error)`

Creates an unsigned order from order data.

#### `BuildSignedOrder(signer signer.Signer, orderData *model.OrderData, contract model.VerifyingContract) (*model.SignedOrder, error)`

Builds and signs an order in one operation.

#### `BuildOrderHash(order *model.Order, contract model.VerifyingContract) (model.OrderHash, error)`

Generates the EIP-712 typed data hash for an order.

#### `BuildOrderSignature(signer Signer, order *model.Order, contract model.VerifyingContract) (model.OrderSignature, error)`

Signs an order using EIP-712 typed data signing. The signer must implement `ethsig.TypedDataSigner` interface for EIP-712 typed data signing.

## Examples

### Complete Example: Creating a Buy Order

```go
package main

import (
    "fmt"
    "math/big"

    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ivanzzeth/ethsig"
    "github.com/ivanzzeth/opinion-go-order-utils/pkg/builder"
    "github.com/ivanzzeth/opinion-go-order-utils/pkg/model"
    polymarketcontracts "github.com/ivanzzeth/polymarket-go-contracts"
)

func main() {
    // Setup
    privateKey, _ := crypto.HexToECDSA("your_private_key")
    ethSigner := ethsig.NewEthPrivateKeySigner(privateKey)
    makerAddress := ethSigner.GetAddress()

    chainId := big.NewInt(56) // BNB Chain mainnet
    orderBuilder := builder.NewExchangeOrderBuilderImpl(chainId, nil)

    // Create a buy order for outcome token
    signedOrder, err := orderBuilder.BuildSignedOrder(ethSigner, &model.OrderData{
        Maker:         makerAddress.Hex(),
        Taker:         common.HexToAddress("0x0").Hex(), // Public order
        TokenId:       "71321045679252212594626385532706912750332728571942532289631379312455583992563",
        MakerAmount:   "1000000",  // 1 USDC
        TakerAmount:   "800000",   // 0.8 outcome tokens (implies 0.8 probability)
        Side:          model.BUY,
        FeeRateBps:    "100",      // 1% fee
        Nonce:         "0",
        Expiration:    "0",        // No expiration
        Signer:        makerAddress.Hex(),
        SignatureType: polymarketcontracts.SignatureTypePolyGnosisSafe,
    }, model.CTFExchange)

    if err != nil {
        panic(err)
    }

    fmt.Printf("Order created successfully!\n")
    fmt.Printf("Salt: %s\n", signedOrder.Salt.String())
    fmt.Printf("Maker: %s\n", signedOrder.Maker.Hex())
    fmt.Printf("Token ID: %s\n", signedOrder.TokenId.String())
    fmt.Printf("Maker Amount: %s\n", signedOrder.MakerAmount.String())
    fmt.Printf("Taker Amount: %s\n", signedOrder.TakerAmount.String())
    fmt.Printf("Signature: %x\n", signedOrder.Signature)
}
```

### Example: Creating a Sell Order

```go
signedOrder, err := orderBuilder.BuildSignedOrder(ethSigner, &model.OrderData{
    Maker:         makerAddress.Hex(),
    Taker:         "0x0000000000000000000000000000000000000000",
    TokenId:       "71321045679252212594626385532706912750332728571942532289631379312455583992563",
    MakerAmount:   "800000",   // 0.8 outcome tokens to sell
    TakerAmount:   "750000",   // Minimum 0.75 USDC to receive
    Side:          model.SELL,
    FeeRateBps:    "100",
    Nonce:         "0",
    Signer:        makerAddress.Hex(),
    SignatureType: polymarketcontracts.SignatureTypePolyGnosisSafe,
}, model.CTFExchange)
```

### Example: Using NegRisk Exchange

```go
signedOrder, err := orderBuilder.BuildSignedOrder(ethSigner, &model.OrderData{
    Maker:         makerAddress.Hex(),
    Taker:         "0x0000000000000000000000000000000000000000",
    TokenId:       "1234",
    MakerAmount:   "1000000",
    TakerAmount:   "500000",
    Side:          model.BUY,
    FeeRateBps:    "100",
    Nonce:         "0",
    Signer:        makerAddress.Hex(),
    SignatureType: polymarketcontracts.SignatureTypePolyGnosisSafe,
}, model.NegRiskCTFExchange) // Use NegRisk exchange
```

### Example: Using Custom Salt Generator

```go
// Use a custom salt generator for deterministic salts
customSaltGenerator := func() int64 {
    return 12345678
}

orderBuilder := builder.NewExchangeOrderBuilderImpl(chainId, customSaltGenerator)
```

## Contributions

Before pushing changes please run `make lint test` to format the code and run the tests.

### Development

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Format code
go fmt ./...

# Lint code (requires golangci-lint)
golangci-lint run
```

## License

See LICENSE file for details.
