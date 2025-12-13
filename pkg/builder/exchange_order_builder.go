package builder

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/opinion-go-order-utils/pkg/model"
)

//go:generate mockery --name ExchangeOrderBuilder
type ExchangeOrderBuilder interface {
	// build an order object including the signature.
	//
	// @param signer - the signer instance to use for signing
	//
	// @param orderData
	//
	// @param exchangeAddress - the exchange contract address (from API's ctf_exchange_address)
	//
	// @returns a SignedOrder object (order + signature)
	BuildSignedOrder(signer Signer, orderData *model.OrderData, exchangeAddress common.Address) (*model.SignedOrder, error)

	// Creates an Order object from order data.
	//
	// @param orderData
	//
	// @returns a Order object (not signed)
	BuildOrder(orderData *model.OrderData) (*model.Order, error)

	// Generates the hash of the order from a EIP712TypedData object.
	//
	// @param Order
	//
	// @param exchangeAddress - the exchange contract address (from API's ctf_exchange_address)
	//
	// @returns a OrderHash that is a 'common.Hash'
	BuildOrderHash(order *model.Order, exchangeAddress common.Address) (model.OrderHash, error)

	// signs an order
	//
	// @param signer - the signer instance to use for signing
	//
	// @param Order
	//
	// @param exchangeAddress - the exchange contract address (from API's ctf_exchange_address)
	//
	// @returns a OrderSignature that is []byte
	BuildOrderSignature(signer Signer, order *model.Order, exchangeAddress common.Address) (model.OrderSignature, error)
}
