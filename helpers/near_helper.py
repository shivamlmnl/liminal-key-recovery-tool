import hashlib
import base58
from near_api.transactions import (
    Transaction, BinarySerializer, PublicKey, create_transfer_action, Signature, SignedTransaction, tx_schema
)
from near_api.providers import JsonProvider
import eddsa_sign

rpc_url="https://rpc.mainnet.near.org"


def build_unsigned_transaction(from_address: str, to_address: str, amount: int) -> Transaction:
    account_id = from_address
    public_key = bytes.fromhex(account_id)
    public_key_b58 = base58.b58encode(public_key).decode()

    provider = JsonProvider(rpc_url)
    nonce = provider.get_access_key(account_id, public_key_b58)["nonce"]+1
    block_hash = provider.get_status()['sync_info']['latest_block_hash']
    block_hash = base58.b58decode(block_hash.encode('utf8'))

    tx = Transaction()
    tx.signerId = account_id
    tx.publicKey = PublicKey()
    tx.publicKey.keyType = 0
    tx.publicKey.data = public_key
    tx.nonce = nonce
    tx.receiverId = to_address
    tx.actions = [create_transfer_action(amount)]
    tx.blockHash = block_hash

    return tx


def build_signing_payload(unsigned_txn: Transaction) -> bytes:
    msg: bytes = BinarySerializer(tx_schema).serialize(unsigned_txn)
    return hashlib.sha256(msg).digest()


def sign_transaction_payload(private_key: bytes, payload: bytes) -> bytes:
    return eddsa_sign.eddsa_sign(private_key, payload)


def build_signed_transaction(unsigned_txn: Transaction, signature: bytes) -> SignedTransaction:
    signed_tx = SignedTransaction()
    signed_tx.transaction = unsigned_txn
    signed_tx.signature = Signature()
    signed_tx.signature.keyType = 0
    signed_tx.signature.data = signature
    return signed_tx


def broadcast_transaction(signed_txn: SignedTransaction) -> dict:
    provider = JsonProvider(rpc_url)
    serialized_tx: bytes = BinarySerializer(tx_schema).serialize(signed_txn)
    return provider.send_tx(serialized_tx)


def withdraw(public_key_hex: str, private_key_hex: str, to_address: str, amount: float):
    private_key = bytes.fromhex(private_key_hex)
    unsigned_txn = build_unsigned_transaction(public_key_hex, to_address, amount)
    signing_payload = build_signing_payload(unsigned_txn)
    signature = sign_transaction_payload(private_key, signing_payload)
    signed_txn = build_signed_transaction(unsigned_txn, signature)
    tx_id = broadcast_transaction(signed_txn)
    print(f'Transaction ID: {tx_id}')
    return tx_id


public_key=""
private_key=""
to_address=""
amount=0 # yocto

withdraw(public_key, private_key, to_address, amount)
