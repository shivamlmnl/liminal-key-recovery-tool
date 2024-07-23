import hashlib
import base58
from near_api.transactions import (
    Transaction, BinarySerializer, PublicKey, create_transfer_action, Signature, SignedTransaction, tx_schema
)
from near_api.providers import JsonProvider
import eddsa_sign


def withdraw(public_key_hex: str, private_key_hex: str, rpc_url: str, to_address: str, amount: int):
    account_id = public_key_hex
    public_key_b58 = base58.b58encode(bytes.fromhex(account_id)).decode()
    public_key = bytes.fromhex(account_id)
    private_key = bytes.fromhex(private_key_hex)

    provider = JsonProvider(rpc_url)
    block_hash = provider.get_status()['sync_info']['latest_block_hash']
    block_hash = base58.b58decode(block_hash.encode('utf8'))

    access_key = provider.get_access_key(account_id, public_key_b58)

    tx = Transaction()
    tx.signerId = account_id
    tx.publicKey = PublicKey()
    tx.publicKey.keyType = 0
    tx.publicKey.data = public_key
    tx.nonce = access_key["nonce"]+1
    tx.receiverId = to_address
    tx.actions = [create_transfer_action(amount*(10**24))]
    tx.blockHash = block_hash

    msg: bytes = BinarySerializer(tx_schema).serialize(tx)
    hash_: bytes = hashlib.sha256(msg).digest()

    signature = Signature()
    signature.keyType = 0
    signature.data = eddsa_sign.eddsa_sign(private_key, hash_)

    signed_tx = SignedTransaction()
    signed_tx.transaction = tx
    signed_tx.signature = signature

    stx: bytes = BinarySerializer(tx_schema).serialize(signed_tx)
    res = provider.send_tx(stx)
    print("tx hash", res)


public_key=""
private_key=""
rpc_url="https://rpc.testnet.near.org"
to_address=""
amount=0

# withdraw(public_key, private_key, rpc_url, to_address, amount)
