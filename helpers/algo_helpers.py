from algosdk.v2client import algod
from algosdk import encoding
from algosdk import constants
from algosdk.future.transaction import PaymentTxn, SignedTransaction
import base64
import eddsa_sign

BIP_44_CONSTANT = 44
ALGO_ASSET_NUM = 283
CHANGE = 0
ADDR_INDEX = 0

# change the following settings to your Algorand node's URL and its token
# these settings work with the Algorand Sandbox: https://github.com/algorand/sandbox
algod_address = "http://localhost:4001"
algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
algod_client = algod.AlgodClient(algod_token, algod_address)


def build_unsigned_transaction(from_address: str, to_address: str, amount: int) -> PaymentTxn:
    params = algod_client.suggested_params()
    # remove the next 2 lines to use suggested fees
    params.flat_fee = True
    params.fee = 1000
    return PaymentTxn(from_address, params, to_address, amount)


def build_signing_payload(unsigned_txn: PaymentTxn) -> bytes:
    txn = encoding.msgpack_encode(unsigned_txn)
    return constants.txid_prefix + base64.b64decode(txn)


def sign_transaction_payload(private_key: bytes, payload: bytes) -> bytes:
    return eddsa_sign.eddsa_sign(private_key, payload)


def build_signed_transaction(unsigned_txn: PaymentTxn, signature: bytes) -> SignedTransaction:
    return SignedTransaction(unsigned_txn, base64.b64encode(signature).decode())


def broadcast_transaction(signed_txn: SignedTransaction) -> str:
    return algod_client.send_transaction(signed_txn)


def withdraw(priv: bytes, pub: bytes, to_address: str, amount) -> str:
    from_address = public_key_to_address(pub)
    unsigned_txn = build_unsigned_transaction(from_address, to_address, amount)
    signing_payload = build_signing_payload(unsigned_txn)
    signature = sign_transaction_payload(priv, signing_payload)
    signed_txn = build_signed_transaction(unsigned_txn, signature)
    tx_id = broadcast_transaction(signed_txn)
    print(f'Transaction ID: {tx_id}')
    return tx_id


def getBalance(addr):
    account_info = algod_client.account_info(addr)
    if account_info is None: return 0
    return account_info.get('amount') / 1e6

def public_key_to_address(public_key: bytes) -> str:
    return encoding.encode_address(public_key)


public_key = bytes.fromhex("")
private_key = bytes.fromhex("")
to_address = ""
amount = 0 # microalgo

withdraw(private_key, public_key, to_address, amount)
