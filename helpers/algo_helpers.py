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

def withdraw(priv: bytes, pub: bytes, to_address: str, amount):
    from_address = public_key_to_address(pub)

    params = algod_client.suggested_params()
    # remove the next 2 lines to use suggested fees
    params.flat_fee = True
    params.fee = 1000

    unsigned_txn = PaymentTxn(from_address, params, to_address, int(amount * 1e6))

    txn = encoding.msgpack_encode(unsigned_txn)
    to_sign = constants.txid_prefix + base64.b64decode(txn)
    sig = eddsa_sign.eddsa_sign(priv, to_sign)
    sig = base64.b64encode(sig).decode()
    signed_txn = SignedTransaction(unsigned_txn, sig)
    txid = algod_client.send_transaction(signed_txn)

    print("Sent transaction with txID: {}".format(txid))

def getBalance(addr):
    account_info = algod_client.account_info(addr)
    if account_info is None: return 0
    return account_info.get('amount') / 1e6

def public_key_to_address(public_key: bytes) -> str:
    return encoding.encode_address(public_key)


public_key = bytes.fromhex("")
private_key = bytes.fromhex("")
to_address = ""
amount=0

# withdraw(private_key, public_key, to_address, amount)
