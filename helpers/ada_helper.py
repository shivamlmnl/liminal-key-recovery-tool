from pycardano import TransactionOutput, VerificationKeyWitness, Transaction, TransactionBuilder, VerificationKey, TransactionBody, Network
from pycardano.backend.blockfrost import BlockFrostChainContext
import eddsa_sign

blockfrost_api_key=""


def build_unsigned_transaction(from_address: str, to_address: str, amount: int) -> TransactionBody:
    ctx = BlockFrostChainContext(project_id=blockfrost_api_key, network=Network.MAINNET)
    utxos = ctx.utxos(from_address)
    builder = TransactionBuilder(ctx)
    for utxo in utxos:
        builder.add_input(utxo)
    builder.add_output(TransactionOutput.from_primitive([to_address, amount]))
    return builder.build(from_address, merge_change=True)


def build_signing_payload(unsigned_txn: TransactionBody) -> bytes:
    return unsigned_txn.hash()


def sign_transaction_payload(private_key: bytes, payload: bytes) -> bytes:  
    return eddsa_sign.eddsa_sign(private_key, payload)


def build_signed_transaction(unsigned_txn: TransactionBody, signature: bytes, public_key: bytes) -> Transaction:
    ctx = BlockFrostChainContext(project_id=blockfrost_api_key, network=Network.MAINNET)
    witness_set = TransactionBuilder(ctx).build_witness_set()
    witness_set.vkey_witnesses = []
    witness_set.vkey_witnesses.append(
        VerificationKeyWitness(VerificationKey(public_key, "PaymentVerificationKeyShelley_ed25519", "Payment Verification Key"), signature)
    )
    return Transaction(unsigned_txn, witness_set, valid=True)


def broadcast_transaction(signed_txn: Transaction) -> str:
    return BlockFrostChainContext(project_id=blockfrost_api_key, network=Network.MAINNET).submit_tx(signed_txn)


def withdraw(public_key_hex: str, private_key_hex: str, from_address: str, to_address: str, amount: int):
    unsigned_txn = build_unsigned_transaction(from_address, to_address, amount)
    signing_payload = build_signing_payload(unsigned_txn)
    private_key = bytes.fromhex(private_key_hex)
    signature = sign_transaction_payload(private_key, signing_payload)
    public_key = bytes.fromhex(public_key_hex)
    signed_txn = build_signed_transaction(unsigned_txn, signature, public_key)
    tx_id = broadcast_transaction(signed_txn)
    print(f'Transaction ID: {tx_id}')
    return tx_id


def parse_unsgined_tx_body(cbor_tx_body_hex: str):
    tx_body = TransactionBody.from_cbor(cbor_tx_body_hex)
    print("unsigned tx body", tx_body)


def parse_signed_tx(cbor_tx_hex: str):
    tx = Transaction.from_cbor(cbor_tx_hex)
    print("signed tx", tx)
    

public_key=""
private_key=""
from_address=""
to_address=""
amount=0 # lovelace

# withdraw(public_key, private_key, from_address, to_address, amount)


unsigned_cbor_tx_body_hex=""
signed_cbor_tx_hex=""

# parse_unsgined_tx_body(unsigned_cbor_tx_body_hex)
# parse_signed_tx(signed_cbor_tx_hex)
