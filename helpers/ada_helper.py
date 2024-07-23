from pycardano import TransactionOutput, VerificationKeyWitness, Transaction, TransactionBuilder, VerificationKey, TransactionBody
from pycardano.backend.blockfrost import BlockFrostChainContext
import eddsa_sign

def withdraw(public_key_hex: str, private_key_hex: str, from_address: str, to_address: str, amount: int, blockfrost_api_key: str):
    public_key = bytes.fromhex(public_key_hex)
    private_key = bytes.fromhex(private_key_hex)

    ctx = BlockFrostChainContext(project_id=blockfrost_api_key)
    utxos = ctx.utxos(from_address)
    builder = TransactionBuilder(ctx)
    for utxo in utxos:
        builder.add_input(utxo)
    builder.add_output(TransactionOutput.from_primitive([to_address, amount * 1000000]))

    tx_body = builder.build(from_address, merge_change=True)
    print("unsigned cbor tx hex", tx_body.to_cbor_hex())
    print("signing payload", tx_body.hash().hex())

    witness_set = builder.build_witness_set()
    witness_set.vkey_witnesses = []
    signature: bytes = eddsa_sign.eddsa_sign(private_key, tx_body.hash())
    witness_set.vkey_witnesses.append(
        VerificationKeyWitness(VerificationKey(public_key, "PaymentVerificationKeyShelley_ed25519", "Payment Verification Key"), signature)
    )

    signed_tx = Transaction(tx_body, witness_set, valid=True, auxiliary_data=builder.auxiliary_data)
    print("signed cbor tx hex", signed_tx.to_cbor_hex())
    tx_hash = ctx.submit_tx(signed_tx)
    print("tx hash", tx_hash)


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
amount=0
blockfrost_api_key=""

# withdraw(public_key, private_key, from_address, to_address, amount, blockfrost_api_key)


unsigned_cbor_tx_body_hex=""
signed_cbor_tx_hex=""

# parse_unsgined_tx_body(unsigned_cbor_tx_body_hex)
# parse_signed_tx(signed_cbor_tx_hex)
