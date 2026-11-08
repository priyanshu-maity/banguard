
import os

from dotenv import load_dotenv
from web3 import Web3


load_dotenv()

SEPOLIA_RPC_URL = os.getenv("SEPOLIA_RPC_URL")
PRIVATE_KEY = os.getenv("SEPOLIA_PRIVATE_KEY")
CHAIN_ID = 11155111

CONTRACT_ADDRESS = Web3.to_checksum_address("0x59bA22a7C1Ba140e8aCAC76159A01fDBA6eC6410")

CONTRACT_ABI = [
    {
        "inputs": [{"name": "reportId", "type": "string"}],
        "name": "latestVersion",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"name": "reportId", "type": "string"},
            {"name": "version", "type": "uint256"},
            {"name": "contentHash", "type": "bytes32"}
        ],
        "name": "registerReport",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"name": "reportId", "type": "string"},
            {"name": "version", "type": "uint256"}
        ],
        "name": "getReport",
        "outputs": [
            {"name": "", "type": "bytes32"},
            {"name": "", "type": "uint256"},
            {"name": "", "type": "address"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)


def is_blockchain_connected() -> bool:
    return w3.is_connected()


def get_latest_version(report_id: str) -> int:
    return contract.functions.latestVersion(report_id).call()


def get_registered_report(report_id: str, version: int) -> dict:
    content_hash, registered_at, submitter = contract.functions.getReport(report_id, version).call()
    return {"content_hash": content_hash.hex(), "registered_at": registered_at, "submitter": submitter}


def register_report_on_chain(report_id: str, version: int, content_hash: str) -> str:
    if not PRIVATE_KEY:
        raise ValueError("SEPOLIA_PRIVATE_KEY is not configured.")

    if not w3.is_connected() or w3.eth.chain_id != CHAIN_ID:
        raise ConnectionError("Not connected to Sepolia.")

    account = w3.eth.account.from_key(PRIVATE_KEY)

    if version != get_latest_version(report_id) + 1:
        raise ValueError("Invalid report version for blockchain registration.")

    hash_bytes = Web3.to_bytes(hexstr=content_hash if content_hash.startswith("0x") else "0x" + content_hash)

    transaction = contract.functions.registerReport(report_id, version, hash_bytes).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "chainId": CHAIN_ID,
        "gas": 600000,
        "gasPrice": w3.eth.gas_price
    })

    signed_transaction = w3.eth.account.sign_transaction(transaction, PRIVATE_KEY)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)

    if receipt.status != 1:
        raise RuntimeError("Blockchain registration transaction failed.")

    return transaction_hash.hex()
