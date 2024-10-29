from base64 import b64decode
from typing import Tuple

from hvac import Client as VaultClient


def generate_data_key(
    client: VaultClient,
    key_name: str,
    mount_point: str,
    bits: int = 256,
) -> Tuple[str, bytes]:
    """Calls the Vault Transit API to retrieve a data key for in-place encryption.

    Args:
        client (VaultClient): Instance of `hvac.Client` to use for Vault API calls
        key_name (str): Name of the Vault Transit key from which to generate the data key
        mount_point (str): Vault Transit engine mount point
        bits (int, optional): Length of encryption data key in bits. Defaults to 256.

    Raises:
        RuntimeError: Unable to generate data key from Vault

    Returns:
        Tuple[str, bytes]: Base64-encoded wrapped data key and raw bytes data key
    """
    try:
        res = client.secrets.transit.generate_data_key(
            name=key_name, mount_point=mount_point, bits=bits, key_type="plaintext"
        )
        return res["data"]["ciphertext"], b64decode(res["data"]["plaintext"])
    except Exception as exc:
        raise RuntimeError("Failed to generate data key from Vault") from exc


def decrypt_data_key(
    wrapped_key: str,
    client: VaultClient,
    key_name: str,
    mount_point: str,
) -> bytes:
    """Calls the Vault Transit API to decrypt a wrapped data key.

    Args:
        wrapped_key (str): Vault-wrapped data key
        client (VaultClient): Instance of `hvac.Client` to use for Vault API calls
        key_name (str): Name of the Vault Transit key that protects the data key
        mount_point (str): Mount point of the Vault Transit engine

    Raises:
        RuntimeError: Unable to unwrap data key from Vault

    Returns:
        bytes: Raw encryption data key
    """
    try:
        res = client.secrets.transit.decrypt_data(
            name=key_name,
            ciphertext=wrapped_key,
            mount_point=mount_point,
        )
        return b64decode(res["data"]["plaintext"])
    except Exception as exc:
        raise RuntimeError("Failed to decrypt data key") from exc
