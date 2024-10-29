# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

"""Core cryptographic classes for the Vault In-Place Encryption package."""

import json
import secrets
from dataclasses import dataclass
from io import BufferedReader, BufferedWriter
from pathlib import Path
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import Cipher, CipherContext
from hvac import Client as VaultClient

from vault_in_place_enc.vault import decrypt_data_key, generate_data_key

NONCE_LEN = 12


@dataclass
class EncryptionMetadata:
    """Data class for holding metadata required to decrypt a file."""

    wrapped_key: str
    nonce: str
    tag: str
    digest: Optional[str] = None

    def __post_init__(self):
        for var in (self.wrapped_key, self.nonce, self.tag):
            if not isinstance(var, str):
                raise ValueError(
                    "Wrapped key, nonce, and tag must be hex-encoded strings"
                )

        if self.digest is not None and not isinstance(self.digest, str):
            raise ValueError("Digest, if provided, must be a hex-encoded string")

    def to_dict(self) -> dict:
        """Returns a dictionary representation of the encryption metadata object."""
        return {
            "wrapped_key": self.wrapped_key,
            "nonce": self.nonce,
            "tag": self.tag,
            "digest": self.digest,
        }

    def to_json(self) -> str:
        """Returns a JSON-serialized string representation of the encryption metadata object."""
        return json.dumps(self.to_dict())

    def save(self, file: Path) -> None:
        """Serializes the encryption metadata into JSON and writes it out to `file`.

        Args:
            file (Path): The file to write the metadata to.
        """
        with file.open("w") as fout:
            json.dump(obj=self.to_dict(), fp=fout)

    @classmethod
    def load(cls, file: Path) -> "EncryptionMetadata":
        """Instantiates an EncryptionMetadata object from a JSON file.

        Args:
            file (Path): Path to the JSON file containing the metadata.

        Returns:
            EncryptionMetadata: Instantiated encryption metadata object.
        """
        with file.open("r") as fin:
            data = json.load(fin)
            return cls(**data)


def crypto_stream(
    source: BufferedReader,
    destination: BufferedWriter,
    cipher: CipherContext,
    chunk_size: int = 1024,
):
    """Processes a `source` stream through a `cipher` encryptor/decryptor and writes the result
    to `destination` stream.

    Args:
        source (BufferedReader): The source stream to process.
        destination (BufferedWriter): The destination stream to write the processed data to.
        cipher (CipherContext): An encryptor or decryptor object.
        chunk_size (int, optional): Bytes to process at a time. Defaults to 1024.
    """
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            break
        destination.write(cipher.update(chunk))
    destination.write(cipher.finalize())


class VaultInPlaceCrypto:
    """In-place encryption and decryption of messages using Vault Transit data keys."""

    def __init__(
        self,
        key_name: str,
        mount_path: str = "transit",
        client: Optional[VaultClient] = None,
    ) -> None:
        self._key_name = key_name
        self._mount_path = mount_path
        self._client = client or VaultClient()

    @property
    def key_name(self) -> str:
        """Name of the Vault Transit key used to generate and protect data keys."""
        return self._key_name

    @property
    def mount_path(self) -> str:
        """Path where the Vault Transit engine is mounted."""
        return self._mount_path

    def encrypt(
        self,
        source: BufferedReader,
        destination: BufferedWriter,
        metadata: BufferedWriter,
    ) -> None:
        """Encrypts the contents of a `source` stream with a Vault Transit data key and writes the
        resulting ciphertext to the `destination` stream. The associated encryption metadata is
        serialized and written to the `metadata` stream.

        Args:
            source (BufferedReader): Stream of source data to encrypt
            destination (BufferedWriter): Stream to which resulting ciphertext will be written
            metadata (BufferedWriter): Stream to which encryption metadata will be written

        Raises:
            TypeError: Source is not a BufferedReader object
            TypeError: Destination is not a BufferedWriter object
            TypeError: Metadata is not a BufferedWriter object
        """
        # Check input stream types
        if not isinstance(source, BufferedReader):
            raise TypeError("Source must be a BufferedReader object")
        if not isinstance(destination, BufferedWriter):
            raise TypeError("Destination must be a BufferedWriter object")
        if not isinstance(metadata, BufferedWriter):
            raise TypeError("Metadata must be a BufferedWriter object")

        # Generate a new data key from Vault Transit
        wrapped_key, raw_key = self._generate_data_key()

        # Instantiate an encryptor with the raw data key
        nonce = self._generate_nonce()
        cipher = self._get_cipher(raw_key, nonce)
        encryptor = cipher.encryptor()

        # Encrypt the source stream and write it to the destination stream
        crypto_stream(source, destination, encryptor)

        # Write out the encryption metadata
        encryption_meta = EncryptionMetadata(
            wrapped_key, nonce.hex(), encryptor.tag.hex()
        )
        metadata.write(encryption_meta.to_json().encode())

    def decrypt(
        self,
        source: BufferedReader,
        destination: BufferedWriter,
        metadata: EncryptionMetadata,
    ) -> None:
        """Decrypts the contents of a `source` stream using the given `metadata` encryption metadata
        and writes the resulting plaintext to the `destination` stream.

        Args:
            source (BufferedReader): Stream of source data to decrypt
            destination (BufferedWriter): Stream to which resulting plaintext will be written
            metadata (EncryptionMetadata): Encryption metadata to use for decrypting `source`

        Raises:
            TypeError: Source is not a BufferedReader object
            TypeError: Destination is not a BufferedWriter object
            TypeError: Metadata is not an EncryptionMetadata object
            InvalidTag: Incorrect encryption key, nonce, or tag
            RuntimeError: Unable to decrypt source data
        """

        # Check variable types
        if not isinstance(source, BufferedReader):
            raise TypeError("Source must be a BufferedReader object")
        if not isinstance(destination, BufferedWriter):
            raise TypeError("Destination must be a BufferedWriter object")
        if not isinstance(metadata, EncryptionMetadata):
            raise TypeError("Metadata must be an EncryptionMetadata object")

        # Call Vault Transit to decrypt the data key
        raw_key = self._decrypt_data_key(metadata.wrapped_key)

        # Instantiate the decryptor
        cipher = self._get_cipher(
            raw_key, bytes.fromhex(metadata.nonce), bytes.fromhex(metadata.tag)
        )
        decryptor = cipher.decryptor()

        # Decrypt
        try:
            crypto_stream(source, destination, decryptor)
        except InvalidTag as exc:
            destination.truncate(0)
            destination.flush()
            raise InvalidTag(
                "Failed to decrypt data: key, nonce, or tag were incorrect"
            ) from exc
        except Exception as exc:
            raise RuntimeError("Failed to decrypt data") from exc

    def _generate_data_key(self) -> Tuple[str, bytes]:
        try:
            wrapped_key, raw_key = generate_data_key(
                client=self._client,
                key_name=self.key_name,
                mount_point=self.mount_path,
            )
        except Exception as exc:
            raise RuntimeError("Failed to generate data key from Vault") from exc

        return wrapped_key, raw_key

    def _decrypt_data_key(self, wrapped_key: str) -> bytes:
        try:
            return decrypt_data_key(
                wrapped_key=wrapped_key,
                client=self._client,
                key_name=self.key_name,
                mount_point=self.mount_path,
            )
        except Exception as exc:
            raise RuntimeError("Failed to decrypt data key through Vault") from exc

    def _generate_nonce(self) -> bytes:
        return secrets.token_bytes(NONCE_LEN)

    def _get_cipher(
        self, key: bytes, nonce: bytes, tag: Optional[bytes] = None
    ) -> Cipher:
        return Cipher(
            algorithm=algorithms.AES(key),
            mode=modes.GCM(nonce, tag),
            backend=default_backend(),
        )
