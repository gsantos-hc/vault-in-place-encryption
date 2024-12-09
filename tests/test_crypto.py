# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=C0114,C0115,C0116
"""Test suite for crypto module."""

import json
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM

from vault_in_place_enc.crypto import EncryptionMetadata as EncMeta
from vault_in_place_enc.crypto import crypto_stream


class TestEncryptionMetadata:
    @pytest.fixture
    def sample_metadata_args(self) -> dict:
        return {"wrapped_key": "123", "nonce": "123", "tag": "123"}

    @pytest.fixture
    def sample_metadata(self, sample_metadata_args: dict) -> EncMeta:
        return EncMeta(**sample_metadata_args)

    def test_key_must_be_str(self):
        with pytest.raises(ValueError):
            EncMeta(wrapped_key=123, nonce="123", tag="123")  # type:ignore

    def test_nonce_must_be_str(self):
        with pytest.raises(ValueError):
            EncMeta(wrapped_key="123", nonce=123, tag="123")  # type:ignore

    def test_tag_must_be_str(self):
        with pytest.raises(ValueError):
            EncMeta(wrapped_key="123", nonce="123", tag=123)  # type:ignore

    def test_digest_must_be_str(self):
        with pytest.raises(ValueError):
            EncMeta(wrapped_key="123", nonce="123", tag="123", digest=123)  # type:ignore

    def test_dict_has_required_attrs(
        self, sample_metadata_args: dict, sample_metadata: EncMeta
    ):
        assert sample_metadata.to_dict() == {**sample_metadata_args, "digest": None}

    def test_json_has_required_attrs(
        self, sample_metadata_args: dict, sample_metadata: EncMeta
    ):
        expected_json = json.dumps({**sample_metadata_args, "digest": None})
        assert sample_metadata.to_json() == expected_json

    def test_can_load_json_file(self, sample_metadata: EncMeta):
        with NamedTemporaryFile(delete_on_close=False) as temp_file:
            temp_file_path = Path(temp_file.name)
            sample_metadata.save(temp_file_path)
            loaded_metadata = EncMeta.load(temp_file_path)
            assert loaded_metadata == sample_metadata


class TestCryptoStream:
    @pytest.fixture
    def aes_key(self) -> bytes:
        return bytes.fromhex(
            "31d145ac12a520b8588d612226597f5e62adc494fcbd9685d67e7ef5e83cfac6"
        )

    @pytest.fixture
    def aes_iv(self) -> bytes:
        return bytes.fromhex("bf768363f8b491583dc15231")

    @pytest.fixture
    def aes_gcm_cipher(self, aes_key: bytes, aes_iv: bytes) -> Cipher:
        return Cipher(
            algorithm=AES(aes_key), mode=GCM(aes_iv), backend=default_backend()
        )

    def test_decrypt_encrypted_data(self, aes_gcm_cipher: Cipher):
        self._encrypt_decrypt(b"hello world", aes_gcm_cipher)

    def test_encrypt_data_of_block_size(self, aes_gcm_cipher: Cipher):
        self._encrypt_decrypt(b"1" * 16, aes_gcm_cipher)

    def test_encrypt_data_not_of_block_size(self, aes_gcm_cipher: Cipher):
        self._encrypt_decrypt(b"1" * 21, aes_gcm_cipher)

    @staticmethod
    def _encrypt_decrypt(message: bytes, cipher: Cipher):
        internal_cipher = deepcopy(cipher)
        input_stream = BytesIO(message)
        output_stream = BytesIO()
        check_stream = BytesIO()

        # Encrypt `input_stream` data into `output_stream`
        encryptor = internal_cipher.encryptor()
        crypto_stream(input_stream, output_stream, encryptor)

        # Grab the tag from the encryptor and modify the cipher
        internal_cipher.mode = GCM(cipher.mode.initialization_vector, encryptor.tag)
        decryptor = internal_cipher.decryptor()

        # Decrypt `output_stream` data into `check_stream` and compare
        output_stream.seek(0)
        crypto_stream(output_stream, check_stream, decryptor)
        assert check_stream.getvalue() == message
