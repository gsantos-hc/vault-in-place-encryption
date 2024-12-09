# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=C0114,C0115,C0116
"""Test suite for crypto module."""

import json
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from vault_in_place_enc.crypto import EncryptionMetadata as EncMeta


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
