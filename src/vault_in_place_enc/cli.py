# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

"""Command-line interface for the Vault In-Place Encryption package."""

from pathlib import Path

import click

from .crypto import EncryptionMetadata, VaultInPlaceCrypto


@click.group()
@click.option(
    "--key-name",
    required=True,
    type=str,
    help="Name of the Vault Transit key under which to generate a data key",
)
@click.option(
    "--mount-path",
    type=str,
    default="transit",
    help="Mount path of the Vault Transit engine to use",
)
@click.pass_context
def main(ctx, key_name: str, mount_path: str):  # pylint: disable=C0116
    ctx.ensure_object(dict)

    ctx.obj["vault_mount_path"] = mount_path
    ctx.obj["vault_key_name"] = key_name


@main.command()
@click.argument(
    "source",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
)
@click.pass_context
def encrypt(ctx, source: str) -> None:  # pylint: disable=C0116
    src_path = Path(source)
    dest_path = src_path.with_suffix(".enc")
    meta_path = src_path.with_suffix(".meta")

    # Check that the output files don't already exist
    if any(f.exists() and f.stat().st_size > 0 for f in (dest_path, meta_path)):
        click.echo(
            err=True,
            message=(
                f"Output file '{dest_path}' or metadata file '{meta_path}' already "
                "exists and is not empty. Aborting to prevent data loss."
            ),
        )
        return

    # Instantiate the encryptor
    vault_ipe = VaultInPlaceCrypto(
        mount_path=ctx.obj["vault_mount_path"], key_name=ctx.obj["vault_key_name"]
    )

    # Open contexts for the source, destination, and metadata files and encrypt the data
    with src_path.open("rb") as src:
        with dest_path.open("wb") as dst, meta_path.open("wb") as meta:
            vault_ipe.encrypt(src, dst, meta)


@main.command()
@click.argument(
    "source",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
)
@click.argument(
    "meta",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
)
@click.argument(
    "dest",
    type=click.Path(exists=False),
)
@click.pass_context
def decrypt(ctx, source: str, meta: str, dest: str) -> None:  # pylint: disable=C0116
    src_path = Path(source)
    meta_path = Path(meta)
    dest_path = Path(dest)

    # Check that the output file doesn't already exist
    if dest_path.exists():
        click.echo(
            err=True,
            message=f"Output file '{dest_path}' already exists. Aborting to prevent data loss.",
        )
        return

    # Check that the encryption metadata can be loaded
    try:
        encryption_meta = EncryptionMetadata.load(meta_path)
    except Exception as exc:
        raise RuntimeError("Failed to load encryption metadata") from exc

    # Instantiate the decryptor
    vault_ipe = VaultInPlaceCrypto(
        mount_path=ctx.obj["vault_mount_path"], key_name=ctx.obj["vault_key_name"]
    )

    # Open contexts for the source, destination, and metadata files and decrypt the data
    with src_path.open("rb") as src, dest_path.open("wb") as dst:
        vault_ipe.decrypt(src, dst, encryption_meta)
