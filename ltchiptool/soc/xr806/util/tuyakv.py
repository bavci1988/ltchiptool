#  Copyright (c) 2026 bavci1988.

"""
Reader for the TuyaOS key-value storage of XR806 (Tuya WXU) flash dumps.

The storage uses the TuyaOS "simple flash" layout, encrypted with AES-128-ECB:

- A key record, encrypted with a fixed master key, holds a per-device key:
  magic 0x13579753, the byte sum of the key, then the 16-byte key.
- The data key is the byte-wise sum (mod 256) of that key and a fixed key
  ("HHRRQbyemofrtytf" plus "8710", repeated).
- Data blocks are 4 KiB, made of 32 slots of 128 bytes. Slot 0 is the block header
  (magic 0x135726AB, then the logical block number at +8). The other slots are
  either entry headers or value data.
- An entry header holds the byte sum of the value (+0), the value length (+4),
  the name length (+17) and the name (+18), followed by the logical block number and
  the first and last slot of the value.

The result has the same shape as the "Storage JSON" of upk2esphome: a dict of entry
names and their values, with JSON values already parsed.
"""

import json
import struct
from logging import info, warning
from typing import Dict, List, Optional, Tuple, Union

import click

MASTER_KEY = b"qwertyuiopasdfgh"
FIXED_KEY_SOURCE = b"HHRRQbyemofrtytf"
FIXED_KEY_TABLE = b"8710"
KEY_RECORD_MAGIC = 0x13579753
BLOCK_MAGIC = 0x135726AB
BLOCK_SIZE = 0x1000
SLOT_SIZE = 0x80

StorageValue = Union[dict, list, str, int, float, bool, None]


def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            AES = None
    if AES is not None:
        return AES.new(key, AES.MODE_ECB).decrypt(data)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        return Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(data)
    except ImportError:
        pass
    from pyaes import AESModeOfOperationECB

    aes = AESModeOfOperationECB(key)
    return b"".join(aes.decrypt(data[i : i + 16]) for i in range(0, len(data), 16))


def fixed_key() -> bytes:
    return bytes(
        (FIXED_KEY_SOURCE[i] + FIXED_KEY_TABLE[i & 3]) & 0xFF for i in range(16)
    )


def find_device_key(flash: bytes) -> Optional[Tuple[int, bytes]]:
    """Find the key record. Returns its offset and the per-device key."""
    for offset in range(0, len(flash) - 32, BLOCK_SIZE):
        head = _aes_ecb_decrypt(MASTER_KEY, flash[offset : offset + 32])
        magic, key_sum = struct.unpack_from("<II", head)
        if magic == KEY_RECORD_MAGIC and sum(head[8:24]) == key_sum:
            return offset, head[8:24]
    return None


def data_key(device_key: bytes) -> bytes:
    return bytes((a + b) & 0xFF for a, b in zip(device_key, fixed_key()))


def _find_blocks(flash: bytes, key: bytes) -> Dict[int, List[Tuple[int, bytes]]]:
    blocks: Dict[int, List[Tuple[int, bytes]]] = {}
    for offset in range(0, len(flash) - BLOCK_SIZE + 1, BLOCK_SIZE):
        head = _aes_ecb_decrypt(key, flash[offset : offset + 16])
        if struct.unpack_from("<I", head)[0] != BLOCK_MAGIC:
            continue
        block = _aes_ecb_decrypt(key, flash[offset : offset + BLOCK_SIZE])
        number = struct.unpack_from("<H", block, 8)[0]
        blocks.setdefault(number, []).append((offset, block))
    return blocks


def _parse_entry(slot: bytes) -> Optional[Tuple[str, int, int, int, int, int]]:
    if slot[0:4] == b"\xff\xff\xff\xff":
        return None
    value_sum, length = struct.unpack_from("<II", slot)
    name_len = slot[17]
    if not 1 < name_len <= SLOT_SIZE - 22 or length > 0x10000:
        return None
    name = slot[18 : 18 + name_len - 1]
    if slot[18 + name_len - 1] != 0 or not name:
        return None
    if not all(c == 0x5F or 0x30 <= c <= 0x39 or 0x61 <= c <= 0x7A for c in name):
        return None
    block, first, last = struct.unpack_from("<HBB", slot, 18 + name_len)
    if first == 0 or last < first or last >= BLOCK_SIZE // SLOT_SIZE:
        return None
    return name.decode(), value_sum, length, block, first, last


def _decode_value(value: bytes) -> StorageValue:
    text = value.rstrip(b"\x00")
    try:
        return json.loads(text.decode())
    except (UnicodeDecodeError, ValueError):
        pass
    try:
        decoded = text.decode()
        if decoded.isprintable():
            return decoded
    except UnicodeDecodeError:
        pass
    return value.hex()


def read_tuya_storage(flash: bytes) -> Optional[Dict[str, StorageValue]]:
    """Decrypt and parse the Tuya storage. Returns None if none is found."""
    found = find_device_key(flash)
    if not found:
        return None
    key = data_key(found[1])
    blocks = _find_blocks(flash, key)
    if not blocks:
        return None

    entries: Dict[str, Tuple[int, StorageValue]] = {}
    for number, copies in blocks.items():
        for _, block in copies:
            # a copy with a higher write counter (+10) is newer
            counter = struct.unpack_from("<H", block, 10)[0]
            for pos in range(SLOT_SIZE, BLOCK_SIZE, SLOT_SIZE):
                entry = _parse_entry(block[pos : pos + SLOT_SIZE])
                if not entry:
                    continue
                name, value_sum, length, target, first, last = entry
                for _, data in blocks.get(target, []):
                    value = data[first * SLOT_SIZE : (last + 1) * SLOT_SIZE][:length]
                    if len(value) == length and sum(value) == value_sum:
                        break
                else:
                    continue
                if name in entries and entries[name][0] >= counter:
                    continue
                entries[name] = (counter, _decode_value(value))
    return {name: value for name, (_, value) in sorted(entries.items())}


def tuya_io_to_pin(io: int) -> Optional[str]:
    """Tuya GPIO number to XR806 pin name (PA0..PA23 are 0..23, PB0.. follow)."""
    if 0 <= io < 24:
        return f"PA{io}"
    if 24 <= io < 24 + 16:
        return f"PB{io - 24}"
    return None


def pull_schema(storage: Dict[str, StorageValue]) -> dict:
    """
    Fetch the device's DP schema with upk2esphome. This sends the device's
    Tuya credentials to the upk2esphome schema server, which asks the Tuya cloud.
    """
    try:
        from ltctplugin.upk2esphome.work_schema import UpkSchemaThread
        from upk2esphome import ConfigData
    except ImportError:
        raise click.ClickException("Install upk2esphome: pip install upk2esphome")
    config = ConfigData.build(storage, {})
    result = {}
    thread = UpkSchemaThread(
        device=config.data_device,
        software=config.data_software,
        license_=config.data_license,
        schema_id=config.schema_id,
        on_success=result.update,
    )
    thread.run_impl()
    return result


def build_yaml(storage: Dict[str, StorageValue], schema: Optional[dict]) -> str:
    """ESPHome YAML for the XR806 port: XR806 header plus upk2esphome entities."""
    try:
        from upk2esphome import Opts, upk2esphome
        from upk2esphome.result import YamlResult
    except ImportError:
        raise click.ClickException("Install upk2esphome: pip install upk2esphome")

    extras = {}
    if schema:
        model = schema.get("modelResponse", {}).get("model", {})
        category = schema.get("detailsResponse", {}).get("category", None)
        if model:
            extras = dict(model=model, category=category)
    result = upk2esphome(storage, Opts(), extras)
    if result.errors:
        raise click.ClickException("\n".join(result.errors))
    for text in result.warnings:
        warning(text)

    data = dict(result.data)
    upk_tuya = data.get("tuya") or {}
    for key in ("bk72xx", "rtl87xx", "ln882x", "libretiny", "uart", "tuya"):
        data.pop(key, None)
    data["text_sensor"] = [
        item
        for item in data.get("text_sensor", [])
        if item.get("platform") != "libretiny"
    ]
    if not data["text_sensor"]:
        data.pop("text_sensor")

    # current ESPHome removed the API password; use encryption instead
    data["api"] = dict(encryption=dict(key="!secret api_encryption_key"))
    if isinstance(data.get("ota"), dict) and not data["ota"].get("password"):
        data["ota"].pop("password", None)
    header = dict(esphome=dict(name="xr806-tuya"), xr806=dict(board="wxu"))
    data.pop("esphome", None)
    baud = (storage.get("baud_cfg") or {}).get("baud", 115200)
    uart = dict(id="mcu_uart", tx_pin="PB0", rx_pin="PB1", baud_rate=baud)
    uart["rx_buffer_size"] = 256
    tuya = dict(upk_tuya)
    tuya["uart_id"] = "mcu_uart"
    wake = storage.get("wake_up_mcu_io")
    if isinstance(wake, dict) and (pin := tuya_io_to_pin(wake.get("io", -1))):
        # a module that wakes the MCU before sending is a low-power TuyaMCU device
        tuya["protocol"] = "low_power"
        tuya["mcu_wake_pin"] = dict(number=pin, inverted=wake.get("level", 1) == 0)
    ordered = dict(header)
    ordered.update(data)
    ordered["uart"] = uart
    ordered["tuya"] = tuya
    for key in list(data):
        if key not in (
            "logger",
            "api",
            "ota",
            "wifi",
            "web_server",
            "captive_portal",
            "mdns",
        ):
            ordered[key] = ordered.pop(key)

    out = YamlResult()
    out.data = ordered
    return out.text


@click.command(
    help="Read the Tuya storage from an XR806 flash dump",
)
@click.argument("dump", type=click.File("rb"))
@click.option(
    "-o",
    "--output",
    help="Write the storage as JSON (for upk2esphome)",
    type=click.File("w"),
)
@click.option(
    "-s",
    "--schema",
    "schema_out",
    help="Download the DP schema with upk2esphome and save it as JSON "
    "(sends the device's Tuya credentials to the upk2esphome server)",
    type=click.File("w"),
)
@click.option(
    "-S",
    "--schema-file",
    help="Use a DP schema JSON saved before",
    type=click.File("r"),
)
@click.option(
    "-y",
    "--yaml",
    "yaml_out",
    help="Write an ESPHome YAML for the XR806 port",
    type=click.File("w"),
)
def cli(dump, output, schema_out, schema_file, yaml_out):
    storage = read_tuya_storage(dump.read())
    if storage is None:
        raise click.ClickException("No Tuya storage found in the dump")
    info(f"Found {len(storage)} entries:")
    for name, value in storage.items():
        kind = type(value).__name__
        info(f" - {name} ({kind})")
    if output:
        json.dump(storage, output, indent=4)
        warning(
            "The JSON file holds the device's Tuya credentials "
            "(uuid, auth_key, Wi-Fi). Keep it private."
        )

    schema = None
    if schema_file:
        schema = json.load(schema_file)
    elif schema_out:
        info("Downloading the DP schema...")
        schema = pull_schema(storage)
    if schema and schema_out:
        json.dump(schema, schema_out, indent=4)
    if schema:
        details = schema.get("detailsResponse", {})
        model = schema.get("modelResponse", {}).get("model", {})
        info(f"Schema: {details.get('category_name')} / {details.get('model')}")
        if not model:
            warning("The schema response has no DP model")

    if yaml_out:
        yaml_out.write(build_yaml(storage, schema))
        info(f"Wrote {yaml_out.name}")


if __name__ == "__main__":
    cli()
