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
from dataclasses import dataclass
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


# Tuya's low-power TuyaMCU firmware for the XR806 carries this build name
LOW_POWER_FIRMWARE = b"xr806_lowpower_common_ty"
# XR806 GPIOs that can wake the chip from standby (see the xr806 component)
STANDBY_WAKE_GPIOS = (11, 12, 13, 19, 20)


def detect_low_power(flash: bytes, storage: Dict[str, StorageValue]) -> List[str]:
    """Reasons why the module runs Tuya's low-power TuyaMCU firmware."""
    reasons = []
    if LOW_POWER_FIRMWARE in flash:
        reasons.append(f"firmware '{LOW_POWER_FIRMWARE.decode()}'")
    if isinstance(storage.get("wake_up_mcu_io"), dict):
        reasons.append("storage entry 'wake_up_mcu_io'")
    return reasons


def parse_product_info(data: bytes) -> Optional[dict]:
    """
    Wake and sleep fields of the MCU's product info (CMD01 reply): 'wk' (MCU wakes
    the module), 'mwk' (module wakes the MCU) and 'sm' (sleep mode). Works on the
    reply text and on an MCU firmware dump, which can hold several 'sm' variants.
    """
    import re

    def numbers(key: bytes) -> List[int]:
        pattern = rb'"' + key + rb'"\s*:\s*(\d+)'
        return sorted({int(m) for m in re.findall(pattern, data)})

    info_ = dict(
        pid=sorted({m.decode() for m in re.findall(rb'"p"\s*:\s*"\W*(\w{8,})', data)}),
        wk=numbers(b"wk"),
        mwk=numbers(b"mwk"),
        sm=numbers(b"sm"),
    )
    if not info_["wk"] and not info_["mwk"] and not info_["sm"]:
        return None
    return info_


def _standby_config(product: dict, opts: "YamlOptions") -> dict:
    """xr806.standby and xr806.wlan for a low-power device."""
    # Standby is decided at run time: the tuya component reads wk, mwk and sm
    # from the MCU's product info, takes the wake pins from it when they are
    # not set here, and only lets the module sleep with sm 1 or 2.
    standby = dict(enabled=True, require_external_sync=True)
    wk = product.get("wk", [])
    if len(wk) == 1 and wk[0] in STANDBY_WAKE_GPIOS:
        standby["wake_pin"] = f"PA{wk[0]}"
        standby["wake_edge"] = "falling"
    elif wk:
        warning(f"MCU wake line wk={wk} cannot wake the XR806")
    if product and not set(product.get("sm", [])) & {1, 2}:
        info("The MCU product info allows no standby (sm); it stays off at run time")
    if opts.wlan == "suspend":
        wlan = {
            "_1": "In standby the WLAN is off: the device is offline while it sleeps",
            "network_suspend": True,
        }
    else:
        wlan = {
            "_1": "In standby the WLAN stays connected: Home Assistant sees the device",
            "_2": "online, and every packet to it (HA, web, OTA) wakes the CPU",
            "dtim": opts.dtim,
            "stay_connected": True,
        }
    return dict(standby=standby, wlan=wlan)


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


@dataclass
class YamlOptions:
    """Settings for low-power devices that no dump holds."""

    standby: bool = True
    # "connected": WLAN stays up in standby; "suspend": WLAN off in standby
    wlan: str = "connected"
    dtim: int = 3
    mcu_wake_pin: bool = True


def build_yaml(
    storage: Dict[str, StorageValue],
    schema: Optional[dict],
    low_power: bool = False,
    product: Optional[dict] = None,
    opts: YamlOptions = YamlOptions(),
) -> str:
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
    product = product or {}
    if low_power:
        tuya["protocol"] = "low_power"
        wake = storage.get("wake_up_mcu_io")
        if not opts.mcu_wake_pin:
            info("MCU wake pin left to the product info at run time")
        elif isinstance(wake, dict) and (pin := tuya_io_to_pin(wake.get("io", -1))):
            inverted = wake.get("level", 0) == 0
            tuya["mcu_wake_pin"] = dict(number=pin, inverted=inverted)
        elif len(product.get("mwk", [])) == 1:
            if pin := tuya_io_to_pin(product["mwk"][0]):
                # the original firmware drives the wake line low by default
                tuya["mcu_wake_pin"] = dict(number=pin, inverted=True)
        if opts.standby:
            header["xr806"].update(_standby_config(product, opts))
            if opts.wlan == "connected" and isinstance(data.get("wifi"), dict):
                # stay_connected needs a Wi-Fi power save mode
                data["wifi"]["power_save_mode"] = "light"
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
@click.option(
    "-m",
    "--mcu-dump",
    help="MCU firmware dump (optional): fixes the wake pins from its product info "
    "instead of at run time",
    type=click.File("rb"),
)
@click.option(
    "-p",
    "--product-info",
    help="MCU product info (optional) as logged by the tuya component, e.g. "
    '\'{"p":"...","v":"1.0.0","wk":20,"mwk":28,"sm":1}\'',
)
@click.option(
    "--standby/--no-standby",
    default=True,
    help="Low-power devices: set up XR806 standby (default: on)",
)
@click.option(
    "--wlan",
    type=click.Choice(["connected", "suspend"]),
    default="connected",
    help="WLAN in standby: stay connected, or switch off (default: connected)",
)
@click.option(
    "--dtim",
    type=click.IntRange(1, 30),
    default=3,
    help="DTIM period while connected in standby (default: 3)",
)
@click.option(
    "--mcu-wake-pin/--no-mcu-wake-pin",
    default=True,
    help="Write the MCU wake pin from the dump; without it, it is learned "
    "from the MCU's product info at run time (default: on)",
)
def cli(
    dump,
    output,
    schema_out,
    schema_file,
    yaml_out,
    mcu_dump,
    product_info,
    standby,
    wlan,
    dtim,
    mcu_wake_pin,
):
    flash = dump.read()
    storage = read_tuya_storage(flash)
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

    reasons = detect_low_power(flash, storage)
    if reasons:
        info(f"Low-power TuyaMCU device: {', '.join(reasons)}")
    product = None
    if mcu_dump:
        product = parse_product_info(mcu_dump.read())
    elif product_info:
        product = parse_product_info(product_info.encode())
    if (mcu_dump or product_info) and not product:
        warning("No wk/mwk/sm fields found in the MCU product info")
    if product:
        info(
            f"MCU product info: wk={product['wk']} mwk={product['mwk']} "
            f"sm={product['sm']}"
        )

    if yaml_out:
        opts = YamlOptions(
            standby=standby, wlan=wlan, dtim=dtim, mcu_wake_pin=mcu_wake_pin
        )
        yaml_out.write(build_yaml(storage, schema, bool(reasons), product, opts))
        info(f"Wrote {yaml_out.name}")


if __name__ == "__main__":
    cli()
