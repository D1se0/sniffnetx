"""SniffNex - Base de datos OUI local para resolver fabricantes de MAC.

Compatible con el formato 'manuf' de Wireshark: lineas "Hex", "Short name",
"Long name" (comentadas con #). Se puede reemplazar por un manuf completo.
"""
from __future__ import annotations

import os
from pathlib import Path

_DIR = Path(__file__).parent

# Prefijo MAC (3 primeros octetos) -> (fabricante corto, fabricante largo)
_DEFAULT_OUI = {
    "00:00:0C": ("Cisco", "Cisco Systems, Inc"),
    "00:03:93": ("Apple", "Apple, Inc."),
    "00:05:69": ("VMware", "VMware, Inc."),
    "00:0C:29": ("VMware", "VMware, Inc."),
    "00:1C:14": ("VMware", "VMware, Inc."),
    "00:50:56": ("VMware", "VMware, Inc."),
    "00:15:5D": ("Microsoft", "Microsoft Hyper-V"),
    "00:50:F2": ("Microsoft", "Microsoft Corporation"),
    "08:00:27": ("PCS", "PCS Systemtechnik / VirtualBox"),
    "52:54:00": ("Red Hat", "Red Hat / QEMU (KVM)"),
    "00:16:3E": ("Xensource", "Xensource, Inc."),
    "3C:15:C2": ("Apple", "Apple, Inc."),
    "D0:E1:40": ("Apple", "Apple, Inc."),
    "F0:18:98": ("Apple", "Apple, Inc."),
    "AC:DE:48": ("Private", "Locally administered / Privado"),
    "B8:27:EB": ("RaspberryPi", "Raspberry Pi Foundation"),
    "DC:A6:32": ("RaspberryPi", "Raspberry Pi Trading Ltd"),
    "E4:5F:01": ("RaspberryPi", "Raspberry Pi Trading Ltd"),
    "00:E0:4C": ("Realtek", "Realtek Semiconductor"),
    "00:1A:11": ("Google", "Google, Inc."),
    "F4:F5:D8": ("Google", "Google, Inc."),
    "3C:5A:B4": ("Google", "Google, Inc."),
    "00:1B:63": ("Apple", "Apple, Inc."),
    "00:25:00": ("Apple", "Apple, Inc."),
    "F0:9F:C2": ("Ubnt", "Ubiquiti Networks"),
    "84:16:F9": ("Tplink", "TP-LINK Technologies"),
    "00:09:5B": ("Netgear", "Netgear Inc."),
    "00:05:5D": ("D-Link", "D-Link Systems"),
    "00:1B:2F": ("Netgear", "Netgear Inc."),
    "00:02:B3": ("Intel", "Intel Corporation"),
    "00:1B:21": ("Intel", "Intel Corporation"),
    "00:0D:88": ("D-Link", "D-Link Systems"),
    "00:11:2F": ("ASUSTek", "ASUSTek COMPUTER INC."),
    "00:16:32": ("Samsung", "Samsung Electro Mechanics"),
    "00:1B:98": ("Samsung", "Samsung Electronics"),
    "00:21:19": ("Samsung", "Samsung Electronics"),
    "00:1E:75": ("LG", "LG Electronics"),
    "00:46:4B": ("Huawei", "Huawei Technologies"),
    "00:1A:A1": ("Cisco", "Cisco Systems, Inc"),
    "00:21:55": ("Cisco", "Cisco Systems, Inc"),
    "00:13:10": ("Linksys", "Linksys (Cisco)"),
    "02:00:00": ("Local", "Locally administered (virtual)"),
    "02:42:AC": ("Docker", "Docker / container runtime"),
}

# Patron de "manuf": mapear prefijos VMware/Intel/Apple mas usados para NICs
# dadas señuelo de 02/06/0A/0E... (localmente administradas): se resuelven como Local
_EXTRA_DOWNSTREAM = {
    "0A:00:27": ("PCS", "PCS Systemtechnik / VirtualBox"),
    "06:00:27": ("PCS", "PCS Systemtechnik / VirtualBox"),
}


def _load_manuf_file() -> dict:
    """Carga un archivo manuf externo si el usuario lo coloca en data/manuf."""
    out = {}
    external = _DIR / "data" / "manuf"
    if external.exists():
        try:
            for raw in external.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                prefix = parts[0].strip().upper()
                if len(prefix) != 8 or not prefix.count(":"):
                    continue
                short = parts[1].strip()
                long_ = parts[2].strip() if len(parts) > 2 else short
                out[prefix] = (short, long_)
        except Exception:
            pass
    return out


_EXTERNAL = _load_manuf_file()

# Prefijos parciales "00:0C:29:XX" allowidos (solo 3 octetos usados)


def lookup_mac(mac: str) -> dict:
    """Devuelve {nic_vendor, nic_vendor_long} para una MAC dada."""
    if not mac:
        return {"nic_vendor": "", "nic_vendor_long": ""}
    m = mac.upper().replace("-", ":").strip()
    # Mascara de localmente administrado: bit 0x02 del primer octeto
    try:
        first_octet = int(m[:2], 16)
    except ValueError:
        first_octet = 0
    prefix = m[:8]
    db = _EXTERNAL or _DEFAULT_OUI
    short, long_ = db.get(prefix, _DEFAULT_OUI.get(prefix, _EXTRA_DOWNSTREAM.get(prefix, (None, None))))
    if short is None:
        if first_octet & 0x02:
            short, long_ = "Local", "Locally administered (MAC aleatoria / virtual)"
        else:
            short, long_ = "Desconocido", "Fabricante desconocido (sin OUI registrado)"
    return {"nic_vendor": short, "nic_vendor_long": long_}


def is_randomized_mac(mac: str) -> bool:
    """MAC aleatorizada: bit local (0x02) activado y segundo octeto tipico 2/6/A/E."""
    if not mac or len(mac) < 8:
        return False
    core = mac.upper().replace("-", ":")[:8]
    try:
        second = int(core[3:5], 16)
        first = int(core[0:2], 16)
    except ValueError:
        return False
    return bool(first & 0x02) and second in {0x2, 0x6, 0xA, 0xE, 0x2E, 0xEE}
