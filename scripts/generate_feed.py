#!/usr/bin/env python3

import ipaddress
import os
from datetime import datetime, timezone
from pathlib import Path

import requests


API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OUTPUT_FILE = Path("feed/otx-ipv4.txt")

PAGE_SIZE = 50
MAX_PAGES = 200


def normalize_ipv4(value):
    """Valida, normaliza e aceita somente IPv4 público."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)

        if network.version != 4:
            return None

        # Descarta IP privado, loopback, multicast e reservado.
        if not network.is_global:
            return None

        if network.prefixlen == 32:
            return str(network.network_address)

        return str(network)

    except (ValueError, AttributeError):
        return None


def get_otx_page(url, api_key, params=None):
    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
        "User-Agent": "OTX-FortiGate-Feed/1.0",
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=90,
    )

    response.raise_for_status()
    return response.json()


def main():
    api_key = os.environ.get("OTX_API_KEY")

    if not api_key:
        raise RuntimeError("O segredo OTX_API_KEY não foi informado.")

    indicators = set()
    url = API_URL
    params = {
        "limit": PAGE_SIZE,
        "page": 1,
    }

    page_number = 0

    while url and page_number < MAX_PAGES:
        page_number += 1
        print(f"Consultando página {page_number}...")

        data = get_otx_page(url, api_key, params)

        # Depois da primeira consulta, a URL "next" já contém a paginação.
        params = None

        pulses = data.get("results", [])

        for pulse in pulses:
            for item in pulse.get("indicators", []):
                indicator_type = item.get("type", "")
                indicator_value = item.get("indicator", "")

                if indicator_type not in {"IPv4", "CIDR"}:
                    continue

                normalized = normalize_ipv4(indicator_value)

                if normalized:
                    indicators.add(normalized)

        url = data.get("next")

        if not pulses:
            break

    if not indicators:
        raise RuntimeError(
            "Nenhum IPv4 público foi encontrado. "
            "Confirme a API key e se a conta possui Pulses assinados."
        )

    sorted_indicators = sorted(
        indicators,
        key=lambda item: (
            int(ipaddress.ip_network(item, strict=False).network_address),
            ipaddress.ip_network(item, strict=False).prefixlen,
        ),
    )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        "# AlienVault OTX IPv4 Threat Feed",
        f"# Updated UTC: {timestamp}",
        f"# Entries: {len(sorted_indicators)}",
        *sorted_indicators,
        "",
    ]

    OUTPUT_FILE.write_text("\n".join(lines), encoding="utf-8")

    print(f"Arquivo criado: {OUTPUT_FILE}")
    print(f"Quantidade de indicadores: {len(sorted_indicators)}")


if __name__ == "__main__":
    main()
