from __future__ import annotations

import httpx

from fusion_siem.adapters.errors import DestinationNotConfigured
from fusion_siem.adapters.https import HttpsAdapter
from fusion_siem.adapters.qradar import QRadarAdapter
from fusion_siem.adapters.rapid7 import Rapid7Adapter
from fusion_siem.adapters.splunk import SplunkAdapter
from fusion_siem.config import Settings

Adapter = HttpsAdapter | SplunkAdapter | Rapid7Adapter | QRadarAdapter


def effective_destination(settings: Settings) -> str:
    dest = (settings.destination or "").strip().lower()
    if dest:
        return dest
    if (settings.forward_url or "").strip():
        return "any"
    return "none"


def _required(value: str | None, name: str) -> str:
    text = (value or "").strip()
    if not text:
        raise DestinationNotConfigured(f"{name} is required")
    return text


def build_destination(
    settings: Settings,
    client: httpx.Client | None = None,
) -> Adapter | None:
    dest = effective_destination(settings)
    if dest == "none":
        return None
    if dest == "any":
        url = _required(settings.forward_url, "FUSION_SIEM_FORWARD_URL")
        return HttpsAdapter(url, settings.forward_token, client=client)
    if dest == "splunk":
        return SplunkAdapter(
            url=_required(settings.splunk_hec_url, "FUSION_SIEM_SPLUNK_HEC_URL"),
            token=_required(settings.splunk_hec_token, "FUSION_SIEM_SPLUNK_HEC_TOKEN"),
            index=(settings.splunk_index or "").strip() or None,
            sourcetype=(settings.splunk_sourcetype or "fusion_siem:v1").strip()
            or "fusion_siem:v1",
            client=client,
        )
    if dest == "rapid7":
        return Rapid7Adapter(
            url=_required(settings.rapid7_url, "FUSION_SIEM_RAPID7_URL"),
            token=_required(settings.rapid7_token, "FUSION_SIEM_RAPID7_TOKEN"),
            client=client,
        )
    if dest == "qradar":
        host = _required(settings.qradar_host, "FUSION_SIEM_QRADAR_HOST")
        return QRadarAdapter(host=host, port=settings.qradar_port)
    raise DestinationNotConfigured(f"unknown destination {dest}")
