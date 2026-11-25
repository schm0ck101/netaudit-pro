"""Configuration réseau du poste d'audit : cartes, adresses, passerelles, DNS,
DHCP, routes et compteurs (erreurs, broadcast).

Collecte par PowerShell 5.1 (CIM, noms de classes indépendants de la langue),
puis conversion en réseaux IPv4 à analyser.
"""
from __future__ import annotations

import ipaddress
import logging
import time

from . import ps

log = logging.getLogger(__name__)

SCRIPT = r"""
TL 'adapters' {
  Get-NetAdapter -ErrorAction Stop | ForEach-Object {
    [ordered]@{ index = [int]$_.ifIndex; name = $_.Name; desc = $_.InterfaceDescription; status = "$($_.Status)";
      speed = [int64]$_.ReceiveLinkSpeed; tx_speed = [int64]$_.TransmitLinkSpeed; full_duplex = $_.FullDuplex;
      media = "$($_.PhysicalMediaType)"; mac = "$($_.MacAddress)"; virtual = [bool]$_.Virtual; hidden = [bool]$_.Hidden;
      driver = "$($_.DriverVersionString)"; driver_date = "$($_.DriverDate)"; vlan = $_.VlanID; mtu = [int]$_.MtuSize }
  }
}
TL 'ipconfig' {
  Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' | ForEach-Object {
    [ordered]@{ index = [int]$_.InterfaceIndex; desc = $_.Description; ip = @($_.IPAddress); mask = @($_.IPSubnet);
      gateway = @($_.DefaultIPGateway); dns = @($_.DNSServerSearchOrder); dhcp = [bool]$_.DHCPEnabled;
      dhcp_server = $_.DHCPServer; lease_obtained = (D $_.DHCPLeaseObtained); lease_expires = (D $_.DHCPLeaseExpires);
      domain = $_.DNSDomain; suffixes = @($_.DNSDomainSuffixSearchOrder); wins = $_.WINSPrimaryServer; mac = $_.MACAddress }
  }
}
TL 'stats' {
  Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface | ForEach-Object {
    [ordered]@{ name = $_.Name; rx_bytes = [int64]$_.BytesReceivedPersec; tx_bytes = [int64]$_.BytesSentPersec;
      rx_ucast = [int64]$_.PacketsReceivedUnicastPersec; rx_nucast = [int64]$_.PacketsReceivedNonUnicastPersec;
      rx_discard = [int64]$_.PacketsReceivedDiscarded; rx_err = [int64]$_.PacketsReceivedErrors; rx_unknown = [int64]$_.PacketsReceivedUnknown;
      tx_discard = [int64]$_.PacketsOutboundDiscarded; tx_err = [int64]$_.PacketsOutboundErrors; queue = [int64]$_.OutputQueueLength;
      bandwidth = [int64]$_.CurrentBandwidth }
  }
}
TL 'routes' {
  Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetRoute -Filter 'AddressFamily = 2' | ForEach-Object {
    [ordered]@{ prefix = $_.DestinationPrefix; next_hop = $_.NextHop; index = [int]$_.InterfaceIndex; metric = [int]$_.RouteMetric }
  }
}
T 'host' {
  $cs = Get-CimInstance Win32_ComputerSystem
  [ordered]@{ name = $env:COMPUTERNAME; domain = $cs.Domain; part_of_domain = [bool]$cs.PartOfDomain; user = "$env:USERDOMAIN\$env:USERNAME" }
}
T 'firewall' {
  @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ name = "$($_.Name)"; enabled = "$($_.Enabled)" } })
}
T 'profiles' {
  @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ index = [int]$_.InterfaceIndex; name = $_.Name; category = "$($_.NetworkCategory)"; ipv4 = "$($_.IPv4Connectivity)" } })
}
"""

STATS_SCRIPT = r"""
TL 'stats' {
  Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface | ForEach-Object {
    [ordered]@{ name = $_.Name; rx_bytes = [int64]$_.BytesReceivedPersec; tx_bytes = [int64]$_.BytesSentPersec;
      rx_ucast = [int64]$_.PacketsReceivedUnicastPersec; rx_nucast = [int64]$_.PacketsReceivedNonUnicastPersec;
      rx_discard = [int64]$_.PacketsReceivedDiscarded; rx_err = [int64]$_.PacketsReceivedErrors; rx_unknown = [int64]$_.PacketsReceivedUnknown;
      tx_discard = [int64]$_.PacketsOutboundDiscarded; tx_err = [int64]$_.PacketsOutboundErrors; queue = [int64]$_.OutputQueueLength;
      bandwidth = [int64]$_.CurrentBandwidth }
  }
}
"""


def collect(cancel=None) -> dict:
    data, err = ps.run(SCRIPT, timeout=60, cancel=cancel)
    data["_t"] = time.time()
    if err:
        data.setdefault("_errors", []).append(err)
    return data


def stats(cancel=None) -> dict:
    data, _err = ps.run(STATS_SCRIPT, timeout=30, cancel=cancel)
    return {"t": time.time(), "stats": data.get("stats") or []}


def _lst(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def networks(local: dict) -> list[dict]:
    """Réseaux IPv4 directement connectés au poste (hors APIPA / boucle locale),
    avec la carte, l'IP du poste, la passerelle et les DNS."""
    adapters = {a.get("index"): a for a in _lst(local.get("adapters"))}
    out, seen = [], set()
    for cfg in _lst(local.get("ipconfig")):
        ips, masks = _lst(cfg.get("ip")), _lst(cfg.get("mask"))
        for ip, mask in zip(ips, masks):
            if ":" in str(ip) or not mask or ":" in str(mask):
                continue
            try:
                iface = ipaddress.IPv4Interface(f"{ip}/{mask}")
            except ValueError:
                continue
            if iface.ip.is_link_local or iface.ip.is_loopback:
                continue
            net = iface.network
            if str(net) in seen:
                continue
            seen.add(str(net))
            gws = [g for g in _lst(cfg.get("gateway")) if g and ":" not in g and ipaddress.IPv4Address(g) in net]
            ad = adapters.get(cfg.get("index")) or {}
            out.append({"network": str(net), "prefix": net.prefixlen, "local_ip": str(iface.ip), "ifindex": cfg.get("index"),
                        "adapter": ad.get("name") or cfg.get("desc"), "adapter_desc": ad.get("desc") or cfg.get("desc"),
                        "mac": (ad.get("mac") or cfg.get("mac") or "").replace("-", ":").lower(),
                        "gateway": gws[0] if gws else None,
                        "dns": [d for d in _lst(cfg.get("dns")) if d],
                        "dhcp": bool(cfg.get("dhcp")), "dhcp_server": cfg.get("dhcp_server"),
                        "domain": cfg.get("domain") or "", "source": "local"})
    return out


def default_gateway(local: dict) -> str | None:
    best = None
    for r in _lst(local.get("routes")):
        if r.get("prefix") == "0.0.0.0/0" and r.get("next_hop") not in (None, "0.0.0.0"):
            if best is None or (r.get("metric") or 0) < (best.get("metric") or 0):
                best = r
    return best.get("next_hop") if best else None
