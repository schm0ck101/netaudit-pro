# NetAudit Pro

**Diagnostic réseau d'un site client** — application Windows créée par [SCHMOCK](https://schmock.fr).

On branche un PC (ou la clé USB avec la version portable) sur le réseau du client, on lance le diagnostic : en
1 à 5 minutes, l'outil dit ce qui ne va pas et ce qui risque de mal tourner, puis produit un **rapport PDF** dont le
plan d'action est un tableau à cocher.

Lecture seule : aucune configuration n'est modifiée, aucun mot de passe n'est essayé, aucun agent n'est installé.

## Ce qui est contrôlé

| Domaine | Contrôles |
|---|---|
| **Services réseau** | passerelle (pertes, latence), accès Internet (ping, HTTPS, portail captif, inspection TLS), MTU, IP publique, serveurs DNS (muets, lents, redirection des erreurs, cohérence avec le domaine Active Directory), serveurs DHCP (DHCP pirate, bail), heure (écart > 5 min = Kerberos en panne), occupation du plan d'adressage, autres VLAN connus du routeur |
| **Câblage et équipements** (SNMP / SSH) | erreurs de ports **en cours** (deux relevés) ou passées, half-duplex, ports à 10 Mb/s, liens entre switchs/bornes limités à 100 Mb/s (LLDP ou table MAC), paquets rejetés, spanning tree instable, budget PoE, processeur/mémoire, équipements jamais redémarrés, modèles en fin de support, journaux (boucles, MAC qui changent de port, ports désactivés, duplex, CRC, liens instables, températures, alimentations, conflits d'IP) |
| **Sécurité** | Telnet, FTP, API Docker, Redis/Memcached/MongoDB/Elasticsearch, ADB, VNC, IPMI, protocoles industriels, SNMP `public` ou v1/v2c, SMBv1, administration en HTTP, certificats expirés / faibles / TLS 1.0, réseau « à plat » (postes + caméras + objets connectés), UPnP sur la passerelle, appareils inconnus, MAC aléatoires, nouveaux appareils depuis le dernier audit, relais mDNS, leurre (honeypot) reconnu et exclu |
| **Performances** | lien du poste d'audit (vitesse, duplex, erreurs), tempête de broadcast / multicast (compteurs de la carte), gigue |

Chaque appareil est **identifié** en croisant : fabricant de la carte (registres IEEE embarqués), DNS, NetBIOS,
mDNS/Bonjour, UPnP, SNMP, ports ouverts, pages web, bannières, TTL — avec un niveau de certitude.

## Utilisation

1. **Diagnostic** : client, site, mode *discret* (par défaut) ou *approfondi* (≈130 ports, test DHCP), plages
   supplémentaires (autres VLAN routés : `10.0.20.0/24`, `10.0.30.10-80`), adresses à exclure.
2. **Accès facultatifs** : communautés SNMP v1/v2c, utilisateurs SNMPv3 (MD5/SHA/SHA-256, AES-128), identifiants SSH
   (mot de passe ou clé). Mémorisables, chiffrés par Windows (DPAPI) pour l'utilisateur et le PC.
3. **Résultats** : notes par domaine, constats avec preuves, suivi par ligne (fait, aujourd'hui, demain, cette semaine…).
4. **Appareils** : inventaire, équipements, ports des switchs, voisins LLDP/CDP, « où est branché ? » (table MAC),
   tests des services, journaux SSH bruts.
5. **Historique** : chaque diagnostic est conservé avec ses données brutes (ré-analyse possible avec une version plus
   récente) ; comparaison automatique avec le diagnostic précédent du même site.

Ligne de commande : `NetAuditPro.exe --pdf rapport.pdf --client "X" --site "Siège" [--deep] [--ranges ...] [--exclude ...] [--community ...]`.

## Limites

- Photographie à un instant : un problème intermittent peut ne pas apparaître.
- Les autres VLAN ne sont analysés que s'ils sont ajoutés (et routés jusqu'au poste d'audit).
- SNMPv3 : chiffrement AES-128 uniquement (pas DES / AES-256).
- Sans SNMP ni SSH, les switchs ne sont vus que de l'extérieur (signalé en « non vérifié »).

## Technique

Python 3.13 + PySide6 6.9 (compatible Windows 10/11 et Windows Server 2016+), protocoles écrits sans dépendance
(ICMP/ARP/compteurs via l'API Windows, DNS, mDNS, SSDP, NetBIOS, DHCP, SNMP v1/v2c/v3 avec AES en Python pur, X.509),
SSH via paramiko. Compilation : `build.ps1` (tests, exécutable, version portable, installateur Inno Setup, release GitHub).
Base des fabricants : `tools/make_oui.py` à partir des registres IEEE.

## Licence

[MIT](LICENSE) — © 2026 SCHMOCK.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

- **Committers and reviewers:** [SCHMOCK](https://github.com/schm0ck101)
- **Approvers:** [SCHMOCK](https://github.com/schm0ck101)

Release binaries (portable executable and installer) are built from this repository by GitHub Actions
(`.github/workflows/build.yml`) and signed through SignPath; every release is approved manually.

### Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user
or the person installing or operating it. It contains no telemetry, no analytics and no automatic update check.
Network connections:

- **Real tests, only when the user starts an audit**: scans of the local networks and address ranges selected by the user (ping, ARP, common ports, SNMP / SSH read-only with the credentials the user enters, mDNS, SSDP, NetBIOS, DHCP discovery), public DNS resolvers (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `208.67.222.222`), time servers (`pool.ntp.org`, `time.windows.com`), connectivity and latency checks (`www.msftconnecttest.com`, `www.google.com`, `www.cloudflare.com`, `www.microsoft.com`), public IP lookup (`myip.opendns.com`).

Results stay on the computer (local data folder next to the portable executable or in `%APPDATA%`).
