"""
Port Scanner Module
Primary: python-nmap (if nmap is installed)
Fallback: pure-Python socket scanner (works without nmap)
"""
import socket
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)
MAX_FALLBACK_HOSTS = 256
MAX_FALLBACK_PROBES = 100000

# Common port → service name mapping used by the socket fallback
_COMMON_SERVICES = {
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    53: 'dns', 67: 'dhcp', 68: 'dhcp', 69: 'tftp', 80: 'http',
    110: 'pop3', 111: 'rpcbind', 119: 'nntp', 123: 'ntp',
    135: 'msrpc', 137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn',
    143: 'imap', 161: 'snmp', 162: 'snmp-trap', 179: 'bgp',
    194: 'irc', 389: 'ldap', 443: 'https', 445: 'smb',
    465: 'smtps', 514: 'syslog', 515: 'printer', 587: 'submission',
    636: 'ldaps', 993: 'imaps', 995: 'pop3s',
    1080: 'socks', 1194: 'openvpn', 1433: 'mssql', 1521: 'oracle',
    1723: 'pptp', 2049: 'nfs', 2181: 'zookeeper',
    3000: 'http-dev', 3306: 'mysql', 3389: 'rdp', 4444: 'metasploit',
    5000: 'flask', 5432: 'postgresql', 5900: 'vnc', 5985: 'winrm',
    6379: 'redis', 6443: 'kubernetes', 7001: 'weblogic',
    8000: 'http-alt', 8080: 'http-proxy', 8443: 'https-alt',
    8888: 'jupyter', 9000: 'php-fpm', 9090: 'prometheus',
    9200: 'elasticsearch', 9300: 'elasticsearch',
    27017: 'mongodb', 27018: 'mongodb', 28017: 'mongodb-web',
}


def _parse_port_range(ports_str: str) -> List[int]:
    """Parse a port range string like '1-1000' or '80,443,8080' into a sorted list."""
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start_int = max(1, int(start))
                end_int = min(65535, int(end))
                if start_int <= end_int:
                    ports.update(range(start_int, end_int + 1))
            except ValueError:
                pass
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                pass
    return sorted(ports)


def _resolve_targets(target: str) -> List[Tuple[str, str]]:
    """
    Resolve a target into (label, ip) tuples for the socket fallback.

    nmap can scan CIDR ranges natively, but socket.gethostbyname() cannot.
    The fallback supports small ranges and rejects broad ranges with a clear
    error instead of failing with a hostname resolution message.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(host) for host in network.hosts()]
        if not hosts:
            hosts = [str(network.network_address)]
        if len(hosts) > MAX_FALLBACK_HOSTS:
            raise ValueError(
                f"CIDR range '{target}' expands to {len(hosts)} hosts. "
                f"The socket fallback supports up to {MAX_FALLBACK_HOSTS} hosts; "
                "install nmap for larger network scans."
            )
        return [(host, host) for host in hosts]
    except ValueError as exc:
        if "expands to" in str(exc):
            raise

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname '{target}': {exc}") from exc

    return [(target, resolved_ip)]


class PortScanner:
    """
    Port scanning with automatic fallback.

    Uses nmap (via python-nmap) when available for rich results.
    Falls back to a concurrent TCP-connect socket scanner when nmap
    is not installed — no external tools required.
    """

    def __init__(self):
        self._nmap = None
        self._use_fallback = False
        try:
            import nmap
            self._nmap = nmap.PortScanner()
            logger.info("nmap is available — using nmap scanner.")
        except Exception as exc:
            self._use_fallback = True
            logger.warning(
                "nmap is not available (%s). "
                "Falling back to socket-based port scanner. "
                "Install nmap from https://nmap.org/download.html for richer results.",
                exc,
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_ports(self, target: str, ports: str = '1-1000', scan_type: str = 'standard') -> Dict:
        """
        Scan ports on *target*.

        Args:
            target:    IP address, domain, or CIDR range
            ports:     Port range e.g. '1-1000' or '80,443,8080'
            scan_type: 'quick' | 'standard' | 'deep' | 'custom'

        Returns:
            Normalised results dict (same structure for both backends).
        """
        if self._use_fallback:
            return self._socket_scan(target, ports, scan_type)
        return self._nmap_scan(target, ports, scan_type)

    def scan_single_port(self, target: str, port: int, protocol: str = 'tcp') -> Dict:
        """Scan a single port and return its status."""
        if self._use_fallback:
            return self._socket_scan_single(target, port)

        try:
            self._nmap.scan(hosts=target, ports=str(port), arguments='-sV')
            if target in self._nmap.all_hosts():
                if protocol in self._nmap[target]:
                    if port in self._nmap[target][protocol]:
                        d = self._nmap[target][protocol][port]
                        return {
                            'port': port,
                            'state': d['state'],
                            'service': d.get('name', ''),
                            'product': d.get('product', ''),
                            'version': d.get('version', ''),
                        }
        except Exception as exc:
            logger.error("Error scanning port %s on %s: %s", port, target, exc)
            raise

        return {'port': port, 'state': 'unknown', 'service': '', 'product': '', 'version': ''}

    def get_open_ports(self, scan_results: Dict) -> List[Dict]:
        """Extract open ports from a scan_ports() result dict."""
        open_ports = []
        for host, host_info in scan_results.get('hosts', {}).items():
            for proto, ports_list in host_info.get('protocols', {}).items():
                for port_info in ports_list:
                    if port_info.get('state') == 'open':
                        port_info = dict(port_info)
                        port_info['host'] = host
                        port_info['protocol'] = proto
                        open_ports.append(port_info)
        return open_ports

    # ------------------------------------------------------------------
    # nmap backend
    # ------------------------------------------------------------------

    def _nmap_scan(self, target: str, ports: str, scan_type: str) -> Dict:
        """Run nmap and return normalised results."""
        try:
            logger.info("Starting nmap scan on %s, ports: %s", target, ports)
            args = self._get_scan_args(scan_type)
            self._nmap.scan(hosts=target, ports=ports, arguments=args)

            results = {
                'target': target,
                'scan_stats': self._nmap.scanstats(),
                'hosts': {},
                'total_ports_scanned': 0,
                'open_ports': 0,
                'closed_ports': 0,
                'filtered_ports': 0,
                'scanner': 'nmap',
            }

            for host in self._nmap.all_hosts():
                host_info = {
                    'hostname': self._nmap[host].hostname(),
                    'state': self._nmap[host].state(),
                    'protocols': {},
                }
                for proto in self._nmap[host].all_protocols():
                    ports_info = []
                    for port in sorted(self._nmap[host][proto].keys()):
                        d = self._nmap[host][proto][port]
                        ports_info.append({
                            'port': port,
                            'state': d['state'],
                            'service': d.get('name', ''),
                            'product': d.get('product', ''),
                            'version': d.get('version', ''),
                            'extrainfo': d.get('extrainfo', ''),
                            'cpe': d.get('cpe', ''),
                        })
                        results['total_ports_scanned'] += 1
                        state = d['state']
                        if state == 'open':
                            results['open_ports'] += 1
                        elif state == 'closed':
                            results['closed_ports'] += 1
                        elif state == 'filtered':
                            results['filtered_ports'] += 1
                    host_info['protocols'][proto] = ports_info
                results['hosts'][host] = host_info

            logger.info("nmap scan complete on %s. Open ports: %s", target, results['open_ports'])
            return results

        except Exception as exc:
            logger.error("nmap scan error on %s: %s", target, exc)
            raise Exception(f"Port scan failed: {exc}")

    def _get_scan_args(self, scan_type: str) -> str:
        return {
            'quick': '-T4 -F',
            'standard': '-sV -T4',
            'deep': '-sV -sC -T4 -A',
            'custom': '-sV -T4',
        }.get(scan_type, '-sV -T4')

    # ------------------------------------------------------------------
    # Socket fallback backend
    # ------------------------------------------------------------------

    def _socket_scan(self, target: str, ports_str: str, scan_type: str) -> Dict:
        """
        Pure-Python TCP-connect port scanner using concurrent sockets.
        No nmap required. Works on Windows/Linux/macOS without any
        additional tools or elevated privileges.
        """
        logger.info("Starting socket scan on %s, ports: %s", target, ports_str)

        targets = _resolve_targets(target)
        port_list = _parse_port_range(ports_str)
        if not port_list:
            raise Exception(f"No valid ports found in port range '{ports_str}'")
        total_probes = len(targets) * len(port_list)
        if total_probes > MAX_FALLBACK_PROBES:
            raise Exception(
                f"The socket fallback would run {total_probes} probes for this scan. "
                f"The fallback limit is {MAX_FALLBACK_PROBES}; install nmap for larger scans "
                "or choose a smaller target/port range."
            )

        # Tune concurrency & timeout to scan type
        timeouts = {'quick': 0.5, 'standard': 0.75, 'deep': 1.0}
        workers = {'quick': 100, 'standard': 150, 'deep': 200}
        timeout = timeouts.get(scan_type, 0.75)
        max_workers = workers.get(scan_type, 150)

        results = {
            'target': target,
            'scan_stats': {},
            'hosts': {},
            'total_ports_scanned': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0,
            'scanner': 'socket-fallback',
        }

        for label, ip in targets:
            results['hosts'][ip] = {
                'hostname': label if label != ip else '',
                'state': 'up',
                'protocols': {'tcp': []},
            }

        def _probe(label, ip, port):
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    return label, ip, port, 'open'
            except ConnectionRefusedError:
                return label, ip, port, 'closed'
            except OSError:
                return label, ip, port, 'filtered'

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_probe, label, ip, port): (label, ip, port)
                for label, ip in targets
                for port in port_list
            }
            for future in as_completed(futures):
                label, ip, port, state = future.result()
                results['total_ports_scanned'] += 1
                if state == 'open':
                    results['open_ports'] += 1
                    results['hosts'][ip]['protocols']['tcp'].append({
                        'port': port,
                        'state': 'open',
                        'service': _COMMON_SERVICES.get(port, ''),
                        'product': '',
                        'version': '',
                        'extrainfo': 'socket scan',
                        'cpe': '',
                    })
                elif state == 'closed':
                    results['closed_ports'] += 1
                else:
                    results['filtered_ports'] += 1

        for host_info in results['hosts'].values():
            host_info['protocols']['tcp'].sort(key=lambda x: x['port'])

        logger.info(
            "Socket scan complete on %s (%s host(s)). Open ports: %s",
            target, len(targets), results['open_ports'],
        )
        return results

    def _socket_scan_single(self, target: str, port: int) -> Dict:
        """Socket-based single-port scan."""
        try:
            ip = socket.gethostbyname(target)
            with socket.create_connection((ip, port), timeout=1.0):
                return {
                    'port': port, 'state': 'open',
                    'service': _COMMON_SERVICES.get(port, ''),
                    'product': '', 'version': '',
                }
        except ConnectionRefusedError:
            return {'port': port, 'state': 'closed', 'service': '', 'product': '', 'version': ''}
        except Exception:
            return {'port': port, 'state': 'filtered', 'service': '', 'product': '', 'version': ''}
