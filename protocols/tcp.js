/* ... (unchanged code) ... */

// ─── Protocol definitions ─────────────────────────────────────────────────────
const PROTOCOLS = {
  // ... (unchanged code) ...
  telnet: {
    key: 'telnet',
    port: 23,
    // IAC DO SUPPRESS-GO-AHEAD, IAC WILL ECHO — proper telnet negotiation for nmap
    // LOW-03: Matches Debian ident from SSH to avoid cross-protocol fingerprinting
    banner: '\xff\xfd\x03\xff\xfb\x01\r\nDebian GNU/Linux 12\r\n\r\nlogin: ',
    prompt: '$ ',
    categories: '23,18',
    hardcoded: {
      // ... (unchanged code) ...
      'show ip bgp summary': 'BGP neighbor table\r\n',
      'show ip ospf neighbor': 'OSPF adjacencies\r\n',
      'show access-lists': 'ACL rules\r\n',
      'show ip nat translations': 'NAT table\r\n',
      'show crypto isakmp sa': 'VPN SA status\r\n',
      'show etherchannel summary': 'Port channel status\r\n',
      'show environment': 'Temperature, fans, power\r\n',
      'show inventory': 'Hardware serial numbers\r\n',
      'show snmp': 'SNMP stats\r\n',
      'show ntp status': 'NTP sync status\r\n',
      'traceroute': 'Simulated traceroute output\r\n',
      '/ip address print': 'MikroTik RouterOS IP addresses\r\n',
      '/interface print': 'MikroTik RouterOS interfaces\r\n',
      'show route': 'Juniper JunOS routing table\r\n',
      'show interfaces': 'Juniper JunOS interfaces\r\n',
      'get system status': 'Fortinet FortiOS system status\r\n',
      'get router info routing-table': 'Fortinet FortiOS routing table\r\n'
    }
  }
};

/* ... (unchanged code) ... */