<h1>🛡️ Python Packet Sniffer (Educational Tool)</h1>

  <p>
    This is a lightweight <strong>network packet sniffer</strong> built with Python and 
    <a href="https://scapy.net/" target="_blank">Scapy</a>. It captures and displays key packet details 
    such as source/destination IPs, ports, protocols (TCP/UDP/ICMP/ARP), MAC addresses, and payload (truncated for safety).
  </p>

  <h2>🔧 Features</h2>
  <ul>
    <li>Live traffic sniffing with optional BPF filter</li>
    <li>Protocol recognition: IP, TCP, UDP, ARP, ICMP</li>
    <li>Graceful shutdown on <code>CTRL+C</code></li>
    <li>Command-line interface with <code>argparse</code></li>
  </ul>

  <h2>📦 Usage</h2>
  <pre><code>python sniffer.py -i eth0 -c 100 -f "tcp port 80"</code></pre>

</body>
</html>
