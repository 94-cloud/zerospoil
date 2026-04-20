import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Forensic-Network-Server")

class NetworkAnalyzer:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path

    def run_tshark(self, display_filter, fields):
        cmd = ["tshark", "-r", self.pcap_path, "-Y", display_filter, "-T", "fields"]
        for f in fields:
            cmd.extend(["-e", f])
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

@mcp.tool()
def get_connection_summary():
    """Provides a high-level flow view of TCP SYN packets."""
    analyzer = NetworkAnalyzer("/home/sansforensics/evidence.pcap")
    return analyzer.run_tshark(
        "tcp.flags.syn==1",
        ["frame.time", "ip.src", "ip.dst", "tcp.dstport"]
    )

@mcp.tool()
def search_dns_queries(query_pattern: str):
    """Finds C2 beacons or data exfiltration via DNS."""
    analyzer = NetworkAnalyzer("/home/sansforensics/evidence.pcap")
    return analyzer.run_tshark(
        f"dns.qry.name contains {query_pattern}",
        ["frame.time", "ip.src", "dns.qry.name"]
    )

if __name__ == "__main__":
    mcp.run()
