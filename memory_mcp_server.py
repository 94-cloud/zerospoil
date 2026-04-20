import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Forensic-Memory-Server")

class MemoryAnalyzer:
    def __init__(self, mem_dump_path):
        self.mem_path = mem_dump_path

    def run_vol(self, plugin):
        """Standardized Volatility3 wrapper."""
        cmd = ["vol", "-f", self.mem_path, plugin]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

@mcp.tool()
def list_active_processes():
    """Wraps windows.pslist. Provides the baseline of what is running."""
    analyzer = MemoryAnalyzer("/home/sansforensics/memdump.mem")
    return analyzer.run_vol("windows.pslist")

@mcp.tool()
def find_hidden_processes():
    """
    Wraps windows.psscan. Finds EPROCESS blocks unlinked from the active list.
    Delta between pslist and psscan output = hidden process indicator.
    """
    analyzer = MemoryAnalyzer("/home/sansforensics/memdump.mem")
    return analyzer.run_vol("windows.psscan")

if __name__ == "__main__":
    mcp.run()
