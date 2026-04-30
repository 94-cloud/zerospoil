bashcd /home/sansforensics/zerospoil

# Create .mcp.json
cat > .mcp.json << 'EOF'
{
  "mcpServers": {
    "zerospoil-disk": {
      "type": "stdio",
      "command": "python3",
      "args": ["/home/sansforensics/zerospoil/disk_mcp_server.py"],
      "env": {
        "REDIS_HOST": "127.0.0.1",
        "REDIS_PORT": "6379"
      }
    },
    "zerospoil-memory": {
      "type": "stdio",
      "command": "python3",
      "args": ["/home/sansforensics/zerospoil/memory_mcp_server.py"],
      "env": {
        "REDIS_HOST": "127.0.0.1",
        "REDIS_PORT": "6379"
      }
    },
    "zerospoil-network": {
      "type": "stdio",
      "command": "python3",
      "args": ["/home/sansforensics/zerospoil/network_mcp_server.py"],
      "env": {
        "REDIS_HOST": "127.0.0.1",
        "REDIS_PORT": "6379"
      }
    }
  }
}
EOF

echo "Created .mcp.json"
