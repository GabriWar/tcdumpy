# 🌐 tcpdumpy 🕵️‍♀️

## Overview

tcpdumpy is a powerful Python-based network monitoring tool that provides detailed insights into network connections and packet interactions. Whether you're a network administrator, security researcher, or curious developer, tcpdumpy offers comprehensive network traffic analysis with flexible filtering options.

## 🚀 Features

- 🔍 Detailed network connection monitoring
- 🔬 Payload capture and display
- 🚧 Flexible filtering options
- 📊 Comprehensive connection status tracking
- 🌍 IP and port information
- 🚨 TCP flag interpretation

## 🛠 Prerequisites

- Python 3.x
- `tcpdump` installed on your system
- Root/sudo privileges (for packet capture)

## 💾 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/tcpdumpy.git
   cd tcpdumpy
   ```

2. Ensure you have the required permissions:
   ```bash
   sudo chmod +x tcpdumpy.py
   ```

## 🎮 Usage

### Basic Usage
```bash
sudo python3 tcpdumpy.py
```

### Command Line Options

- `-l, --localhost`: Show localhost-to-localhost connections
- `--status`: Filter by connection status (e.g., 'Connection Attempt')
- `--flags`: Filter by TCP flags (e.g., 'S,.')
- `--port`: Filter by specific port
- `--no-payload`: Disable payload display

### Examples

1. Monitor all connections:
   ```bash
   sudo python3 tcpdumpy.py
   ```

2. Show localhost connections:
   ```bash
   sudo python3 tcpdumpy.py -l
   ```

3. Filter by connection status:
   ```bash
   sudo python3 tcpdumpy.py --status "Connection Attempt"
   ```

4. Filter by TCP flags:
   ```bash
   sudo python3 tcpdumpy.py --flags "S,."
   ```

## 🔒 Security Notice

This tool requires root/sudo privileges due to network packet capture limitations. Always use with caution and ensure you have appropriate permissions.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

[Insert your license here, e.g., MIT License]

## 🐛 Bug Reports

Please open an issue on GitHub with detailed information about the bug.

## 🌟 Acknowledgments

- Inspired by the powerful `tcpdump` utility
- Python networking and subprocess libraries
