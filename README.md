# TunnelX

TunnelX is a lightweight ingress tunneling tool designed to create a secure SOCKS5 proxy server for routing network traffic. TunnelX is created for enabling internal network scanning from the [ProjectDiscovery platform](https://cloud.projectdiscovery.io/scans), ensuring a seamless and isolated connection.

## Features
- Secure network ingress via SOCKS5 proxy.
- Authenticated connections using your [ProjectDiscovery API key](https://cloud.projectdiscovery.io/?ref=api_key).
- Isolated traffic routing for internal scanning and discovery.


## How It Works

TunnelX creates secure ingress tunnels using your ProjectDiscovery API key, enabling isolated internal scanning via a SOCKS5 proxy.

You can run TunnelX on different networks by specifying unique network names. This allows you to scan multiple networks independently, with each connection appearing as a selectable option in the network dropdown menu on the [ProjectDiscovery Scans](https://cloud.projectdiscovery.io/scans) page.

## Quick Start

### Docker (Recommended)

1. **Run the Docker image:**
    ```sh
    docker run --network host -d -e PDCP_API_KEY="your_api_key" projectdiscovery/tunnelx:latest
    ```
    Replace `your_api_key` with your ProjectDiscovery API key.

2. **Alternatively, build and run locally:**
    ```sh
    docker build . -t tunnelx
    docker run --network host -d -e PDCP_API_KEY="your_api_key" tunnelx
    ```

### Go

1. **Install and run:**
    ```sh
    go install github.com/projectdiscovery/tunnelx@latest
    export PDCP_API_KEY="your_api_key"
    tunnelx
    ```

2. **Run directly from source:**
    ```sh
    git clone https://github.com/projectdiscovery/tunnelx.git
    cd tunnelx
    export PDCP_API_KEY="your_api_key"
    go run .
    ```

3. After successful connection, navigate to [ProjectDiscovery Scans](https://cloud.projectdiscovery.io/scans) to create and manage scans using the established connection.

![Internal Network](https://github.com/user-attachments/assets/d6e58159-3c2d-4902-a0a9-64d6f07da64c)


## Command-Line Usage

### Flags

| Flag        | Description                                                 |
|-------------|-------------------------------------------------------------|
| `-auth`     | Your ProjectDiscovery API key (required).                   |
| `-name`     | (Optional) Specify a custom network name. Default is your machine’s hostname. |

**Example:**
```sh
tunnelx -auth <your_api_key> -name <custom_network_name>
```

**Output Example:**
```sh
tunnelx -auth <your_api_key>

[INF] Session established. Leave this terminal open to enable continuous discovery and scanning.
[INF] Your network is protected—connection isolated and not exposed to the internet.
[INF] To create a scan, visit: https://cloud.projectdiscovery.io/scans

[HELP] To terminate, press Ctrl+C.
```

**Running in the Background**

To keep tunnelx running continuously in the background, follow these instructions based on your operating system:

```sh
# Linux & MacOS
nohup tunnelx -auth <your_api_key>

# Windows
start /B tunnelx -auth <your_api_key>
```
