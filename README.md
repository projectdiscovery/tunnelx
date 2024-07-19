# TunnelX

TunnelX is a lightweight network ingress tunnelling to local SOCKS5 proxy server written in Go. It allows you to create a secure ingress tunnel for your network traffic.

## Prerequisites

- Go 1.16 or later

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/tunnelx.git
    cd tunnelx
    ```

2. Set up your environment variable with a fake token:
    ```sh
    export PDCP_API_KEY=a.b.c.d
    ```

## Usage

1. Run the proxy server:
    ```sh
    go run .
    ```

2. You should see output similar to:
    ```
    Socks5 proxy listening on: [::]:36507
    Your tunnel is: x.x.x.x:45931
    ```

3. Test connectivity with curl:
    ```sh
    curl --proxy socks5://pdcp:$PDCP_API_KEY@x.x.x.x:45931 https://scanme.sh
    ```


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
