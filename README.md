# TunnelX

TunnelX is a lightweight network ingress tunnelling to local SOCKS5 proxy server written in Go. It allows you to create a secure ingress tunnel for your network traffic.

## Usage

### Docker (Recommended)

1. Pull and run the Docker image:
    ```sh
    # public docker will be ready to use before pushing this to public.
    docker run --network host -d -e PDCP_API_KEY="XXXX" projectdiscovery/tunnelx:latest
    ```

2. If you prefer to build locally, you can:
    ```sh
    docker build . -t tunnelx
    docker run --network host -d -e PDCP_API_KEY="XXXX" tunnelx
    ```

### Go

1. Install and run go program
    ```sh
    go install github.com/projectdiscovery/tunnelx@latest
    export PDCP_API_KEY=a.b.c.d
    tunnelx
    ```

2. If you prefer to build locally, you can:
    ```sh
    git clone https://github.com/projectdiscovery/tunnelx.git
    cd tunnelx
    go run .
    ```

3. You should see output similar to:
    ```
    Socks5 proxy listening on: [::]:36507
    Your tunnel is: x.x.x.x:45931
    ```

4. Test connectivity with curl:
    ```sh
    curl --proxy socks5://pdcp:$PDCP_API_KEY@x.x.x.x:45931 https://scanme.sh
    ```

Make sure to replace `XXXX` with your actual `PDCP_API_KEY` in the commands above.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
