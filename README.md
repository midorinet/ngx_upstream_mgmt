![CI](https://github.com/midorinet/ngx_upstream_mgmt/workflows/CI/badge.svg)

# NGINX Upstream Management Module
A dynamic module for NGINX that provides HTTP API endpoints to manage upstream server states and view upstream configurations.

## Disclaimer
This project is an independent open-source module for NGINX Open Source and is **not affiliated with, endorsed by, or associated with NGINX, NGINX Plus, or F5, Inc.**.

## Features
- List all configured upstreams and their server details
- View detailed information about specific upstream configurations
- Dynamically change upstream server states (up/drain)
- RESTful JSON API interface

## Limitations
- This module is intended for use with NGINX Open Source only.
- It does not replicate all features of NGINX Plus.

## Installation

### Prerequisites

- NGINX source code
- C compiler (GCC or Clang)
- Basic build tools (make, etc.)

### Building the Module

1. Download or clone this repository:
```bash
git clone https://github.com/midorinet/ngx_upstream_mgmt
```
Download NGINX source code:
```bash
wget https://nginx.org/download/nginx-1.26.2.tar.gz
tar -xzvf nginx-1.26.2.tar.gz
```
Build NGINX with the module:
```bash
cd nginx-1.26.2
./configure --add-dynamic-module=../ngx_upstream_mgmt
make
make install
```

### Configuration
Add the following to your NGINX configuration:

```nginx
# Load the dynamic module
load_module modules/ngx_http_upstream_mgmt_module.so;

# Configure upstream groups
upstream backend {
    server 10.0.0.1:8080 weight=4 max_fails=2 fail_timeout=30s;
    server 10.0.0.2:8080 weight=2 max_fails=2 fail_timeout=30s backup;
}

# Enable the management API
location /api/upstreams {
    upstream_mgmt;
    client_max_body_size 1m;
    client_body_buffer_size 16k;
    # Add access controls here
    allow 127.0.0.1;
    deny all;
}
```

### API Endpoints
#### GET /api/upstreams
Lists all configured upstreams and their server details.

**Response Example:**
```
{
  "backend": {
    "servers": [
      {
        "id": 0,
        "server": "172.16.0.61:8080",
        "weight": 1,
        "max_conns": 0,
        "max_fails": 1,
        "fail_timeout": "10s",
        "slow_start": "0s",
        "backup": false,
        "down": false
      },
      {
        "id": 1,
        "server": "172.16.0.62:8080",
        "weight": 1,
        "max_conns": 0,
        "max_fails": 1,
        "fail_timeout": "10s",
        "slow_start": "0s",
        "backup": false,
        "down": false
      }
    ]
  },
  "backend2": {
    "servers": [
      {
        "id": 0,
        "server": "172.16.0.71:80",
        "weight": 1,
        "max_conns": 0,
        "max_fails": 1,
        "fail_timeout": "10s",
        "slow_start": "0s",
        "backup": false,
        "down": false
      },
      {
        "id": 1,
        "server": "172.16.0.72:80",
        "weight": 1,
        "max_conns": 0,
        "max_fails": 1,
        "fail_timeout": "10s",
        "slow_start": "0s",
        "backup": false,
        "down": false
      }
    ]
  }
}
```

#### GET /api/upstreams/{upstream_name}
Get details for a specific upstream configuration.

**Response Example: **
```
{
  "servers": [
    {
      "id": 0,
      "server": "172.16.0.71:80",
      "weight": 1,
      "max_conns": 0,
      "max_fails": 1,
      "fail_timeout": "10s",
      "slow_start": "0s",
      "backup": false,
      "down": false
    },
    {
      "id": 1,
      "server": "172.16.0.72:80",
      "weight": 1,
      "max_conns": 0,
      "max_fails": 1,
      "fail_timeout": "10s",
      "slow_start": "0s",
      "backup": false,
      "down": false
    }
  ]
}
```

#### PATCH /api/upstreams/{upstream_name}/servers/{server_id}

Update the state of a specific server in an upstream group.

**Request Body:**
```json
{
  "drain": true
}
```
**Response Example:**
```json
{
  "status": "success"
}
```
### Usage Examples
  - List all upstreams:
```
curl http://localhost/api/upstreams
```
  - Get specific upstream details:
```
curl http://localhost/api/upstreams/backend
```
  - Drain a server (mark as down):
```
curl -X PATCH \
     -d '{"drain":true}' \
     http://localhost/api/upstreams/backend/servers/1
```
  - Bring a server back up:
```
curl -X PATCH \
     -d '{"drain":false}' \
     http://localhost/api/upstreams/backend/servers/1
```

