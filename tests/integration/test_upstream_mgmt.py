import pytest
import requests
import time
import subprocess
import os
import logging
import json
from pathlib import Path
from collections import defaultdict

# Configure logging to suppress urllib3 debug logs and show our informative logs
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress urllib3 debug logging
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)

def log_request_response(method, url, response, request_data=None, headers=None):
    """Log HTTP request and response details in a clear format"""
    logger.info("=" * 60)
    logger.info(f"HTTP {method.upper()} Request: {url}")
    if headers:
        logger.info(f"Request Headers: {headers}")
    if request_data:
        logger.info(f"Request Data: {request_data}")
    logger.info(f"Response Status: {response.status_code}")
    logger.info(f"Response Headers: {dict(response.headers)}")
    logger.info(f"Response Body: {response.text}")
    logger.info("=" * 60)

class BackendServer:
    def __init__(self, port):
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                response = f"Response from backend port {port}"
                self.wfile.write(response.encode())
                
        self.port = port
        self.server = HTTPServer(('localhost', port), Handler)
        self.server_thread = None
    
    def start(self):
        import threading
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
    
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

class NginxServer:
    def __init__(self, nginx_bin, config_path, module_path):
        self.nginx_bin = nginx_bin
        self.config_path = config_path
        self.module_path = module_path
        self.process = None
        self.workdir = Path(config_path).parent
    
    def create_dirs(self):
        """Create necessary nginx directories"""
        (self.workdir / "logs").mkdir(exist_ok=True)
        (self.workdir / "temp").mkdir(exist_ok=True)
    
    def _write_config(self):
        """Write nginx configuration"""
        config_content = f"""
    worker_processes  1;
    error_log logs/error.log debug;
    pid logs/nginx.pid;
    
    # Load dynamic modules
    load_module {self.module_path};
    
    events {{
        worker_connections  1024;
    }}
    
    http {{
        upstream backend {{
            server 127.0.0.1:8081;
            server 127.0.0.1:8082;
        }}
        
        server {{
            listen 8080;
            
            location /api/upstreams {{
                upstream_mgmt;
            }}
            
            location / {{
                proxy_pass http://backend;
                add_header X-Upstream $upstream_addr always;
                proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
            }}
        }}
    }}
    """
        Path(self.config_path).write_text(config_content)
    
    def start(self):
        self.create_dirs()
        self._write_config()
        self.process = subprocess.Popen([
            self.nginx_bin,
            '-p', str(self.workdir),
            '-c', self.config_path,
            '-g', 'daemon off;'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        
        if self.process.poll() is not None:
            out, err = self.process.communicate()
            raise RuntimeError(f"Nginx failed to start:\nSTDOUT:\n{out.decode()}\nSTDERR:\n{err.decode()}")
    
    def get_logs(self):
        """Get nginx logs for debugging"""
        logs = {}
        log_files = ['error.log', 'access.log', 'api_error.log', 'api_access.log']
        
        for log_file in log_files:
            log_path = self.workdir / "logs" / log_file
            if log_path.exists():
                try:
                    logs[log_file] = log_path.read_text()
                except Exception as e:
                    logs[log_file] = f"Error reading log: {e}"
            else:
                logs[log_file] = "Log file not found"
        
        return logs
    
    def stop(self):
        if self.process:
            # Get logs before stopping
            logs = self.get_logs()
            logger.info("=== NGINX LOGS ===")
            for log_name, log_content in logs.items():
                logger.info(f"--- {log_name} ---")
                logger.info(log_content[-1000:])  # Last 1000 chars
                logger.info(f"--- End {log_name} ---")
            
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

@pytest.fixture
def backend_servers():
    servers = [
        BackendServer(8081),
        BackendServer(8082)
    ]
    for server in servers:
        server.start()
    yield servers
    for server in servers:
        server.stop()

@pytest.fixture
def nginx_server(tmp_path):
    nginx_bin = os.getenv('NGINX_BIN', '/usr/sbin/nginx')
    module_path = os.getenv('MODULE_PATH', './ngx_http_api/upstreams_module.so')
    config_path = tmp_path / "nginx.conf"
    
    server = NginxServer(nginx_bin, str(config_path), module_path)
    try:
        server.start()
        yield server
    finally:
        server.stop()

# Basic API Tests
def test_api_connectivity(nginx_server, backend_servers):
    """Test basic API connectivity and endpoint availability"""
    # Test if nginx is responding
    response = requests.get('http://localhost:8080/')
    log_request_response("GET", "http://localhost:8080/", response)
    assert response.status_code == 200
    
    # Test if API endpoint exists
    response = requests.get('http://localhost:8080/api/upstreams')
    log_request_response("GET", "http://localhost:8080/api/upstreams", response)
    
    if response.status_code == 404:
        pytest.skip("API endpoints not configured properly")
    
    assert response.status_code == 200

def test_get_upstream_servers(nginx_server, backend_servers):
    """Test getting the list of upstream servers"""
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    log_request_response("GET", "http://localhost:8080/api/upstreams/backend", response)
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify structure and content
    assert 'servers' in data
    assert len(data['servers']) == 2
    
    # Verify each server has required fields
    for server in data['servers']:
        assert 'id' in server
        assert 'backup' in server
        assert 'down' in server
        assert 'fail_timeout' in server

def test_set_server_drain_state(nginx_server, backend_servers):
    """Test setting drain state for a specific server"""
    # First get the current state and server ID
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    log_request_response("GET", "http://localhost:8080/api/upstreams/backend", response)
    
    assert response.status_code == 200
    data = response.json()
    
    servers = data.get('servers', [])
    if not servers:
        raise ValueError(f"No servers found in response: {data}")
        
    server_id = servers[0]['id']

    # Test setting drain to true
    url = f'http://localhost:8080/api/upstreams/backend/servers/{server_id}'
    payload = '{"drain":true}'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
        'Content-Length': str(len(payload))
    }
    
    drain_response = requests.patch(url, data=payload, headers=headers)
    log_request_response("PATCH", url, drain_response, payload, headers)
    
    if drain_response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    elif drain_response.status_code == 404:
        pytest.skip("API endpoint not found - check nginx configuration")
    
    assert drain_response.status_code == 200
    assert drain_response.json() == {"status": "success"}

    # Verify the server state was updated
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    updated_data = response.json()
    print(f"Updated Response Data: {updated_data}")
    
    updated_servers = updated_data.get('servers', [])
    updated_server = next(
        server for server in updated_servers
        if server['id'] == server_id
    )
    assert updated_server['down'] is True

def test_unset_server_drain_state(nginx_server, backend_servers):
    """Test unsetting drain state for a specific server"""
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    data = response.json()
    servers = data.get('servers', [])
    if not servers:
        raise ValueError(f"No servers found in response: {data}")
    server_id = servers[0]['id']

    # First set drain to true
    url = f'http://localhost:8080/api/upstreams/backend/servers/{server_id}'
    payload = '{"drain":true}'
    set_drain_response = requests.patch(
        url,
        data=payload,
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Content-Length': str(len(payload))
        }
    )
    logger.info(f"Set drain response: {set_drain_response.status_code} - {set_drain_response.text}")
    if set_drain_response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert set_drain_response.status_code == 200

    # Then set drain to false
    payload = '{"drain":false}'
    unset_drain_response = requests.patch(
        url,
        data=payload,
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Content-Length': str(len(payload))
        }
    )
    logger.info(f"Unset drain response: {unset_drain_response.status_code} - {unset_drain_response.text}")
    assert unset_drain_response.status_code == 200
    assert unset_drain_response.json() == {"status": "success"}

    # Verify the server state was updated
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    updated_data = response.json()
    updated_servers = updated_data.get('servers', [])
    updated_server = next(
        server for server in updated_servers
        if server['id'] == server_id
    )
    assert updated_server['down'] is False

def test_drain_nonexistent_server(nginx_server, backend_servers):
    """Test setting drain state for a non-existent server"""
    url = 'http://localhost:8080/api/upstreams/backend/servers/999'
    payload = '{"drain":true}'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*'
    }
    response = requests.patch(url, data=payload, headers=headers)
    log_request_response("PATCH", url, response, payload, headers)
    if response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert response.status_code == 404

def test_invalid_drain_value(nginx_server, backend_servers):
    """Test setting invalid drain value"""
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    data = response.json()
    servers = data.get('servers', [])
    if not servers:
        raise ValueError(f"No servers found in response: {data}")
    server_id = servers[0]['id']

    url = f'http://localhost:8080/api/upstreams/backend/servers/{server_id}'
    payload = '{"drain":"invalid"}'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*'
    }
    response = requests.patch(url, data=payload, headers=headers)
    log_request_response("PATCH", url, response, payload, headers)
    if response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert response.status_code == 400

# Routing Tests
def test_drain_upstream_routing(nginx_server, backend_servers):
    """Test that traffic is properly routed when an upstream is drained"""
    # First get the current state and server IDs
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    data = response.json()
    
    servers = data['servers']
    if not servers:
        raise ValueError(f"No servers found in response: {data}")
    
    # Get server ID for the first backend (8081)
    server_id = servers[0]['id']
    
    # Make multiple requests and collect upstream information before drain
    upstream_distribution_before = defaultdict(int)
    for _ in range(50):
        response = requests.get('http://localhost:8080/')
        assert response.status_code == 200
        upstream = response.headers.get('X-Upstream')
        upstream_distribution_before[upstream] += 1
    
    # Verify both upstreams are receiving traffic
    assert len(upstream_distribution_before) == 2, "Traffic should be distributed to both upstreams"
    logger.info(f"Traffic distribution before drain: {dict(upstream_distribution_before)}")
    
    # Set drain state for the first server
    url = f'http://localhost:8080/api/upstreams/backend/servers/{server_id}'
    payload = '{"drain":true}'
    
    drain_response = requests.patch(
        url,
        data=payload,
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Content-Length': str(len(payload))
        }
    )
    logger.info(f"Drain response: {drain_response.status_code} - {drain_response.text}")
    
    if drain_response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert drain_response.status_code == 200

    # Verify the server was marked as down
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    updated_data = response.json()
    updated_server = next(
        server for server in updated_data['servers']
        if server['id'] == server_id
    )
    assert updated_server['down'] is True

    # Wait a short time for drain state to take effect
    time.sleep(1)
    
    # Make multiple requests and collect upstream information after drain
    upstream_distribution_after = defaultdict(int)
    for _ in range(50):
        response = requests.get('http://localhost:8080/')
        assert response.status_code == 200
        upstream = response.headers.get('X-Upstream')
        upstream_distribution_after[upstream] += 1
    
    logger.info(f"Traffic distribution after drain: {dict(upstream_distribution_after)}")
    
    # Verify traffic is only going to the non-drained upstream
    assert len(upstream_distribution_after) == 1, "Traffic should only go to non-drained upstream"

def test_undrain_upstream_routing(nginx_server, backend_servers):
    """Test that traffic distribution returns to normal after undraining an upstream"""
    # First get the current state and server ID
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    data = response.json()
    servers = data['servers']
    server_id = servers[0]['id']
    
    # Set drain state
    url = f'http://localhost:8080/api/upstreams/backend/servers/{server_id}'
    drain_response = requests.patch(
        url,
        data='{"drain":true}',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*'
        }
    )
    assert drain_response.status_code == 200
    
    # Verify traffic is only going to non-drained upstream
    time.sleep(1)
    drained_distribution = defaultdict(int)
    for _ in range(50):
        response = requests.get('http://localhost:8080/')
        assert response.status_code == 200
        upstream = response.headers.get('X-Upstream')
        drained_distribution[upstream] += 1
    
    assert len(drained_distribution) == 1, "During drain, traffic should only go to non-drained upstream"
    
    # Then undrain it
    undrain_response = requests.patch(
        url,
        data='{"drain":false}',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*'
        }
    )
    assert undrain_response.status_code == 200
    
    # Wait a short time for undrain to take effect
    time.sleep(1)
    
    # Verify traffic distribution returns to normal
    normal_distribution = defaultdict(int)
    for _ in range(50):
        response = requests.get('http://localhost:8080/')
        assert response.status_code == 200
        upstream = response.headers.get('X-Upstream')
        normal_distribution[upstream] += 1
    
    logger.info(f"Traffic distribution after undrain: {dict(normal_distribution)}")
    
    # Verify both upstreams are receiving traffic again
    assert len(normal_distribution) == 2, "Traffic should be distributed to both upstreams after undrain"
    # Check for reasonable distribution (allowing for some variance)
    total_requests = sum(normal_distribution.values())
    for count in normal_distribution.values():
        distribution_percentage = (count / total_requests) * 100
        assert 30 <= distribution_percentage <= 70, f"Traffic distribution {distribution_percentage}% is outside expected range (30-70%)"

def test_multiple_drains(nginx_server, backend_servers):
    """Test behavior when attempting to drain all upstreams"""
    # Get server IDs
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    data = response.json()
    servers = data['servers']
    assert len(servers) >= 2, "Test requires at least 2 upstream servers"
    
    # Try to drain first server
    url1 = f'http://localhost:8080/api/upstreams/backend/servers/{servers[0]["id"]}'
    response1 = requests.patch(
        url1,
        data='{"drain":true}',
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    logger.info(f"First drain response: {response1.status_code} - {response1.text}")
    assert response1.status_code == 200
    
    # Try to drain second server
    url2 = f'http://localhost:8080/api/upstreams/backend/servers/{servers[1]["id"]}'
    response2 = requests.patch(
        url2,
        data='{"drain":true}',
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    logger.info(f"Second drain response: {response2.status_code} - {response2.text}")
    
    # The module should either:
    # 1. Prevent draining all servers (return 400)
    # 2. Allow it but maintain at least one active server
    if response2.status_code == 200:
        # If second drain was allowed, verify at least one server still accepts traffic
        time.sleep(1)
        success_count = 0
        for _ in range(10):
            response = requests.get('http://localhost:8080/')
            if response.status_code == 200:
                success_count += 1
        assert success_count > 0, "Should still successfully serve some traffic with multiple drains"
    else:
        # If second drain was prevented, should be 400 Bad Request
        assert response2.status_code == 400, "Expected 400 Bad Request when trying to drain all servers"

def test_backend_status_with_one_down(nginx_server, backend_servers):
    """Test that API correctly shows status when one backend is down"""
    # First stop one of the backend servers
    backend_servers[1].stop()  # Stop the second backend (8082)
    
    # Wait a moment for nginx to detect the down state
    time.sleep(2)
    
    # Make some requests to ensure nginx marks the server as down
    for _ in range(5):
        try:
            requests.get('http://localhost:8080/')
        except:
            pass
    
    # Get the upstream status via API
    response = requests.get('http://localhost:8080/api/upstreams/backend')
    assert response.status_code == 200
    data = response.json()
    
    # Verify we have info for both servers
    assert 'servers' in data
    assert len(data['servers']) == 2, "Should show both backends even when one is down"
    
    # Verify servers status
    servers_status = {server['server']: server['down'] for server in data['servers']}
    assert not servers_status['127.0.0.1:8081'], "First backend should be up"
    assert servers_status['127.0.0.1:8082'], "Second backend should be down"
    
    # Verify traffic only goes to the working backend
    distribution = defaultdict(int)
    for _ in range(10):
        response = requests.get('http://localhost:8080/')
        assert response.status_code == 200
        upstream = response.headers.get('X-Upstream')
        distribution[upstream] += 1
    
    # Should only see traffic to 8081
    assert len(distribution) == 1, "Traffic should only go to the working backend"
    assert '127.0.0.1:8081' in distribution, "Traffic should go to the working backend"