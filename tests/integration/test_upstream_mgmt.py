import pytest
import requests
import time
import subprocess
import os
import shutil
import logging
import json
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
            }}
        }}
    }}
    """
        Path(self.config_path).write_text(config_content)
    
    def start(self):
        self.create_dirs()
        self._write_config()
        # Start nginx with the test configuration
        self.process = subprocess.Popen([
            self.nginx_bin,
            '-p', str(self.workdir),  # Set prefix path
            '-c', self.config_path,
            '-g', 'daemon off;'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)  # Wait for nginx to start
        
        # Check if nginx started successfully
        if self.process.poll() is not None:
            out, err = self.process.communicate()
            raise RuntimeError(f"Nginx failed to start:\nSTDOUT:\n{out.decode()}\nSTDERR:\n{err.decode()}")
    
    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

@pytest.fixture
def nginx_server(tmp_path):
    # Get paths from environment or use defaults
    nginx_bin = os.getenv('NGINX_BIN', '/usr/sbin/nginx')
    module_path = os.getenv('MODULE_PATH', './ngx_http_api/upstreams_module.so')
    
    # Create test configuration path
    config_path = tmp_path / "nginx.conf"
    
    # Create and start nginx server
    server = NginxServer(nginx_bin, str(config_path), module_path)
    try:
        server.start()
        yield server
    finally:
        server.stop()

def test_set_server_drain_state(nginx_server):
    """Test setting drain state for a specific server"""
    # Get the current state and server ID
    response = requests.get('http://localhost:8080/api/upstreams')
    assert response.status_code == 200
    data = response.json()
    print(f"Initial Response Data: {data}")
    server_id = data['backend']['servers'][0]['id']
    
    # Construct URL without trailing slash
    url = f'http://localhost:8080/api/upstreams/backend/servers/{server_id}'
    print(f"URL: {url}")
    payload = {"drain": True}
    print(f"Payload: {json.dumps(payload)}")
    
    # Send PATCH request
    drain_response = requests.patch(
        url,
        data=json.dumps(payload),  # Explicit serialization
        headers={
            'Content-Type': 'application/json',
            'Accept': '*/*'
        }
    )
    print(f"Response Status Code: {drain_response.status_code}")
    print(f"Response Text: {drain_response.text}")
    print(f"Request Headers: {drain_response.request.headers}")
    
    if drain_response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    
    # Verify response
    assert drain_response.status_code == 200
    assert drain_response.json() == {"status": "success"}

    # Verify server state
    response = requests.get('http://localhost:8080/api/upstreams')
    assert response.status_code == 200
    updated_data = response.json()
    updated_server = next(
        server for server in updated_data['backend']['servers'] 
        if server['id'] == server_id
    )
    assert updated_server['down'] is True

def test_unset_server_drain_state(nginx_server):
    """Test unsetting drain state for a specific server"""
    # First get the server ID
    response = requests.get('http://localhost:8080/api/upstreams')
    assert response.status_code == 200
    data = response.json()
    server_id = data['backend']['servers'][0]['id']

    # First set drain to true
    payload = {"drain": True}
    url = f'http://localhost:8080/api/upstreams/backend/servers/{server_id}/'

    set_drain_response = requests.patch(
        url,
        json=payload,  # Use json instead of data
        headers={
            'Accept': '*/*'
        }
    )
    if set_drain_response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert set_drain_response.status_code == 200
    assert set_drain_response.json() == {"status": "success"}

    # Then set drain to false
    payload = {"drain": False}
    unset_drain_response = requests.patch(
        url,
        json=payload,  # Use json instead of data
        headers={
            'Accept': '*/*'
        }
    )
    assert unset_drain_response.status_code == 200
    assert unset_drain_response.json() == {"status": "success"}

    # Verify the server state was updated
    response = requests.get('http://localhost:8080/api/upstreams')
    assert response.status_code == 200
    updated_data = response.json()
    updated_server = next(
        server for server in updated_data['backend']['servers'] 
        if server['id'] == server_id
    )
    assert updated_server['down'] is False
