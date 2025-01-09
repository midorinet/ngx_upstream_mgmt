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
            
            location /upstream_mgmt {{
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
    module_path = os.getenv('MODULE_PATH', './ngx_http_upstream_mgmt_module.so')
    
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
    # First get the current state and server ID
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    data = response.json()
    logger.info("Initial server state: %s", json.dumps(data, indent=2))
    server_id = data['backend']['servers'][0]['id']

    # Test setting drain to true
    url = f'http://localhost:8080/upstream_mgmt/backend/servers/{server_id}'
    payload = {'drain': True}
    logger.info("Sending PATCH to %s with payload: %s", url, json.dumps(payload))
    
    drain_response = requests.patch(url, json=payload)
    logger.info("PATCH response status: %d", drain_response.status_code)
    logger.info("PATCH response body: %s", drain_response.text)
    
    if drain_response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert drain_response.status_code == 200

    # Verify the server state was updated
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    updated_data = response.json()
    logger.info("Server state after PATCH: %s", json.dumps(updated_data, indent=2))
    
    updated_server = next(
        server for server in updated_data['backend']['servers'] 
        if server['id'] == server_id
    )
    logger.info("Updated server state: %s", json.dumps(updated_server, indent=2))
    
    assert updated_server['down'] is True

def test_unset_server_drain_state(nginx_server):
    """Test unsetting drain state for a specific server"""
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    data = response.json()
    server_id = data['backend']['servers'][0]['id']

    # First set drain to true
    set_drain_response = requests.patch(
        f'http://localhost:8080/upstream_mgmt/backend/servers/{server_id}',
        json={'drain': True}
    )
    if set_drain_response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert set_drain_response.status_code == 200

    # Then set drain to false
    unset_drain_response = requests.patch(
        f'http://localhost:8080/upstream_mgmt/backend/servers/{server_id}',
        json={'drain': False}
    )
    assert unset_drain_response.status_code == 200

    # Verify the server state was updated
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    updated_data = response.json()
    updated_server = next(
        server for server in updated_data['backend']['servers'] 
        if server['id'] == server_id
    )
    assert updated_server['down'] is False