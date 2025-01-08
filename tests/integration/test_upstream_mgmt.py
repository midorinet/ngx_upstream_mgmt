import pytest
import requests
import time
import subprocess
import os
import signal
from pathlib import Path

class NginxServer:
    def __init__(self, config_path):
        self.config_path = config_path
        self.process = None
    
    def start(self):
        self.process = subprocess.Popen([
            'nginx',
            '-c', self.config_path,
            '-g', 'daemon off;'
        ])
        time.sleep(2)  # Wait for nginx to start
    
    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()

@pytest.fixture
def nginx_server(tmp_path):
    # Create test configuration
    config = tmp_path / "nginx.conf"
    config.write_text("""
    worker_processes  1;
    error_log logs/error.log debug;
    
    events {
        worker_connections  1024;
    }
    
    http {
        upstream backend {
            server 127.0.0.1:8081;
            server 127.0.0.1:8082;
        }
        
        server {
            listen 8080;
            location /upstream_mgmt {
                upstream_mgmt;
            }
            
            location / {
                proxy_pass http://backend;
            }
        }
    }
    """)
    
    server = NginxServer(str(config))
    server.start()
    yield server
    server.stop()

def test_get_upstream_status(nginx_server):
    """Test getting upstream server status"""
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    data = response.json()
    assert 'servers' in data

def test_modify_upstream_state(nginx_server):
    """Test modifying upstream server state"""
    data = {'server': '127.0.0.1:8081', 'state': 'down'}
    response = requests.post('http://localhost:8080/upstream_mgmt', json=data)
    assert response.status_code == 200
    
    # Verify state change
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    data = response.json()
    server_found = False
    for server in data['servers']:
        if server['address'] == '127.0.0.1:8081':
            assert server['state'] == 'down'
            server_found = True
    assert server_found

def test_invalid_state_change(nginx_server):
    """Test invalid state change request"""
    data = {'server': '127.0.0.1:8081', 'state': 'invalid'}
    response = requests.post('http://localhost:8080/upstream_mgmt', json=data)
    assert response.status_code == 400

def test_nonexistent_server(nginx_server):
    """Test modifying non-existent server"""
    data = {'server': '127.0.0.1:9999', 'state': 'down'}
    response = requests.post('http://localhost:8080/upstream_mgmt', json=data)
    assert response.status_code == 404