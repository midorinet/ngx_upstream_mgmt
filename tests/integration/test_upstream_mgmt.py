import pytest
import requests
import time
import subprocess
import os
import shutil
from pathlib import Path

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
    
    def start(self):
        self.create_dirs()
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
    
    # Create test configuration
    config = tmp_path / "nginx.conf"
    config.write_text(f"""
    worker_processes  1;
    error_log logs/error.log debug;
    pid logs/nginx.pid;
    
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
    """)
    
    # Create and start nginx server
    server = NginxServer(nginx_bin, str(config), module_path)
    try:
        server.start()
        yield server
    finally:
        server.stop()

def test_get_upstream_status(nginx_server):
    """Test getting upstream server status"""
    for _ in range(3):  # Retry a few times
        try:
            response = requests.get('http://localhost:8080/upstream_mgmt')
            assert response.status_code == 200
            data = response.json()
            assert 'servers' in data
            return
        except requests.ConnectionError:
            time.sleep(1)
    pytest.fail("Failed to connect to nginx after retries")

def test_nonexistent_server(nginx_server):
    """Test modifying non-existent server"""
    try:
        data = {'server': '127.0.0.1:9999', 'state': 'down'}
        response = requests.post('http://localhost:8080/upstream_mgmt', json=data)
        assert response.status_code == 404
    except requests.ConnectionError as e:
        pytest.fail(f"Failed to connect to nginx: {e}")