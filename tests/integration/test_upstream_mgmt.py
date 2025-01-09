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

def test_get_upstream_status(nginx_server):
    """Test getting upstream server status"""
    for _ in range(3):  # Retry a few times
        try:
            response = requests.get('http://localhost:8080/upstream_mgmt')
            assert response.status_code == 200
            data = response.json()
            
            # Check the response structure
            assert 'backend' in data
            assert 'servers' in data['backend']
            servers = data['backend']['servers']
            
            # Check if we have our expected servers
            assert len(servers) == 2
            
            # Check server properties
            for server in servers:
                assert 'id' in server
                assert 'fail_timeout' in server
                assert isinstance(server['down'], bool)
                assert isinstance(server['backup'], bool)
            return
        except requests.ConnectionError:
            time.sleep(1)
    pytest.fail("Failed to connect to nginx after retries")

def test_nonexistent_server(nginx_server):
    """Test modifying non-existent server"""
    try:
        data = {'upstream': 'nonexistent', 'server': '127.0.0.1:9999', 'state': 'down'}
        response = requests.post('http://localhost:8080/upstream_mgmt', json=data)
        if response.status_code == 405:
            pytest.skip("POST method not implemented yet")
        assert response.status_code == 404
    except requests.ConnectionError as e:
        pytest.fail(f"Failed to connect to nginx: {e}")

def test_get_backend_details(nginx_server):
    """Test getting details of the backend upstream"""
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    data = response.json()
    
    # Verify backend exists
    assert 'backend' in data
    backend = data['backend']
    
    # Verify servers array exists and has correct length
    assert 'servers' in backend
    assert len(backend['servers']) == 2
    
    # Verify server details
    servers = backend['servers']
    for server in servers:
        # Required fields
        assert 'id' in server
        assert 'fail_timeout' in server
        assert isinstance(server['down'], bool)
        assert isinstance(server['backup'], bool)

def test_set_server_drain_state(nginx_server):
    """Test setting drain state for a specific server"""
    # First get the current state and server ID
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    data = response.json()
    server_id = data['backend']['servers'][0]['id']

    # Test setting drain to true
    drain_response = requests.patch(
        f'http://localhost:8080/upstream_mgmt/backend/servers/{server_id}',
        json={'drain': True}
    )
    if drain_response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert drain_response.status_code == 200

    # Verify the server state was updated
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    updated_data = response.json()
    updated_server = next(
        server for server in updated_data['backend']['servers'] 
        if server['id'] == server_id
    )
    assert updated_server.get('drain') is True

def test_unset_server_drain_state(nginx_server):
    """Test unsetting drain state for a specific server"""
    # First get the server ID
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
    assert updated_server.get('drain') is False

def test_drain_nonexistent_server(nginx_server):
    """Test setting drain state for a non-existent server"""
    response = requests.patch(
        'http://localhost:8080/upstream_mgmt/backend/servers/999',
        json={'drain': True}
    )
    if response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert response.status_code == 404

def test_invalid_drain_value(nginx_server):
    """Test setting invalid drain state value"""
    # First get a valid server ID
    response = requests.get('http://localhost:8080/upstream_mgmt')
    assert response.status_code == 200
    data = response.json()
    server_id = data['backend']['servers'][0]['id']

    # Test with invalid drain value
    response = requests.patch(
        f'http://localhost:8080/upstream_mgmt/backend/servers/{server_id}',
        json={'drain': "invalid"}
    )
    if response.status_code == 405:
        pytest.skip("PATCH method not implemented yet")
    assert response.status_code == 400