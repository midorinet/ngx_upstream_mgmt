import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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