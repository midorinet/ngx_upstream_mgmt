#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Mock the nginx includes and structures
typedef struct {
    size_t len;
    char* data;
} ngx_str_t;

typedef unsigned int ngx_uint_t;
typedef int ngx_int_t;
#define NGX_OK 0
#define NGX_ERROR -1

// Mock request structure for URI parsing tests
typedef struct {
    ngx_str_t uri;
} mock_request_t;

typedef struct {
    ngx_str_t upstream;
    ngx_uint_t server_id;
    ngx_str_t state;
} mock_upstream_mgmt_request_t;

// Function declarations that would normally come from your module
ngx_int_t parse_upstream_state(ngx_str_t *state);
ngx_int_t parse_uri_components(mock_request_t *r, mock_upstream_mgmt_request_t *req);
ngx_int_t parse_json_body(ngx_str_t *body, mock_upstream_mgmt_request_t *req);
size_t calculate_json_buffer_size(ngx_uint_t num_upstreams, ngx_uint_t num_servers);

// Test implementations
ngx_int_t parse_upstream_state(ngx_str_t *state) {
    if (state == NULL || state->data == NULL) {
        return NGX_ERROR;
    }
    
    if (state->len == 2 && strncmp(state->data, "up", 2) == 0) {
        return NGX_OK;
    }
    
    if (state->len == 5 && strncmp(state->data, "drain", 5) == 0) {
        return NGX_OK;
    }
    
    return NGX_ERROR;
}

ngx_int_t parse_uri_components(mock_request_t *r, mock_upstream_mgmt_request_t *req) {
    char *uri = r->uri.data;
    char *upstream_start = strstr(uri, "/api/upstreams/");
    
    if (!upstream_start) {
        return NGX_ERROR;
    }
    
    upstream_start += strlen("/api/upstreams/");
    char *server_start = strstr(upstream_start, "/servers/");
    
    if (!server_start) {
        return NGX_ERROR;
    }
    
    req->upstream.data = upstream_start;
    req->upstream.len = server_start - upstream_start;
    
    server_start += strlen("/servers/");
    req->server_id = (ngx_uint_t)atoi(server_start);
    
    return NGX_OK;
}

ngx_int_t parse_json_body(ngx_str_t *body, mock_upstream_mgmt_request_t *req) {
    if (body == NULL || body->data == NULL) {
        return NGX_ERROR;
    }
    
    if (strstr(body->data, "\"drain\":true")) {
        req->state.data = "drain";
        req->state.len = 5;
        return NGX_OK;
    } else if (strstr(body->data, "\"drain\":false")) {
        req->state.data = "up";
        req->state.len = 2;
        return NGX_OK;
    }
    
    return NGX_ERROR;
}

size_t calculate_json_buffer_size(ngx_uint_t num_upstreams, ngx_uint_t num_servers) {
    size_t base_size = 2;  // {}
    size_t per_upstream = 50;  // estimated overhead per upstream
    size_t per_server = 150;   // estimated size per server
    
    return base_size + (num_upstreams * per_upstream) + (num_servers * per_server);
}

// Test functions
void test_parse_upstream_state() {
    ngx_str_t input = { 2, "up" };
    ngx_int_t result = parse_upstream_state(&input);
    assert(result == NGX_OK);
    printf("✓ test_parse_upstream_state passed\n");
}

void test_parse_drain_state() {
    ngx_str_t input = { 5, "drain" };
    ngx_int_t result = parse_upstream_state(&input);
    assert(result == NGX_OK);
    printf("✓ test_parse_drain_state passed\n");
}

void test_parse_invalid_upstream_state() {
    ngx_str_t input = { 7, "invalid" };
    ngx_int_t result = parse_upstream_state(&input);
    assert(result == NGX_ERROR);
    printf("✓ test_parse_invalid_upstream_state passed\n");
}

void test_parse_null_state() {
    ngx_int_t result = parse_upstream_state(NULL);
    assert(result == NGX_ERROR);
    printf("✓ test_parse_null_state passed\n");
}

void test_parse_uri_valid() {
    mock_request_t req;
    mock_upstream_mgmt_request_t parsed;
    req.uri.data = "/api/upstreams/backend/servers/1";
    req.uri.len = strlen(req.uri.data);
    
    ngx_int_t result = parse_uri_components(&req, &parsed);
    assert(result == NGX_OK);
    assert(parsed.upstream.len == 7);  // "backend"
    assert(strncmp(parsed.upstream.data, "backend", 7) == 0);
    assert(parsed.server_id == 1);
    printf("✓ test_parse_uri_valid passed\n");
}

void test_parse_uri_invalid() {
    mock_request_t req;
    mock_upstream_mgmt_request_t parsed;
    req.uri.data = "/invalid/path";
    req.uri.len = strlen(req.uri.data);
    
    ngx_int_t result = parse_uri_components(&req, &parsed);
    assert(result == NGX_ERROR);
    printf("✓ test_parse_uri_invalid passed\n");
}

void test_parse_json_drain_true() {
    ngx_str_t body = { 15, "{\"drain\":true}" };
    mock_upstream_mgmt_request_t req;
    
    ngx_int_t result = parse_json_body(&body, &req);
    assert(result == NGX_OK);
    assert(req.state.len == 5);
    assert(strncmp(req.state.data, "drain", 5) == 0);
    printf("✓ test_parse_json_drain_true passed\n");
}

void test_parse_json_drain_false() {
    ngx_str_t body = { 16, "{\"drain\":false}" };
    mock_upstream_mgmt_request_t req;
    
    ngx_int_t result = parse_json_body(&body, &req);
    assert(result == NGX_OK);
    assert(req.state.len == 2);
    assert(strncmp(req.state.data, "up", 2) == 0);
    printf("✓ test_parse_json_drain_false passed\n");
}

void test_parse_json_invalid() {
    ngx_str_t body = { 18, "{\"invalid\":\"json\"}" };
    mock_upstream_mgmt_request_t req;
    
    ngx_int_t result = parse_json_body(&body, &req);
    assert(result == NGX_ERROR);
    printf("✓ test_parse_json_invalid passed\n");
}

void test_buffer_size_calculation() {
    size_t size = calculate_json_buffer_size(2, 4);
    assert(size > 0);
    assert(size == 2 + (2 * 50) + (4 * 150));  // base + upstreams + servers
    printf("✓ test_buffer_size_calculation passed\n");
}

int main(void) {
    printf("Running enhanced unit tests...\n");
    
    // Original tests
    test_parse_upstream_state();
    test_parse_drain_state();
    test_parse_invalid_upstream_state();
    test_parse_null_state();
    
    // New tests
    test_parse_uri_valid();
    test_parse_uri_invalid();
    test_parse_json_drain_true();
    test_parse_json_drain_false();
    test_parse_json_invalid();
    test_buffer_size_calculation();
    
    printf("All tests passed!\n");
    return EXIT_SUCCESS;
}