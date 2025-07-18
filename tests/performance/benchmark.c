#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

// Mock nginx types for performance testing
typedef struct {
    size_t len;
    char* data;
} ngx_str_t;

typedef unsigned int ngx_uint_t;
typedef int ngx_int_t;
#define NGX_OK 0
#define NGX_ERROR -1

// Mock request structure
typedef struct {
    ngx_str_t uri;
} mock_request_t;

typedef struct {
    ngx_str_t upstream;
    ngx_uint_t server_id;
    ngx_str_t state;
} mock_upstream_mgmt_request_t;

// Original (unoptimized) URI parsing function
ngx_int_t parse_uri_original(mock_request_t *r, mock_upstream_mgmt_request_t *req) {
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

// Optimized URI parsing function
ngx_int_t parse_uri_optimized(mock_request_t *r, mock_upstream_mgmt_request_t *req) {
    char *uri = r->uri.data;
    size_t uri_len = r->uri.len;
    static const char prefix[] = "/api/upstreams/";
    static const char servers_path[] = "/servers/";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t servers_len = sizeof(servers_path) - 1;
    
    // Check minimum URI length and prefix
    if (uri_len < prefix_len || strncmp(uri, prefix, prefix_len) != 0) {
        return NGX_ERROR;
    }
    
    char *upstream_start = uri + prefix_len;
    char *uri_end = uri + uri_len;
    char *server_start = strchr(upstream_start, '/');
    
    if (!server_start || (uri_end - server_start) < servers_len ||
        strncmp(server_start, servers_path, servers_len) != 0) {
        return NGX_ERROR;
    }
    
    req->upstream.data = upstream_start;
    req->upstream.len = server_start - upstream_start;
    
    server_start += servers_len;
    req->server_id = (ngx_uint_t)atoi(server_start);
    
    return NGX_OK;
}

// Performance benchmark function
void benchmark_uri_parsing() {
    const int iterations = 100000;
    mock_request_t req;
    mock_upstream_mgmt_request_t parsed;
    clock_t start, end;
    double cpu_time_used;
    
    // Test data
    char test_uri[] = "/api/upstreams/backend/servers/1";
    req.uri.data = test_uri;
    req.uri.len = strlen(test_uri);
    
    printf("Benchmarking URI parsing with %d iterations...\n", iterations);
    
    // Benchmark original function
    start = clock();
    for (int i = 0; i < iterations; i++) {
        parse_uri_original(&req, &parsed);
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Original function: %f seconds\n", cpu_time_used);
    double original_time = cpu_time_used;
    
    // Benchmark optimized function
    start = clock();
    for (int i = 0; i < iterations; i++) {
        parse_uri_optimized(&req, &parsed);
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Optimized function: %f seconds\n", cpu_time_used);
    double optimized_time = cpu_time_used;
    
    // Calculate improvement
    double improvement = ((original_time - optimized_time) / original_time) * 100;
    printf("Performance improvement: %.2f%%\n", improvement);
    
    // Verify correctness
    parse_uri_original(&req, &parsed);
    assert(parsed.upstream.len == 7);
    assert(strncmp(parsed.upstream.data, "backend", 7) == 0);
    assert(parsed.server_id == 1);
    
    parse_uri_optimized(&req, &parsed);
    assert(parsed.upstream.len == 7);
    assert(strncmp(parsed.upstream.data, "backend", 7) == 0);
    assert(parsed.server_id == 1);
    
    printf("✓ Correctness verified for both functions\n");
}

int main() {
    printf("NGINX Upstream Management Module - Performance Benchmark\n");
    printf("========================================================\n\n");
    
    benchmark_uri_parsing();
    
    printf("\n✅ Performance benchmark completed successfully!\n");
    return 0;
}