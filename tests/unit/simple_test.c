#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Mock the nginx includes and structures
typedef struct {
    size_t len;
    char* data;
} ngx_str_t;

typedef int ngx_int_t;
typedef unsigned int ngx_uint_t;
#define NGX_OK 0
#define NGX_ERROR -1

// Test function implementations
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

ngx_int_t validate_server_id(ngx_uint_t server_id, ngx_uint_t max_servers) {
    if (server_id >= max_servers) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t parse_json_drain_value(const char *json, size_t len) {
    if (json == NULL || len == 0) {
        return NGX_ERROR;
    }
    
    const char *drain_pos = strstr(json, "\"drain\":");
    if (drain_pos == NULL) {
        return NGX_ERROR;
    }
    
    drain_pos += 8; // Skip "drain":
    while (*drain_pos == ' ' || *drain_pos == '\t') {
        drain_pos++; // Skip whitespace
    }
    
    if (strncmp(drain_pos, "true", 4) == 0 || strncmp(drain_pos, "false", 5) == 0) {
        return NGX_OK;
    }
    
    return NGX_ERROR;
}

// Simple test runner
int run_tests() {
    int tests_passed = 0;
    int tests_failed = 0;
    
    printf("Running simple unit tests...\n");
    
    // Test 1: parse_upstream_state with "up"
    {
        ngx_str_t input = { 2, "up" };
        ngx_int_t result = parse_upstream_state(&input);
        if (result == NGX_OK) {
            printf("✓ Test 1 passed: parse_upstream_state('up')\n");
            tests_passed++;
        } else {
            printf("✗ Test 1 failed: parse_upstream_state('up')\n");
            tests_failed++;
        }
    }
    
    // Test 2: parse_upstream_state with "drain"
    {
        ngx_str_t input = { 5, "drain" };
        ngx_int_t result = parse_upstream_state(&input);
        if (result == NGX_OK) {
            printf("✓ Test 2 passed: parse_upstream_state('drain')\n");
            tests_passed++;
        } else {
            printf("✗ Test 2 failed: parse_upstream_state('drain')\n");
            tests_failed++;
        }
    }
    
    // Test 3: parse_upstream_state with invalid input
    {
        ngx_str_t input = { 7, "invalid" };
        ngx_int_t result = parse_upstream_state(&input);
        if (result == NGX_ERROR) {
            printf("✓ Test 3 passed: parse_upstream_state('invalid')\n");
            tests_passed++;
        } else {
            printf("✗ Test 3 failed: parse_upstream_state('invalid')\n");
            tests_failed++;
        }
    }
    
    // Test 4: parse_upstream_state with NULL
    {
        ngx_int_t result = parse_upstream_state(NULL);
        if (result == NGX_ERROR) {
            printf("✓ Test 4 passed: parse_upstream_state(NULL)\n");
            tests_passed++;
        } else {
            printf("✗ Test 4 failed: parse_upstream_state(NULL)\n");
            tests_failed++;
        }
    }
    
    // Test 5: validate_server_id with valid ID
    {
        ngx_int_t result = validate_server_id(0, 5);
        if (result == NGX_OK) {
            printf("✓ Test 5 passed: validate_server_id(0, 5)\n");
            tests_passed++;
        } else {
            printf("✗ Test 5 failed: validate_server_id(0, 5)\n");
            tests_failed++;
        }
    }
    
    // Test 6: validate_server_id with invalid ID
    {
        ngx_int_t result = validate_server_id(5, 5);
        if (result == NGX_ERROR) {
            printf("✓ Test 6 passed: validate_server_id(5, 5)\n");
            tests_passed++;
        } else {
            printf("✗ Test 6 failed: validate_server_id(5, 5)\n");
            tests_failed++;
        }
    }
    
    // Test 7: parse_json_drain_value with true
    {
        const char *json = "{\"drain\":true}";
        ngx_int_t result = parse_json_drain_value(json, strlen(json));
        if (result == NGX_OK) {
            printf("✓ Test 7 passed: parse_json_drain_value('{\"drain\":true}')\n");
            tests_passed++;
        } else {
            printf("✗ Test 7 failed: parse_json_drain_value('{\"drain\":true}')\n");
            tests_failed++;
        }
    }
    
    // Test 8: parse_json_drain_value with false
    {
        const char *json = "{\"drain\":false}";
        ngx_int_t result = parse_json_drain_value(json, strlen(json));
        if (result == NGX_OK) {
            printf("✓ Test 8 passed: parse_json_drain_value('{\"drain\":false}')\n");
            tests_passed++;
        } else {
            printf("✗ Test 8 failed: parse_json_drain_value('{\"drain\":false}')\n");
            tests_failed++;
        }
    }
    
    // Test 9: parse_json_drain_value with invalid JSON
    {
        const char *json = "{\"other\":true}";
        ngx_int_t result = parse_json_drain_value(json, strlen(json));
        if (result == NGX_ERROR) {
            printf("✓ Test 9 passed: parse_json_drain_value('{\"other\":true}')\n");
            tests_passed++;
        } else {
            printf("✗ Test 9 failed: parse_json_drain_value('{\"other\":true}')\n");
            tests_failed++;
        }
    }
    
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests: %d\n", tests_passed + tests_failed);
    
    return tests_failed == 0 ? 0 : 1;
}

int main(void) {
    return run_tests();
}