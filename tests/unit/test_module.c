#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

// Mock the nginx includes and structures
typedef struct {
    size_t len;
    char* data;
} ngx_str_t;

typedef int ngx_int_t;
typedef unsigned int ngx_uint_t;
#define NGX_OK 0
#define NGX_ERROR -1

// Function declarations that would normally come from your module
ngx_int_t parse_upstream_state(ngx_str_t *state);
ngx_int_t validate_server_id(ngx_uint_t server_id, ngx_uint_t max_servers);
ngx_int_t parse_json_drain_value(const char *json, size_t len);

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

// Test cases
START_TEST(test_parse_upstream_state_up)
{
    ngx_str_t input = { 2, "up" };
    ngx_int_t result = parse_upstream_state(&input);
    ck_assert_int_eq(result, NGX_OK);
}
END_TEST

START_TEST(test_parse_upstream_state_drain)
{
    ngx_str_t input = { 5, "drain" };
    ngx_int_t result = parse_upstream_state(&input);
    ck_assert_int_eq(result, NGX_OK);
}
END_TEST

START_TEST(test_parse_invalid_upstream_state)
{
    ngx_str_t input = { 7, "invalid" };
    ngx_int_t result = parse_upstream_state(&input);
    ck_assert_int_eq(result, NGX_ERROR);
}
END_TEST

START_TEST(test_parse_null_state)
{
    ngx_int_t result = parse_upstream_state(NULL);
    ck_assert_int_eq(result, NGX_ERROR);
}
END_TEST

START_TEST(test_validate_server_id_valid)
{
    ngx_int_t result = validate_server_id(0, 5);
    ck_assert_int_eq(result, NGX_OK);
    
    result = validate_server_id(4, 5);
    ck_assert_int_eq(result, NGX_OK);
}
END_TEST

START_TEST(test_validate_server_id_invalid)
{
    ngx_int_t result = validate_server_id(5, 5);
    ck_assert_int_eq(result, NGX_ERROR);
    
    result = validate_server_id(10, 5);
    ck_assert_int_eq(result, NGX_ERROR);
}
END_TEST

START_TEST(test_parse_json_drain_true)
{
    const char *json = "{\"drain\":true}";
    ngx_int_t result = parse_json_drain_value(json, strlen(json));
    ck_assert_int_eq(result, NGX_OK);
}
END_TEST

START_TEST(test_parse_json_drain_false)
{
    const char *json = "{\"drain\":false}";
    ngx_int_t result = parse_json_drain_value(json, strlen(json));
    ck_assert_int_eq(result, NGX_OK);
}
END_TEST

START_TEST(test_parse_json_invalid)
{
    const char *json = "{\"drain\":\"invalid\"}";
    ngx_int_t result = parse_json_drain_value(json, strlen(json));
    ck_assert_int_eq(result, NGX_ERROR);
}
END_TEST

START_TEST(test_parse_json_missing_drain)
{
    const char *json = "{\"other\":true}";
    ngx_int_t result = parse_json_drain_value(json, strlen(json));
    ck_assert_int_eq(result, NGX_ERROR);
}
END_TEST

// Test suite
Suite *upstream_mgmt_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_validation, *tc_json;

    s = suite_create("Upstream Management");
    
    // Core parsing tests
    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_parse_upstream_state_up);
    tcase_add_test(tc_core, test_parse_upstream_state_drain);
    tcase_add_test(tc_core, test_parse_invalid_upstream_state);
    tcase_add_test(tc_core, test_parse_null_state);
    suite_add_tcase(s, tc_core);
    
    // Validation tests
    tc_validation = tcase_create("Validation");
    tcase_add_test(tc_validation, test_validate_server_id_valid);
    tcase_add_test(tc_validation, test_validate_server_id_invalid);
    suite_add_tcase(s, tc_validation);
    
    // JSON parsing tests
    tc_json = tcase_create("JSON");
    tcase_add_test(tc_json, test_parse_json_drain_true);
    tcase_add_test(tc_json, test_parse_json_drain_false);
    tcase_add_test(tc_json, test_parse_json_invalid);
    tcase_add_test(tc_json, test_parse_json_missing_drain);
    suite_add_tcase(s, tc_json);

    return s;
}

int main(void)
{
    int failed;
    Suite *s;
    SRunner *sr;

    s = upstream_mgmt_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}