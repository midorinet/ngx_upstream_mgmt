#include <stdio.h>
#include <stdlib.h>
#include <check.h>

// Mock the nginx includes and structures
typedef struct {
    size_t len;
    char* data;
} ngx_str_t;

typedef int ngx_int_t;
#define NGX_OK 0
#define NGX_ERROR -1

// Function declarations that would normally come from your module
ngx_int_t parse_upstream_state(ngx_str_t *state);

// Test implementations
ngx_int_t parse_upstream_state(ngx_str_t *state) {
    if (state == NULL || state->data == NULL) {
        return NGX_ERROR;
    }
    
    if (strcmp(state->data, "up") == 0) {
        return NGX_OK;
    }
    
    return NGX_ERROR;
}

// Test cases
START_TEST(test_parse_upstream_state)
{
    ngx_str_t input = { 2, "up" };
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

// Test suite
Suite *upstream_mgmt_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Upstream Management");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_parse_upstream_state);
    tcase_add_test(tc_core, test_parse_invalid_upstream_state);
    tcase_add_test(tc_core, test_parse_null_state);
    suite_add_tcase(s, tc_core);

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