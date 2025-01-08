#include <check.h>
#include <stdlib.h>
#include "../../ngx_http_upstream_mgmt_module.h"

// Mock functions to simulate nginx environment
ngx_int_t ngx_http_upstream_zone_lookup_value(ngx_str_t *name) {
    return NGX_OK;
}

// Test cases
START_TEST(test_parse_upstream_state)
{
    ngx_str_t input = ngx_string("up");
    ngx_int_t result = parse_upstream_state(&input);
    ck_assert_int_eq(result, NGX_OK);
}
END_TEST

START_TEST(test_parse_invalid_upstream_state)
{
    ngx_str_t input = ngx_string("invalid");
    ngx_int_t result = parse_upstream_state(&input);
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