#ifndef _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t  enable;
} ngx_http_upstream_mgmt_loc_conf_t;

typedef struct {
    ngx_shm_zone_t  *shm_zone;
} ngx_http_upstream_mgmt_main_conf_t;

typedef struct {
    ngx_rbtree_t         rbtree;
    ngx_rbtree_node_t    sentinel;
    ngx_atomic_t         lock;
} ngx_http_upstream_mgmt_shm_t;

typedef struct {
    ngx_str_t  upstream;
    ngx_uint_t server_id;
    ngx_str_t  state;
} ngx_http_upstream_mgmt_request_t;

typedef struct ngx_http_upstream_rr_peer_s ngx_http_upstream_rr_peer_t;

// Function declarations
static ngx_int_t ngx_http_upstream_mgmt_parse_uri(ngx_http_request_t *r, ngx_http_upstream_mgmt_request_t *req);
static ngx_int_t ngx_http_upstream_mgmt_parse_body(ngx_http_request_t *r, ngx_http_upstream_mgmt_request_t *req);
static ngx_int_t ngx_http_upstream_mgmt_send_response(ngx_http_request_t *r, ngx_str_t *response, ngx_uint_t status);
static size_t ngx_http_upstream_mgmt_calculate_buffer_size(ngx_http_upstream_main_conf_t *umcf);
static ngx_flag_t ngx_http_upstream_mgmt_get_server_state(ngx_http_upstream_server_t *server,
                                                         ngx_http_upstream_rr_peers_t *peers,
                                                         ngx_uint_t server_index);
static ngx_int_t ngx_http_upstream_mgmt_write_server_json(u_char **p, ngx_http_upstream_server_t *server,
                                                         ngx_uint_t server_id, ngx_flag_t is_down);

extern ngx_module_t ngx_http_upstream_mgmt_module;

#endif /* _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_ */