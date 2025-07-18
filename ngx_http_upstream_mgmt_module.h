#ifndef _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Performance macros */
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define ngx_likely(x)   __builtin_expect(!!(x), 1)
#define ngx_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define ngx_likely(x)   (x)
#define ngx_unlikely(x) (x)
#endif

/* Security Constants */
#define NGX_HTTP_UPSTREAM_MGMT_MAX_JSON_SIZE     (64 * 1024)
#define NGX_HTTP_UPSTREAM_MGMT_SERVER_JSON_SIZE  256
#define NGX_HTTP_UPSTREAM_MGMT_MAX_UPSTREAM_NAME 256
#define NGX_HTTP_UPSTREAM_MGMT_MAX_SERVER_NAME   1024
#define NGX_HTTP_UPSTREAM_MGMT_SAFETY_MARGIN     512

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

typedef struct {
    ngx_http_upstream_srv_conf_t  *uscf;
    ngx_http_upstream_server_t    *servers;
    ngx_http_upstream_rr_peers_t  *peers;
    ngx_uint_t                     nservers;
} ngx_http_upstream_mgmt_ctx_t;

typedef struct ngx_http_upstream_rr_peer_s ngx_http_upstream_rr_peer_t;

/* Function prototypes */
static ngx_http_upstream_rr_peer_t *ngx_http_upstream_mgmt_get_peer(
    ngx_http_upstream_rr_peers_t *peers, ngx_uint_t index);
static size_t ngx_http_upstream_mgmt_calc_json_size(
    ngx_http_upstream_mgmt_ctx_t *ctx);
static ngx_int_t ngx_http_upstream_mgmt_write_server_json_safe(u_char **p, u_char *end,
    ngx_http_upstream_server_t *server, ngx_uint_t id, ngx_flag_t is_down);

/* Security validation functions */
static ngx_int_t ngx_http_upstream_mgmt_validate_input(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_mgmt_sanitize_string(ngx_str_t *str, size_t max_len);

extern ngx_module_t ngx_http_upstream_mgmt_module;

#endif /* _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_ */