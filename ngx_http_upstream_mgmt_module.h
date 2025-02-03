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

extern ngx_module_t ngx_http_upstream_mgmt_module;

#endif /* _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_ */