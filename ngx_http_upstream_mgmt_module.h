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
    ngx_str_t   upstream;
    ngx_str_t   server;
    ngx_str_t   state;
    ngx_uint_t  server_id;  // Added this line
} ngx_http_upstream_mgmt_request_t;

typedef struct {
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                        name;
    ngx_int_t                        weight;
    ngx_uint_t                       max_conns;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;
    unsigned                         down:1;
    unsigned                         backup:1;
    unsigned                         draining:1;  /* Add draining flag */
} ngx_http_upstream_server_t;

/* Add peer data structure */
typedef struct {
    ngx_http_upstream_rr_peer_t     *peer;
    ngx_http_upstream_rr_peer_t     *current;
    ngx_http_upstream_rr_peers_t    *peers;
    ngx_uint_t                       tries;
    ngx_event_get_peer_pt           original_get_peer;
} ngx_http_upstream_rr_peer_data_t;

extern ngx_module_t ngx_http_upstream_mgmt_module;

#endif /* _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_ */