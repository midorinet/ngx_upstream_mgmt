#ifndef _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t  enable;
} ngx_http_upstream_mgmt_loc_conf_t;

typedef struct {
    ngx_str_t  upstream;
    ngx_uint_t server_id;
    ngx_str_t  state;
} ngx_http_upstream_mgmt_request_t;

typedef struct ngx_http_upstream_rr_peer_s ngx_http_upstream_rr_peer_t;

// Function declarations - moved to source file to avoid header dependencies

// Module declaration - defined in source file

#endif /* _NGX_HTTP_UPSTREAM_MGMT_MODULE_H_INCLUDED_ */