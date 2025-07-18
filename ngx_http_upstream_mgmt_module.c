/*
 * This module is an open-source project developed independently.
 * It is not affiliated with, endorsed by, or associated with NGINX or F5, Inc.
 */
#include "ngx_http_upstream_mgmt_module.h"
#include <ngx_http_upstream_round_robin.h>

#if (NGX_HTTP_UPSTREAM_CHECK)
#include <ngx_http_upstream_check_module.h>
#endif

/* Constants */
#define NGX_HTTP_UPSTREAM_MGMT_MAX_JSON_SIZE  (64 * 1024)
#define NGX_HTTP_UPSTREAM_MGMT_SERVER_JSON_SIZE  256

/* Forward declarations */
static ngx_int_t ngx_http_upstream_mgmt_handler(ngx_http_request_t *r);
static void ngx_http_upstream_mgmt_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_mgmt_update(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_mgmt_list(ngx_http_request_t *r);
static char *ngx_http_upstream_mgmt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_upstream_mgmt_list_single(ngx_http_request_t *r, ngx_str_t *upstream_name);
static ngx_int_t ngx_http_upstream_mgmt_init(ngx_conf_t *cf);

/* Helper functions */
static ngx_http_upstream_srv_conf_t *ngx_http_upstream_mgmt_find_upstream(
    ngx_http_upstream_main_conf_t *umcf, ngx_str_t *name);
static ngx_int_t ngx_http_upstream_mgmt_parse_uri(ngx_http_request_t *r,
    ngx_str_t *upstream_name, ngx_uint_t *server_id);
static ngx_int_t ngx_http_upstream_mgmt_parse_json(ngx_str_t *body, ngx_str_t *state);
static ngx_int_t ngx_http_upstream_mgmt_send_json_response(ngx_http_request_t *r,
    ngx_str_t *json, ngx_uint_t status);
static ngx_int_t ngx_http_upstream_mgmt_validate_drain_request(
    ngx_http_upstream_server_t *servers, ngx_uint_t nservers, 
    ngx_uint_t server_id, ngx_str_t *state);

/* Helper function implementations */
static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_mgmt_get_peer(ngx_http_upstream_rr_peers_t *peers, ngx_uint_t index)
{
    ngx_http_upstream_rr_peer_t *peer;
    ngx_uint_t i;

    if (peers == NULL) {
        return NULL;
    }

    for (peer = peers->peer, i = 0; peer && i < index; peer = peer->next, i++) {
        /* continue */
    }

    return (i == index) ? peer : NULL;
}

static size_t
ngx_http_upstream_mgmt_calc_json_size(ngx_http_upstream_mgmt_ctx_t *ctx)
{
    size_t len = 32; /* Base JSON structure */
    ngx_uint_t i;

    for (i = 0; i < ctx->nservers; i++) {
        len += NGX_HTTP_UPSTREAM_MGMT_SERVER_JSON_SIZE;
        len += ctx->servers[i].name.len;
    }

    return ngx_min(len, NGX_HTTP_UPSTREAM_MGMT_MAX_JSON_SIZE);
}

static u_char *
ngx_http_upstream_mgmt_write_server_json(u_char *p, ngx_http_upstream_server_t *server,
    ngx_uint_t id, ngx_flag_t is_down)
{
    return ngx_sprintf(p,
        "{"
        "\"id\":%ui,"
        "\"server\":\"%V\","
        "\"weight\":%ui,"
        "\"max_conns\":%ui,"
        "\"max_fails\":%ui,"
        "\"fail_timeout\":\"%ui" "s\","
        "\"slow_start\":\"%ui" "s\","
        "\"backup\":%s,"
        "\"down\":%s"
        "}",
        id,
        &server->name,
        server->weight,
        server->max_conns,
        server->max_fails,
        server->fail_timeout,
        server->slow_start,
        server->backup ? "true" : "false",
        is_down ? "true" : "false"
    );
}

static ngx_http_upstream_srv_conf_t *
ngx_http_upstream_mgmt_find_upstream(ngx_http_upstream_main_conf_t *umcf, ngx_str_t *name)
{
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_uint_t i;

    if (umcf == NULL || name == NULL) {
        return NULL;
    }

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == name->len &&
            ngx_strncmp(uscfp[i]->host.data, name->data, name->len) == 0) {
            return uscfp[i];
        }
    }

    return NULL;
}

static ngx_int_t
ngx_http_upstream_mgmt_parse_uri(ngx_http_request_t *r, ngx_str_t *upstream_name, 
    ngx_uint_t *server_id)
{
    u_char *uri = r->uri.data;
    u_char *upstream_start, *server_start, *server_id_end;
    size_t prefix_len = sizeof("/api/upstreams/") - 1;

    if (r->uri.len <= prefix_len) {
        return NGX_ERROR;
    }

    upstream_start = uri + prefix_len;
    server_start = (u_char *)ngx_strstr((char *)upstream_start, "/servers/");
    
    if (server_start == NULL) {
        /* Single upstream request */
        upstream_name->data = upstream_start;
        upstream_name->len = r->uri.len - prefix_len;
        *server_id = NGX_CONF_UNSET_UINT;
        return NGX_OK;
    }

    /* Parse upstream name */
    upstream_name->data = upstream_start;
    upstream_name->len = server_start - upstream_start;

    /* Parse server ID */
    server_start += sizeof("/servers/") - 1;
    server_id_end = server_start;

    while (server_id_end < uri + r->uri.len && 
           *server_id_end >= '0' && *server_id_end <= '9') {
        server_id_end++;
    }

    if (server_id_end == server_start) {
        return NGX_ERROR;
    }

    *server_id = ngx_atoi(server_start, server_id_end - server_start);
    return (*server_id == (ngx_uint_t)NGX_ERROR) ? NGX_ERROR : NGX_OK;
}

static ngx_int_t
ngx_http_upstream_mgmt_parse_json(ngx_str_t *body, ngx_str_t *state)
{
    if (ngx_strnstr(body->data, "\"drain\":true", body->len)) {
        ngx_str_set(state, "drain");
        return NGX_OK;
    } else if (ngx_strnstr(body->data, "\"drain\":false", body->len)) {
        ngx_str_set(state, "up");
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_upstream_mgmt_send_json_response(ngx_http_request_t *r, ngx_str_t *json, 
    ngx_uint_t status)
{
    ngx_buf_t *b;
    ngx_chain_t out;

    b = ngx_create_temp_buf(r->pool, json->len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = json->data;
    b->last = json->data + json->len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_length_n = json->len;

    ngx_http_send_header(r);
    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_upstream_mgmt_validate_drain_request(ngx_http_upstream_server_t *servers,
    ngx_uint_t nservers, ngx_uint_t server_id, ngx_str_t *state)
{
    ngx_uint_t available_servers = 0;
    ngx_uint_t i;

    if (ngx_strncmp(state->data, "drain", 5) != 0 || state->len != 5) {
        return NGX_OK; /* Not a drain request */
    }

    /* Count available non-backup servers */
    for (i = 0; i < nservers; i++) {
        if (!servers[i].down && !servers[i].backup) {
            available_servers++;
        }
    }

    /* Prevent draining the last available server */
    if (available_servers <= 1 && !servers[server_id].down) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_http_upstream_mgmt_update_peer_status(ngx_http_upstream_server_t *server, 
    ngx_str_t *state, ngx_http_upstream_rr_peers_t *peers, ngx_uint_t server_id) 
{
    ngx_http_upstream_rr_peer_t *peer;
    ngx_flag_t is_up = (state->len == 2 && ngx_strncmp(state->data, "up", 2) == 0);

    /* Update server configuration state */
    server->down = is_up ? 0 : 1;

    /* Update runtime peer state */
    peer = ngx_http_upstream_mgmt_get_peer(peers, server_id);
    if (peer != NULL) {
        peer->down = server->down;
    }
}

// Module context
static ngx_http_module_t ngx_http_upstream_mgmt_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_upstream_mgmt_init,        /* postconfiguration */
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    NULL,                               /* create location configuration */
    NULL                               /* merge location configuration */
};

/* Add the initialization function */
static ngx_int_t
ngx_http_upstream_mgmt_init(ngx_conf_t *cf)
{
    ngx_http_upstream_main_conf_t  *umcf;
    
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_command_t ngx_http_upstream_mgmt_commands[] = {
    { 
        ngx_string("upstream_mgmt"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_upstream_mgmt,
        0,
        0,
        NULL 
    },
    ngx_null_command
};
// Module definition
ngx_module_t ngx_http_upstream_mgmt_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_mgmt_module_ctx,    /* module context */
    ngx_http_upstream_mgmt_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

// Handler configuration
static char *
ngx_http_upstream_mgmt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upstream_mgmt_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_upstream_mgmt_build_servers_json(ngx_http_request_t *r,
    ngx_http_upstream_mgmt_ctx_t *ctx, ngx_str_t *json)
{
    ngx_buf_t *b;
    u_char *p;
    size_t len;
    ngx_uint_t i;
    ngx_flag_t is_down;
    ngx_http_upstream_rr_peer_t *peer;

    len = ngx_http_upstream_mgmt_calc_json_size(ctx);
    
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = b->pos;
    p = ngx_sprintf(p, "{\"servers\":[");

    for (i = 0; i < ctx->nservers; i++) {
        if (i > 0) {
            *p++ = ',';
        }

        /* Determine server state */
        is_down = ctx->servers[i].down;
        peer = ngx_http_upstream_mgmt_get_peer(ctx->peers, i);
        if (peer != NULL) {
            is_down = peer->down || (peer->fails >= peer->max_fails);
        }

        p = ngx_http_upstream_mgmt_write_server_json(p, &ctx->servers[i], i, is_down);
    }

    p = ngx_sprintf(p, "]}");
    
    json->data = b->pos;
    json->len = p - b->pos;
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_mgmt_list_single(ngx_http_request_t *r, ngx_str_t *upstream_name)
{
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t *uscf;
    ngx_http_upstream_mgmt_ctx_t ctx;
    ngx_str_t json;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscf = ngx_http_upstream_mgmt_find_upstream(umcf, upstream_name);
    if (uscf == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* Initialize context */
    ctx.uscf = uscf;
    ctx.servers = uscf->servers ? uscf->servers->elts : NULL;
    ctx.peers = uscf->peer.data;
    ctx.nservers = uscf->servers ? uscf->servers->nelts : 0;

    if (ngx_http_upstream_mgmt_build_servers_json(r, &ctx, &json) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_upstream_mgmt_send_json_response(r, &json, NGX_HTTP_OK);
}

/* Main request handler */
static ngx_int_t
ngx_http_upstream_mgmt_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_str_t upstream_name;
    ngx_uint_t server_id;
    size_t prefix_len = sizeof("/api/upstreams/") - 1;

    if (r->method == NGX_HTTP_GET) {
        if (r->uri.len == prefix_len - 1) {
            /* List all upstreams */
            return ngx_http_upstream_mgmt_list(r);
        } else if (r->uri.len > prefix_len) {
            rc = ngx_http_upstream_mgmt_parse_uri(r, &upstream_name, &server_id);
            if (rc != NGX_OK) {
                return NGX_HTTP_BAD_REQUEST;
            }
            
            if (server_id != NGX_CONF_UNSET_UINT) {
                /* Server-specific request not supported for GET */
                return NGX_HTTP_NOT_ALLOWED;
            }
            
            return ngx_http_upstream_mgmt_list_single(r, &upstream_name);
        }
    } else if (r->method == NGX_HTTP_PATCH) {
        r->request_body_in_single_buf = 1;
        r->request_body_file_log_level = 0;

        rc = ngx_http_read_client_request_body(r, ngx_http_upstream_mgmt_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }

    return NGX_HTTP_NOT_ALLOWED;
}

static ngx_int_t
ngx_http_upstream_mgmt_list(ngx_http_request_t *r)
{
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_http_upstream_mgmt_ctx_t ctx;
    ngx_buf_t *b;
    u_char *p;
    size_t total_len = 32; /* Base JSON structure */
    ngx_uint_t i, j;
    ngx_flag_t is_down;
    ngx_http_upstream_rr_peer_t *peer;
    ngx_str_t json;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    /* Calculate total buffer size needed */
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        total_len += uscfp[i]->host.len + 32; /* Upstream name + structure */
        if (uscfp[i]->servers) {
            total_len += uscfp[i]->servers->nelts * NGX_HTTP_UPSTREAM_MGMT_SERVER_JSON_SIZE;
            ngx_http_upstream_server_t *servers = uscfp[i]->servers->elts;
            for (j = 0; j < uscfp[i]->servers->nelts; j++) {
                total_len += servers[j].name.len;
            }
        }
    }

    total_len = ngx_min(total_len, NGX_HTTP_UPSTREAM_MGMT_MAX_JSON_SIZE);

    b = ngx_create_temp_buf(r->pool, total_len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->pos;
    *p++ = '{';
    
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (i > 0) {
            *p++ = ',';
        }
        p = ngx_sprintf(p, "\"%V\":{\"servers\":[", &uscfp[i]->host);

        if (uscfp[i]->servers) {
            ctx.uscf = uscfp[i];
            ctx.servers = uscfp[i]->servers->elts;
            ctx.peers = uscfp[i]->peer.data;
            ctx.nservers = uscfp[i]->servers->nelts;
            
            for (j = 0; j < ctx.nservers; j++) {
                if (j > 0) {
                    *p++ = ',';
                }
                
                /* Determine server state */
                is_down = ctx.servers[j].down;
                peer = ngx_http_upstream_mgmt_get_peer(ctx.peers, j);
                if (peer != NULL) {
                    is_down = peer->down || (peer->fails >= peer->max_fails);
                }
                
                p = ngx_http_upstream_mgmt_write_server_json(p, &ctx.servers[j], j, is_down);
            }
        }

        p = ngx_sprintf(p, "]}");
    }
    
    *p++ = '}';
    
    json.data = b->pos;
    json.len = p - b->pos;

    return ngx_http_upstream_mgmt_send_json_response(r, &json, NGX_HTTP_OK);
}
/* Request body handler */
static void
ngx_http_upstream_mgmt_body_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    
    rc = ngx_http_upstream_mgmt_update(r);
    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_upstream_mgmt_read_request_body(ngx_http_request_t *r, ngx_str_t *body)
{
    ngx_chain_t *cl;
    size_t body_len = 0;
    u_char *p;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_ERROR;
    }

    if (r->request_body->bufs->next == NULL) {
        /* Single buffer */
        body->data = r->request_body->bufs->buf->pos;
        body->len = ngx_buf_size(r->request_body->bufs->buf);
        return NGX_OK;
    }

    /* Multiple buffers - need to concatenate */
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        body_len += ngx_buf_size(cl->buf);
    }
    
    p = ngx_pnalloc(r->pool, body_len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    
    body->data = p;
    body->len = body_len;
    
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        p = ngx_copy(p, cl->buf->pos, ngx_buf_size(cl->buf));
    }

    return NGX_OK;
}

/* Main update function */
static ngx_int_t
ngx_http_upstream_mgmt_update(ngx_http_request_t *r)
{
    ngx_http_upstream_mgmt_request_t req;
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t *uscf;
    ngx_http_upstream_server_t *servers, *server;
    ngx_str_t request_body, response;
    ngx_int_t rc;

    /* Parse URI to extract upstream name and server ID */
    rc = ngx_http_upstream_mgmt_parse_uri(r, &req.upstream, &req.server_id);
    if (rc != NGX_OK || req.server_id == NGX_CONF_UNSET_UINT) {
        ngx_str_set(&response, "{\"error\":\"Invalid URI format\"}");
        return ngx_http_upstream_mgmt_send_json_response(r, &response, NGX_HTTP_BAD_REQUEST);
    }

    /* Read and parse request body */
    if (ngx_http_upstream_mgmt_read_request_body(r, &request_body) != NGX_OK) {
        ngx_str_set(&response, "{\"error\":\"Empty request body\"}");
        return ngx_http_upstream_mgmt_send_json_response(r, &response, NGX_HTTP_BAD_REQUEST);
    }

    if (ngx_http_upstream_mgmt_parse_json(&request_body, &req.state) != NGX_OK) {
        ngx_str_set(&response, "{\"error\":\"Invalid drain value\"}");
        return ngx_http_upstream_mgmt_send_json_response(r, &response, NGX_HTTP_BAD_REQUEST);
    }

    /* Get upstream configuration */
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscf = ngx_http_upstream_mgmt_find_upstream(umcf, &req.upstream);
    if (uscf == NULL) {
        ngx_str_set(&response, "{\"error\":\"Upstream not found\"}");
        return ngx_http_upstream_mgmt_send_json_response(r, &response, NGX_HTTP_NOT_FOUND);
    }

    if (uscf->servers == NULL) {
        ngx_str_set(&response, "{\"error\":\"Upstream servers not found\"}");
        return ngx_http_upstream_mgmt_send_json_response(r, &response, NGX_HTTP_NOT_FOUND);
    }

    if (req.server_id >= uscf->servers->nelts) {
        ngx_str_set(&response, "{\"error\":\"Invalid server ID\"}");
        return ngx_http_upstream_mgmt_send_json_response(r, &response, NGX_HTTP_NOT_FOUND);
    }

    servers = uscf->servers->elts;
    server = &servers[req.server_id];

    /* Validate drain request */
    if (ngx_http_upstream_mgmt_validate_drain_request(servers, uscf->servers->nelts,
                                                     req.server_id, &req.state) != NGX_OK) {
        ngx_str_set(&response, "{\"error\":\"Cannot drain last available server\"}");
        return ngx_http_upstream_mgmt_send_json_response(r, &response, NGX_HTTP_BAD_REQUEST);
    }

    /* Update server state */
    ngx_http_upstream_mgmt_update_peer_status(server, &req.state, uscf->peer.data, req.server_id);

    ngx_str_set(&response, "{\"status\":\"success\"}");
    return ngx_http_upstream_mgmt_send_json_response(r, &response, NGX_HTTP_OK);
}