/*
 * This module is an open-source project developed independently.
 * It is not affiliated with, endorsed by, or associated with NGINX or F5, Inc.
 */
#include "ngx_http_upstream_mgmt_module.h"
#include <ngx_http_upstream_round_robin.h>

#if (NGX_HTTP_UPSTREAM_CHECK)
#include <ngx_http_upstream_check_module.h>
#endif

// Forward declarations
static ngx_int_t ngx_http_upstream_mgmt_handler(ngx_http_request_t *r);
static void ngx_http_upstream_mgmt_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_mgmt_update(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_mgmt_list(ngx_http_request_t *r);
static char *ngx_http_upstream_mgmt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_upstream_mgmt_list_single(ngx_http_request_t *r, ngx_str_t *upstream_name);
static ngx_int_t ngx_http_upstream_mgmt_init(ngx_conf_t *cf);

static void
ngx_http_upstream_mgmt_update_peer_status(ngx_http_upstream_server_t *server, 
                                         ngx_str_t *state,
                                         ngx_http_upstream_rr_peers_t *peers,
                                         ngx_uint_t server_id) 
{
    ngx_http_upstream_rr_peer_t *peer;

    if (peers == NULL || peers->peer == NULL) {
        return;
    }

    peer = &peers->peer[server_id];

    if (state->len == 2 && ngx_strncmp(state->data, "up", 2) == 0) {
        server->down = 0;
        peer->down = 0;
    } else if (state->len == 5 && ngx_strncmp(state->data, "drain", 5) == 0) {
        server->down = 1;
        peer->down = 1;
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
ngx_http_upstream_mgmt_list_single(ngx_http_request_t *r, ngx_str_t *upstream_name)
{
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t *uscf = NULL, **uscfp;
    ngx_http_upstream_server_t *server;
    ngx_uint_t i;
    ngx_flag_t found = 0;
    ngx_http_upstream_rr_peers_t *peers;
    ngx_http_upstream_rr_peer_t *peer;
    ngx_chain_t *out, *cl, **ll;
    ngx_buf_t *b;
    u_char *p;
    size_t len;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == upstream_name->len &&
            ngx_strncmp(uscfp[i]->host.data, upstream_name->data, upstream_name->len) == 0) {
            uscf = uscfp[i];
            found = 1;
            break;
        }
    }

    if (!found) {
        return NGX_HTTP_NOT_FOUND;
    }

    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b = ngx_create_temp_buf(r->pool, sizeof("{\"servers\":["));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->last = ngx_sprintf(b->pos, "{\"servers\":[");
    out->buf = b;
    ll = &out->next;

    if (uscf->servers) {
        server = uscf->servers->elts;
        peers = uscf->peer.data;
        peer = (peers != NULL) ? peers->peer : NULL;
        
        for (i = 0; i < uscf->servers->nelts; i++) {
            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            len = 200 + server[i].name.len; // Estimate buffer size
            b = ngx_create_temp_buf(r->pool, len);
            if (b == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            p = b->pos;
            if (i > 0) {
                *p++ = ',';
            }
            
            ngx_flag_t is_down = server[i].down;
            if (peer) {
                is_down = peer->down || (peer->fails >= peer->max_fails && peer->max_fails > 0);
                peer = peer->next;
            }
            
            p = ngx_sprintf(p,
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
                i,
                &server[i].name,
                server[i].weight,
                server[i].max_conns,
                server[i].max_fails,
                server[i].fail_timeout,
                server[i].slow_start,
                server[i].backup ? "true" : "false",
                is_down ? "true" : "false"
            );
            
            b->last = p;
            cl->buf = b;
            *ll = cl;
            ll = &cl->next;
        }
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b = ngx_create_temp_buf(r->pool, sizeof("]}"));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->last = ngx_sprintf(b->pos, "]}");
    b->last_buf = 1;
    cl->buf = b;
    *ll = cl;
    *ll = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    
    // Calculate content length
    len = 0;
    for (cl = out; cl; cl = cl->next) {
        len += ngx_buf_size(cl->buf);
    }
    r->headers_out.content_length_n = len;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
}

// Main request handler
static ngx_int_t
ngx_http_upstream_mgmt_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_str_t upstream_name;
    u_char *p;
    size_t remaining_len;

    if (r->method == NGX_HTTP_GET) {
        if (ngx_strncmp(r->uri.data, "/api/upstreams", 14) != 0) {
            return NGX_HTTP_NOT_FOUND;
        }

        p = r->uri.data + 14;
        remaining_len = r->uri.len - 14;

        if (remaining_len == 0 || (remaining_len == 1 && *p == '/')) {
            return ngx_http_upstream_mgmt_list(r);
        }

        if (*p != '/') {
            return NGX_HTTP_NOT_FOUND;
        }
        p++;
        remaining_len--;

        if (remaining_len > 0 && p[remaining_len - 1] == '/') {
            remaining_len--;
        }

        if (ngx_strlchr(p, p + remaining_len, '/') != NULL) {
            return NGX_HTTP_NOT_ALLOWED;
        }

        upstream_name.data = p;
        upstream_name.len = remaining_len;
        return ngx_http_upstream_mgmt_list_single(r, &upstream_name);

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
    ngx_http_upstream_server_t *server;
    ngx_uint_t i, j;
    ngx_http_upstream_rr_peers_t *peers;
    ngx_http_upstream_rr_peer_t *peer;
    ngx_chain_t *out, *cl, **ll;
    ngx_buf_t *b;
    u_char *p;
    size_t len;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b = ngx_create_temp_buf(r->pool, 1);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->last = ngx_sprintf(b->pos, "{");
    out->buf = b;
    ll = &out->next;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        
        len = (i > 0 ? 1 : 0) + 1 + uscfp[i]->host.len + 1 + sizeof("{\"servers\":[") - 1;
        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        
        p = b->pos;
        if (i > 0) {
            *p++ = ',';
        }
        p = ngx_sprintf(p, "\"%V\":{\"servers\":[", &uscfp[i]->host);
        b->last = p;
        cl->buf = b;
        *ll = cl;
        ll = &cl->next;

        if (uscfp[i]->servers) {
            server = uscfp[i]->servers->elts;
            peers = uscfp[i]->peer.data;
            peer = (peers != NULL) ? peers->peer : NULL;

            for (j = 0; j < uscfp[i]->servers->nelts; j++) {
                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                
                len = 200 + server[j].name.len;
                b = ngx_create_temp_buf(r->pool, len);
                if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                
                p = b->pos;
                if (j > 0) {
                    *p++ = ',';
                }

                ngx_flag_t is_down = server[j].down;
                if (peer) {
                    is_down = peer->down || (peer->fails >= peer->max_fails && peer->max_fails > 0);
                    peer = peer->next;
                }

                p = ngx_sprintf(p,
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
                    j,
                    &server[j].name,
                    server[j].weight,
                    server[j].max_conns,
                    server[j].max_fails,
                    server[j].fail_timeout,
                    server[j].slow_start,
                    server[j].backup ? "true" : "false",
                    is_down ? "true" : "false"
                );
                
                b->last = p;
                cl->buf = b;
                *ll = cl;
                ll = &cl->next;
            }
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        
        b = ngx_create_temp_buf(r->pool, sizeof("]}"));
        if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        
        b->last = ngx_sprintf(b->pos, "]}");
        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    b = ngx_create_temp_buf(r->pool, 1);
    if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    b->last = ngx_sprintf(b->pos, "}");
    b->last_buf = 1;
    cl->buf = b;
    *ll = cl;
    *ll = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "application/json");

    len = 0;
    for (cl = out; cl; cl = cl->next) {
        len += ngx_buf_size(cl->buf);
    }
    r->headers_out.content_length_n = len;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
}
// Request body handler
static void
ngx_http_upstream_mgmt_body_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    rc = ngx_http_upstream_mgmt_update(r);
    
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    
    ngx_http_finalize_request(r, NGX_DONE);
}

// Main update function
static ngx_int_t
ngx_http_upstream_mgmt_update(ngx_http_request_t *r)
{
    ngx_http_upstream_mgmt_request_t req;
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_http_upstream_server_t *servers, *server;
    ngx_array_t *srv_array;
    ngx_uint_t i;
    ngx_str_t response = ngx_null_string;
    u_char *p;

    ngx_memzero(&req, sizeof(ngx_http_upstream_mgmt_request_t));

    u_char *uri_end = r->uri.data + r->uri.len;
    u_char *upstream_start = ngx_strnstr(r->uri.data, "/api/upstreams/", r->uri.len);

    if (upstream_start == NULL) {
        response.data = (u_char *) "{\"error\":\"Invalid URI format\"}";
        r->headers_out.status = NGX_HTTP_BAD_REQUEST;
        goto send_response;
    }
    upstream_start += sizeof("/api/upstreams/") - 1;

    u_char *server_start = ngx_strnstr(upstream_start, "/servers/", uri_end - upstream_start);

    if (server_start == NULL) {
        response.data = (u_char *) "{\"error\":\"Invalid URI format\"}";
        r->headers_out.status = NGX_HTTP_BAD_REQUEST;
        goto send_response;
    }

    req.upstream.data = upstream_start;
    req.upstream.len = server_start - upstream_start;

    server_start += sizeof("/servers/") - 1;

    req.server_id = ngx_atoi(server_start, uri_end - server_start);
    if (req.server_id == (ngx_uint_t)NGX_ERROR) {
        response.data = (u_char *) "{\"error\":\"Invalid server ID\"}";
        r->headers_out.status = NGX_HTTP_BAD_REQUEST;
        goto send_response;
    }

    // Process request body
    ngx_str_t request_body;
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        response.data = (u_char *) "{\"error\":\"Request body is empty\"}";
        r->headers_out.status = NGX_HTTP_BAD_REQUEST;
        goto send_response;
    }

    if (r->request_body->bufs->next != NULL) {
        ngx_int_t body_len = 0;
        ngx_chain_t *cl;
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            body_len += ngx_buf_size(cl->buf);
        }
        
        p = ngx_pnalloc(r->pool, body_len);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        request_body.data = p;
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, ngx_buf_size(cl->buf));
        }
        request_body.len = body_len;
    } else {
        request_body.data = r->request_body->bufs->buf->pos;
        request_body.len = ngx_buf_size(r->request_body->bufs->buf);
    }

    // Improved JSON parsing
    p = (u_char *) ngx_strnstr(request_body.data, "\"drain\":", request_body.len);
    if (p) {
        p += sizeof("\"drain\":") - 1;
        if (p < request_body.data + request_body.len) {
            if (*p == 't') { // true
                req.state.data = (u_char *) "drain";
                req.state.len = 5;
            } else if (*p == 'f') { // false
                req.state.data = (u_char *) "up";
                req.state.len = 2;
            }
        }
    }

    if (req.state.len == 0) {
        response.data = (u_char *) "{\"error\":\"Invalid drain value\"}";
        r->headers_out.status = NGX_HTTP_BAD_REQUEST;
        goto send_response;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Parsed upstream: %V, server_id: %ui, state: %V", &req.upstream, req.server_id, &req.state);

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upstream module configuration is NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    // Find the upstream
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == req.upstream.len &&
            ngx_strncmp(uscfp[i]->host.data, req.upstream.data, req.upstream.len) == 0) {

            srv_array = uscfp[i]->servers;
            if (srv_array == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Server array is NULL for upstream: %V", &uscfp[i]->host);
                response.data = (u_char *) "{\"error\":\"Upstream servers not found\"}";
                r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto send_response;
            }

            if (req.server_id >= srv_array->nelts) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid server ID: %ui for upstream: %V", req.server_id, &uscfp[i]->host);
                response.data = (u_char *) "{\"error\":\"Invalid server ID\"}";
                r->headers_out.status = NGX_HTTP_NOT_FOUND;
                goto send_response;
            }

            ngx_uint_t available_servers = 0;
            ngx_uint_t j;
            servers = srv_array->elts;
            server = &servers[req.server_id];

            for (j = 0; j < srv_array->nelts; j++) {
                if (!servers[j].down && !servers[j].backup) {
                    available_servers++;
                }
            }

            if (req.state.len == 5 && // "drain"
                ngx_strncmp(req.state.data, "drain", 5) == 0 &&
                available_servers <= 1 && 
                !servers[req.server_id].down) {
                
                response.data = (u_char *) "{\"error\":\"Cannot drain last available server\"}";
                r->headers_out.status = NGX_HTTP_BAD_REQUEST;
                goto send_response;
            }
            
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Server[%ui]: address=%V, down=%d",
                          req.server_id, &server->name, server->down);

            ngx_http_upstream_rr_peers_t *peers = uscfp[i]->peer.data;
            ngx_http_upstream_mgmt_update_peer_status(server, &req.state, peers, req.server_id);

            response.data = (u_char *) "{\"status\":\"success\"}";
            goto send_response;
        }
    }

    // If loop finishes, upstream was not found
    response.data = (u_char *) "{\"error\":\"Upstream not found\"}";
    r->headers_out.status = NGX_HTTP_NOT_FOUND;

send_response:
    if (response.len == 0) {
        response.len = ngx_strlen(response.data);
    }

    if (r->headers_out.status == 0) {
        r->headers_out.status = NGX_HTTP_OK;
    }
    
    r->headers_out.content_length_n = response.len;
    r->headers_out.content_type.len = sizeof("application/json") - 1;
    r->headers_out.content_type.data = (u_char *) "application/json";

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, response.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, response.data, response.len);
    b->last = b->pos + response.len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}