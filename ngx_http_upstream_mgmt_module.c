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
    ngx_uint_t i;

    // Update server configuration state
    if (state->len == 2 && ngx_strncmp(state->data, "up", 2) == 0) {
        server->down = 0;
        if (peers != NULL) {
            for (peer = peers->peer, i = 0; peer; peer = peer->next, i++) {
                if (i == server_id) {
                    peer->down = 0;
                    break;
                }
            }
        }
    } else if (state->len == 5 && ngx_strncmp(state->data, "drain", 5) == 0) {
        server->down = 1;
        if (peers != NULL) {
            for (peer = peers->peer, i = 0; peer; peer = peer->next, i++) {
                if (i == server_id) {
                    peer->down = 1;
                    break;
                }
            }
        }
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
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_http_upstream_server_t *servers;
    ngx_chain_t out;
    ngx_buf_t *b;
    size_t len;
    u_char *p;
    ngx_uint_t i, j;
    ngx_flag_t found = 0;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    len = 2;
    len += 10;
    len += 2;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == upstream_name->len &&
            ngx_strncmp(uscfp[i]->host.data, upstream_name->data, upstream_name->len) == 0) {
            found = 1;
            if (uscfp[i]->servers) {
                servers = uscfp[i]->servers->elts;
                for (j = 0; j < uscfp[i]->servers->nelts; j++) {
                    if (j > 0) {
                        len++;  // ,
                    }
                    len += 200;
                    len += servers[j].name.len;
                }
            }
            break;
        }
    }

    if (!found) {
        return NGX_HTTP_NOT_FOUND;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->pos;
    p = ngx_sprintf(p, "{\"servers\":[");

    if (uscfp[i]->servers) {
        servers = uscfp[i]->servers->elts;
        for (j = 0; j < uscfp[i]->servers->nelts; j++) {
            if (j > 0) {
                *p++ = ',';
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
                &servers[j].name,
                servers[j].weight,
                servers[j].max_conns,
                servers[j].max_fails,
                servers[j].fail_timeout,
                servers[j].slow_start,
                servers[j].backup ? "true" : "false",
                servers[j].down ? "true" : "false"
            );
        }
    }

    p = ngx_sprintf(p, "]}");
    
    b->last = p;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_length_n = p - b->pos;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
}

// Main request handler
static ngx_int_t
ngx_http_upstream_mgmt_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_str_t upstream_name;

    if (r->method == NGX_HTTP_GET) {
        u_char *uri = r->uri.data;
        size_t prefix_len = ngx_strlen("/api/upstreams/");
        
        if (r->uri.len == prefix_len - 1) {
            return ngx_http_upstream_mgmt_list(r);
        } else if (r->uri.len > prefix_len) {
            upstream_name.data = uri + prefix_len;
            upstream_name.len = r->uri.len - prefix_len;
            
            u_char *server_part = ngx_strlchr(upstream_name.data, 
                                            upstream_name.data + upstream_name.len, 
                                            '/');
            if (server_part) {
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
    ngx_http_upstream_server_t *servers;
    ngx_chain_t out;
    ngx_buf_t *b;
    size_t len;
    u_char *p;
    ngx_uint_t i, j;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    len = 2;  // {}
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (i > 0) {
            len++;
        }
        len += 3 + uscfp[i]->host.len + 10;
        len += 2;

        if (uscfp[i]->servers) {
            servers = uscfp[i]->servers->elts;
            for (j = 0; j < uscfp[i]->servers->nelts; j++) {
                if (j > 0) {
                    len++;
                }
                len += 200;
                len += servers[j].name.len;
            }
        }
    }

    b = ngx_create_temp_buf(r->pool, len);
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
            servers = uscfp[i]->servers->elts;
            for (j = 0; j < uscfp[i]->servers->nelts; j++) {
                if (j > 0) {
                    *p++ = ',';
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
                    &servers[j].name,
                    servers[j].weight,
                    servers[j].max_conns,
                    servers[j].max_fails,
                    servers[j].fail_timeout,
                    servers[j].slow_start,
                    servers[j].backup ? "true" : "false",
                    servers[j].down ? "true" : "false"
                );
            }
        }

        p = ngx_sprintf(p, "]}");
    }
    
    *p++ = '}';
    b->last = p;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_length_n = p - b->pos;

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
    ngx_http_upstream_server_t *servers = NULL, *server = NULL;
    ngx_array_t *srv_array = NULL;
    ngx_uint_t i;
    ngx_str_t response;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_str_t request_body = ngx_null_string;

    // Extract upstream and server ID from URI
    u_char *uri = r->uri.data;
    u_char *upstream_start = (u_char *)ngx_strstr((char *)uri, "/api/upstreams/");
    if (upstream_start) {
        upstream_start += ngx_strlen("/api/upstreams/");
        u_char *server_start = (u_char *)ngx_strstr((char *)upstream_start, "/servers/");
        if (server_start) {
            req.upstream.data = upstream_start;
            req.upstream.len = server_start - upstream_start;

            server_start += ngx_strlen("/servers/");
            u_char *server_id_end = server_start;

            // Locate numeric server ID
            while (*server_id_end >= '0' && *server_id_end <= '9') {
                server_id_end++;
            }

            if (server_id_end == server_start) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Server ID not found in URI");
                response.data = (u_char *) "{\"error\":\"Invalid server ID\"}";
                response.len = ngx_strlen(response.data);
                goto send_response;
            }

            req.server_id = ngx_atoi(server_start, server_id_end - server_start);
            if (req.server_id == (ngx_uint_t)NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid server ID in URI");
                response.data = (u_char *) "{\"error\":\"Invalid server ID\"}";
                response.len = ngx_strlen(response.data);
                goto send_response;
            }
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid URI format, missing '/servers/'");
            response.data = (u_char *) "{\"error\":\"Invalid URI format\"}";
            response.len = ngx_strlen(response.data);
            goto send_response;
        }
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI does not start with '/api/upstreams/'");
        response.data = (u_char *) "{\"error\":\"Invalid URI format\"}";
        response.len = ngx_strlen(response.data);
        goto send_response;
    }

    // Read request body
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Request body is empty");
        response.data = (u_char *) "{\"error\":\"Empty request body\"}";
        response.len = ngx_strlen(response.data);
        goto send_response;
    }

    if (r->request_body->bufs->next) {
        size_t body_len = 0;
        ngx_chain_t *cl;
        
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            body_len += ngx_buf_size(cl->buf);
        }
        
        u_char *p = ngx_pnalloc(r->pool, body_len);
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

    // Simple JSON parsing
    if (ngx_strnstr(request_body.data, "\"drain\":true", request_body.len)) {
        req.state.data = (u_char *) "drain";
        req.state.len = 5;
    } else if (ngx_strnstr(request_body.data, "\"drain\":false", request_body.len)) {
        req.state.data = (u_char *) "up";
        req.state.len = 2;
    } else {
        response.data = (u_char *) "{\"error\":\"Invalid drain value\"}";
        response.len = ngx_strlen(response.data);
        r->headers_out.status = NGX_HTTP_BAD_REQUEST;  // Add this line
        goto send_response;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Parsed upstream: %V, server_id: %ui", &req.upstream, req.server_id);

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upstream module configuration is NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    // Find the upstream
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Checking upstream: %V", &uscfp[i]->host);
        if (uscfp[i]->host.len == req.upstream.len &&
            ngx_strncmp(uscfp[i]->host.data, req.upstream.data, req.upstream.len) == 0) {

            srv_array = uscfp[i]->servers;
            if (srv_array == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Server array is NULL for upstream: %V", &uscfp[i]->host);
                response.data = (u_char *) "{\"error\":\"Upstream servers not found\"}";
                response.len = ngx_strlen(response.data);
                goto send_response;
            }

            if (req.server_id >= srv_array->nelts) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid server ID: %ui for upstream: %V", req.server_id, &uscfp[i]->host);
                response.data = (u_char *) "{\"error\":\"Invalid server ID\"}";
                response.len = ngx_strlen(response.data);
                r->headers_out.status = NGX_HTTP_NOT_FOUND;
                goto send_response;
            }

            servers = srv_array->elts;
            server = &servers[req.server_id];

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Server[%ui]: address=%V, down=%d",
                          req.server_id, &server->name, server->down);

            // Get peers for this upstream
            ngx_http_upstream_rr_peers_t *peers = uscfp[i]->peer.data;

            // Update server state with peer information
            ngx_http_upstream_mgmt_update_peer_status(server, &req.state, peers, req.server_id);

            response.data = (u_char *) "{\"status\":\"success\"}";
            response.len = ngx_strlen(response.data);
            goto send_response;
        }
    }

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == req.upstream.len &&
            ngx_strncmp(uscfp[i]->host.data, req.upstream.data, req.upstream.len) == 0) {

            srv_array = uscfp[i]->servers;
            if (srv_array == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Server array is NULL for upstream: %V", &uscfp[i]->host);
                response.data = (u_char *) "{\"error\":\"Upstream servers not found\"}";
                response.len = ngx_strlen(response.data);
                goto send_response;
            }

            if (req.server_id >= srv_array->nelts) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid server ID: %ui for upstream: %V", req.server_id, &uscfp[i]->host);
                response.data = (u_char *) "{\"error\":\"Invalid server ID\"}";
                response.len = ngx_strlen(response.data);
                r->headers_out.status = NGX_HTTP_NOT_FOUND;
                goto send_response;
            }

            servers = srv_array->elts;
            server = &servers[req.server_id];

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Server[%ui]: address=%V, down=%d",
                          req.server_id, &server->name, server->down);

            // Get peers for this upstream
            ngx_http_upstream_rr_peers_t *peers = uscfp[i]->peer.data;

            // Update server state with peer information
            ngx_http_upstream_mgmt_update_peer_status(server, &req.state, peers, req.server_id);

            response.data = (u_char *) "{\"status\":\"success\"}";
            response.len = ngx_strlen(response.data);
            goto send_response;
        }
    }

    response.data = (u_char *) "{\"error\":\"Upstream not found\"}";
    response.len = ngx_strlen(response.data);

send_response:
    b = ngx_create_temp_buf(r->pool, response.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = response.data;
    b->last = response.data + response.len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    // Change this part
    if (r->headers_out.status == 0) {  // Only set 200 if no error status was set
        r->headers_out.status = NGX_HTTP_OK;
    }
    
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_length_n = response.len;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
}