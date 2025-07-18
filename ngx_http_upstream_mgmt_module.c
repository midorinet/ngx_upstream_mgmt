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

// Constants for common responses - optimization to avoid repeated string operations
static const ngx_str_t ngx_http_upstream_mgmt_success_response = 
    ngx_string("{\"status\":\"success\"}");
static const ngx_str_t ngx_http_upstream_mgmt_error_invalid_uri = 
    ngx_string("{\"error\":\"Invalid URI format\"}");
static const ngx_str_t ngx_http_upstream_mgmt_error_invalid_body = 
    ngx_string("{\"error\":\"Invalid request body\"}");
static const ngx_str_t ngx_http_upstream_mgmt_error_upstream_not_found = 
    ngx_string("{\"error\":\"Upstream not found\"}");
static const ngx_str_t ngx_http_upstream_mgmt_error_servers_not_found = 
    ngx_string("{\"error\":\"Upstream servers not found\"}");
static const ngx_str_t ngx_http_upstream_mgmt_error_invalid_server_id = 
    ngx_string("{\"error\":\"Invalid server ID\"}");
static const ngx_str_t ngx_http_upstream_mgmt_error_cannot_drain_last = 
    ngx_string("{\"error\":\"Cannot drain last available server\"}");

static void
ngx_http_upstream_mgmt_update_peer_status(ngx_http_upstream_server_t *server, 
                                         ngx_str_t *state,
                                         ngx_http_upstream_rr_peers_t *peers,
                                         ngx_uint_t server_id) 
{
    ngx_http_upstream_rr_peer_t *peer;
    ngx_uint_t i;
    ngx_flag_t new_down_state;

    // Determine new state once
    if (state->len == 2 && ngx_strncmp(state->data, "up", 2) == 0) {
        new_down_state = 0;
    } else if (state->len == 5 && ngx_strncmp(state->data, "drain", 5) == 0) {
        new_down_state = 1;
    } else {
        return; // Invalid state, no change
    }

    // Update server configuration state
    server->down = new_down_state;
    
    // Update runtime peer state if peers exist
    if (peers != NULL) {
        peer = peers->peer;
        for (i = 0; peer && i <= server_id; i++, peer = peer->next) {
            if (i == server_id) {
                peer->down = new_down_state;
                break;
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
    ngx_flag_t is_down;
    ngx_http_upstream_rr_peers_t *peers;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;

    // Find the upstream and calculate buffer size
    len = 12;  // {"servers":[]}
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == upstream_name->len &&
            ngx_strncmp(uscfp[i]->host.data, upstream_name->data, upstream_name->len) == 0) {
            found = 1;
            if (uscfp[i]->servers) {
                servers = uscfp[i]->servers->elts;
                for (j = 0; j < uscfp[i]->servers->nelts; j++) {
                    if (j > 0) len++;  // comma separator
                    len += 150 + servers[j].name.len;  // JSON object + server name
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
        peers = uscfp[i]->peer.data;
        
        for (j = 0; j < uscfp[i]->servers->nelts; j++) {
            if (j > 0) {
                *p++ = ',';
            }
            
            is_down = ngx_http_upstream_mgmt_get_server_state(&servers[j], peers, j);
            ngx_http_upstream_mgmt_write_server_json(&p, &servers[j], j, is_down);
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

// Helper function to calculate buffer size needed for JSON response - optimized
static size_t
ngx_http_upstream_mgmt_calculate_buffer_size(ngx_http_upstream_main_conf_t *umcf)
{
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_http_upstream_server_t *servers;
    size_t len = 2;  // {}
    ngx_uint_t i, j;
    static const size_t base_server_json_size = 150; // Estimated size for server JSON object
    
    uscfp = umcf->upstreams.elts;
    
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (i > 0) len++;  // comma separator
        len += 3 + uscfp[i]->host.len + 12;  // "name":{"servers":[
        
        if (uscfp[i]->servers) {
            servers = uscfp[i]->servers->elts;
            ngx_uint_t server_count = uscfp[i]->servers->nelts;
            
            // Add comma separators for servers (server_count - 1)
            if (server_count > 1) {
                len += server_count - 1;
            }
            
            // Calculate total size for all servers
            for (j = 0; j < server_count; j++) {
                len += base_server_json_size + servers[j].name.len;
            }
        }
        len += 2;  // ]}
    }
    
    // Add 10% buffer for safety
    return len + (len / 10);
}

// Helper function to write server JSON - reduces code duplication
static ngx_int_t
ngx_http_upstream_mgmt_write_server_json(u_char **p, ngx_http_upstream_server_t *server,
                                        ngx_uint_t server_id, ngx_flag_t is_down)
{
    *p = ngx_sprintf(*p, 
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
        server_id,
        &server->name,
        server->weight,
        server->max_conns,
        server->max_fails,
        server->fail_timeout,
        server->slow_start,
        server->backup ? "true" : "false",
        is_down ? "true" : "false"
    );
    
    return NGX_OK;
}

// Helper function to get server runtime state
static ngx_flag_t
ngx_http_upstream_mgmt_get_server_state(ngx_http_upstream_server_t *server,
                                       ngx_http_upstream_rr_peers_t *peers,
                                       ngx_uint_t server_index)
{
    ngx_http_upstream_rr_peer_t *peer;
    ngx_uint_t k;
    ngx_flag_t is_down = server->down;  // Start with config state
    
    if (peers != NULL) {
        peer = peers->peer;
        for (k = 0; peer && k < server_index; k++) {
            peer = peer->next;
        }
        
        if (peer) {
            is_down = peer->down || peer->fails >= peer->max_fails;
        }
    }
    
    return is_down;
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
    ngx_flag_t is_down;
    ngx_http_upstream_rr_peers_t *peers;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscfp = umcf->upstreams.elts;
    len = ngx_http_upstream_mgmt_calculate_buffer_size(umcf);

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
            peers = uscfp[i]->peer.data;
            
            for (j = 0; j < uscfp[i]->servers->nelts; j++) {
                if (j > 0) {
                    *p++ = ',';
                }
                
                is_down = ngx_http_upstream_mgmt_get_server_state(&servers[j], peers, j);
                ngx_http_upstream_mgmt_write_server_json(&p, &servers[j], j, is_down);
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

// Helper function to parse URI and extract upstream/server info - optimized
static ngx_int_t
ngx_http_upstream_mgmt_parse_uri(ngx_http_request_t *r, ngx_http_upstream_mgmt_request_t *req)
{
    u_char *uri = r->uri.data;
    size_t uri_len = r->uri.len;
    static const char prefix[] = "/api/upstreams/";
    static const char servers_path[] = "/servers/";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t servers_len = sizeof(servers_path) - 1;
    
    // Check minimum URI length and prefix
    if (uri_len < prefix_len || ngx_strncmp(uri, prefix, prefix_len) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "URI does not start with '/api/upstreams/'");
        return NGX_ERROR;
    }
    
    u_char *upstream_start = uri + prefix_len;
    u_char *uri_end = uri + uri_len;
    u_char *server_start = ngx_strlchr(upstream_start, uri_end, '/');
    
    if (!server_start || (uri_end - server_start) < servers_len ||
        ngx_strncmp(server_start, servers_path, servers_len) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid URI format, missing '/servers/'");
        return NGX_ERROR;
    }
    
    req->upstream.data = upstream_start;
    req->upstream.len = server_start - upstream_start;
    
    server_start += servers_len;
    u_char *server_id_end = server_start;
    
    // Find end of server ID (digits only)
    while (server_id_end < uri_end && *server_id_end >= '0' && *server_id_end <= '9') {
        server_id_end++;
    }
    
    if (server_id_end == server_start) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Server ID not found in URI");
        return NGX_ERROR;
    }
    
    req->server_id = ngx_atoi(server_start, server_id_end - server_start);
    if (req->server_id == (ngx_uint_t)NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid server ID in URI");
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

// Helper function to parse JSON request body - optimized
static ngx_int_t
ngx_http_upstream_mgmt_parse_body(ngx_http_request_t *r, ngx_http_upstream_mgmt_request_t *req)
{
    ngx_str_t request_body = ngx_null_string;
    static const char drain_true[] = "\"drain\":true";
    static const char drain_false[] = "\"drain\":false";
    
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Request body is empty");
        return NGX_ERROR;
    }
    
    // Handle multi-buffer request body
    if (r->request_body->bufs->next) {
        size_t body_len = 0;
        ngx_chain_t *cl;
        
        // Calculate total body length
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            body_len += ngx_buf_size(cl->buf);
        }
        
        if (body_len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Request body is empty");
            return NGX_ERROR;
        }
        
        u_char *p = ngx_pnalloc(r->pool, body_len + 1);  // +1 for null terminator
        if (p == NULL) {
            return NGX_ERROR;
        }
        
        request_body.data = p;
        request_body.len = body_len;
        
        // Copy all buffers
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            size_t buf_size = ngx_buf_size(cl->buf);
            p = ngx_copy(p, cl->buf->pos, buf_size);
        }
        *p = '\0';  // Null terminate for string operations
    } else {
        request_body.data = r->request_body->bufs->buf->pos;
        request_body.len = ngx_buf_size(r->request_body->bufs->buf);
    }
    
    // Parse JSON for drain state - optimized search
    if (ngx_strnstr(request_body.data, drain_true, request_body.len)) {
        req->state.data = (u_char *) "drain";
        req->state.len = 5;
    } else if (ngx_strnstr(request_body.data, drain_false, request_body.len)) {
        req->state.data = (u_char *) "up";
        req->state.len = 2;
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid JSON body format");
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

// Pre-defined response strings for better performance
static ngx_str_t ngx_http_upstream_mgmt_success_response = ngx_string("{\"status\":\"success\"}");
static ngx_str_t ngx_http_upstream_mgmt_error_invalid_uri = ngx_string("{\"error\":\"Invalid URI format\"}");
static ngx_str_t ngx_http_upstream_mgmt_error_invalid_body = ngx_string("{\"error\":\"Invalid request body\"}");
static ngx_str_t ngx_http_upstream_mgmt_error_upstream_not_found = ngx_string("{\"error\":\"Upstream not found\"}");
static ngx_str_t ngx_http_upstream_mgmt_error_servers_not_found = ngx_string("{\"error\":\"Upstream servers not found\"}");
static ngx_str_t ngx_http_upstream_mgmt_error_invalid_server_id = ngx_string("{\"error\":\"Invalid server ID\"}");
static ngx_str_t ngx_http_upstream_mgmt_error_cannot_drain_last = ngx_string("{\"error\":\"Cannot drain last available server\"}");

// Helper function to send JSON response - optimized with pre-allocated responses
static ngx_int_t
ngx_http_upstream_mgmt_send_response(ngx_http_request_t *r, ngx_str_t *response, ngx_uint_t status)
{
    ngx_buf_t *b;
    ngx_chain_t out;
    
    b = ngx_create_temp_buf(r->pool, response->len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->pos = response->data;
    b->last = response->data + response->len;
    b->last_buf = 1;
    b->last_in_chain = 1;
    
    out.buf = b;
    out.next = NULL;
    
    r->headers_out.status = status ? status : NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_length_n = response->len;
    
    ngx_http_send_header(r);
    return ngx_http_output_filter(r, &out);
}

// Main update function - optimized with better error handling
static ngx_int_t
ngx_http_upstream_mgmt_update(ngx_http_request_t *r)
{
    ngx_http_upstream_mgmt_request_t req;
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t **uscfp, *uscf = NULL;
    ngx_http_upstream_server_t *servers, *server;
    ngx_array_t *srv_array;
    ngx_uint_t i, j, available_servers;
    ngx_str_t response;
    ngx_flag_t is_drain_request;
    
    // Parse URI and body in one go for better error handling
    if (ngx_http_upstream_mgmt_parse_uri(r, &req) != NGX_OK) {
        return ngx_http_upstream_mgmt_send_response(r, &ngx_http_upstream_mgmt_error_invalid_uri, NGX_HTTP_BAD_REQUEST);
    }
    
    if (ngx_http_upstream_mgmt_parse_body(r, &req) != NGX_OK) {
        return ngx_http_upstream_mgmt_send_response(r, &ngx_http_upstream_mgmt_error_invalid_body, NGX_HTTP_BAD_REQUEST);
    }
    
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream_mgmt: parsed upstream=%V, server_id=%ui", &req.upstream, req.server_id);
    
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Upstream module configuration is NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    uscfp = umcf->upstreams.elts;
    is_drain_request = (req.state.len == 5 && ngx_strncmp(req.state.data, "drain", 5) == 0);
    
    // Find the upstream - optimized single loop with early validation
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == req.upstream.len &&
            ngx_strncmp(uscfp[i]->host.data, req.upstream.data, req.upstream.len) == 0) {
            
            uscf = uscfp[i];
            break;
        }
    }
    
    if (uscf == NULL) {
        return ngx_http_upstream_mgmt_send_response(r, &ngx_http_upstream_mgmt_error_upstream_not_found, NGX_HTTP_NOT_FOUND);
    }
    
    srv_array = uscf->servers;
    if (srv_array == NULL) {
        return ngx_http_upstream_mgmt_send_response(r, &ngx_http_upstream_mgmt_error_servers_not_found, NGX_HTTP_NOT_FOUND);
    }
    
    if (req.server_id >= srv_array->nelts) {
        return ngx_http_upstream_mgmt_send_response(r, &ngx_http_upstream_mgmt_error_invalid_server_id, NGX_HTTP_NOT_FOUND);
    }
    
    servers = srv_array->elts;
    server = &servers[req.server_id];
    
    // Only count available servers if we're trying to drain
    if (is_drain_request && !server->down) {
        available_servers = 0;
        for (j = 0; j < srv_array->nelts; j++) {
            if (!servers[j].down && !servers[j].backup) {
                available_servers++;
            }
        }
        
        // Prevent draining the last available server
        if (available_servers <= 1) {
            return ngx_http_upstream_mgmt_send_response(r, &ngx_http_upstream_mgmt_error_cannot_drain_last, NGX_HTTP_BAD_REQUEST);
        }
    }
    
    // Update server state
    ngx_http_upstream_rr_peers_t *peers = uscf->peer.data;
    ngx_http_upstream_mgmt_update_peer_status(server, &req.state, peers, req.server_id);
    
    return ngx_http_upstream_mgmt_send_response(r, &ngx_http_upstream_mgmt_success_response, NGX_HTTP_OK);
}