/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

#include <stdbool.h>

#include "keys.h"
#include "resource_request.h"

#define DEFAULT_KEY_PATH "/etc/httpd/conf/stream-security-keys.json"

/**
 * =============================================================
 * A struct that defines the configurations for stream security.
 * =============================================================
 * */
typedef struct {
    int         enabled; /* Enable or disable our module. */
    int         debug; /* Enable or disable debug print out of the module. */
    const char  *keyPath; /* The path to the file that holds the keyids and secret keys */
    int         extensionCount;
    char        *extensions[];
} stream_security_config;

/** The configuration for the module. */
static stream_security_config config;
/** The available keys for signing. */
static struct KeyCollection secret_key_collection;

/**
 * =======================================
 * Directive handlers for stream security.
 * =======================================
 * */

/** Handler for enabling or disabling the stream security module. */
const char* stream_security_set_enabled(cmd_parms *cmd, void *cfg, const char *arg) {
    if(!strcasecmp(arg, "on")) config.enabled = 1;
    else config.enabled = 0;
    return NULL;
}

/** Handler for enabling or disabling the stream security module's debugging. */
const char* stream_security_set_debug(cmd_parms *cmd, void *cfg, const char *arg) {
    if(!strcasecmp(arg, "on")) config.debug = 1;
    else config.debug = 0;
    return NULL;
}

/** Handler for specifying the location of the key ids and secret keys for stream security. */
const char* stream_security_set_key_path(cmd_parms *cmd, void *cfg, const char *arg) {
    config.keyPath = arg;
    char *text = get_stream_security_keys(config.keyPath);
    get_key_collection(text, &secret_key_collection);
    return NULL;
}

/**
 * ========================================================
 * The available directives for the stream security module.
 * ========================================================
 * */
static const command_rec        stream_security_directives[] =
{
    AP_INIT_TAKE1("streamSecurityEnabled", stream_security_set_enabled, NULL, RSRC_CONF, "Enable or disable stream_security_module"),
    AP_INIT_TAKE1("streamSecurityDebug", stream_security_set_debug, NULL, RSRC_CONF, "Enable or disable debug printing of the stream security"),
    AP_INIT_TAKE1("streamSecurityKeysPath", stream_security_set_key_path, NULL, RSRC_CONF, "The path to the file with the key ids and secret keys"),
    { NULL }
};

/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int stream_security_handler(request_rec *r);


/* Define our module as an entity and assign a function for registering hooks  */
module AP_MODULE_DECLARE_DATA   stream_security_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,            // Per-directory configuration handler
    NULL,            // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    stream_security_directives,            // Any directives we may have for httpd
    register_hooks   // Our hook registering function
};

/* *
 * ==============================================================================
 * Hook registration so that httpd will use this module and the default settings.
 * ==============================================================================
 * */
static void register_hooks(apr_pool_t *pool) {
    config.enabled = 1;
    config.debug = 0;
    config.keyPath = DEFAULT_KEY_PATH;
    config.extensionCount = 0;
    /* Hook the request handler */
    ap_hook_handler(stream_security_handler, NULL, NULL, APR_HOOK_LAST);
}

const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot + 1;
}

void debug_print_data(request_rec *r, char* resource, struct ResourceRequest resourceRequest) {
    ap_set_content_type(r, "text/html");
    ap_rputs(DOCTYPE_HTML_3_2, r);
    ap_rputs("<HTML>\n", r);
    ap_rprintf(r, "<p>Key Path: %s</p>\n", config.keyPath);
    ap_rprintf(r, "<p>Hostname: %s</p>\n", r->hostname);
    ap_rprintf(r, "<p>URI %s</p>\n", r->uri);
    ap_rprintf(r, "<p>Query String %s</p>\n", r->args);
    ap_rprintf(r, "<p>Protocol: %s</p>\n", r->protocol);
    ap_rprintf(r, "<p>Signature: %s</p>\n", resourceRequest.signature);
    ap_rprintf(r, "<p>Key ID: %s</p>\n", resourceRequest.key_id);
    ap_rprintf(r, "<p>Decoded Policy: %s</p>\n", resourceRequest.policy.decoded_policy);
    ap_rprintf(r, "<p>Request Client IP '%s'</p>\n", r->connection->remote_ip);
    ap_rprintf(r, "<p>Policy Client IP: %s</p>\n", resourceRequest.policy.ip_address);
    ap_rprintf(r, "<p>Request Resource: %s</p>\n", resource);
    ap_rprintf(r, "<p>Policy Resource: %s</p>\n", resourceRequest.policy.resource);
    ap_rprintf(r, "<p>Return Http Status: %d</p>\n", resourceRequest.status);
    ap_rprintf(r, "<p>Rejection Reason: %s</p>\n", resourceRequest.reason);
    ap_rputs("</HTML>\n", r);
}

bool check_extension(char *resource) {
    if (config.extensions == NULL || config.extensionCount == 0) {
        return true;
    }

    char* extension = (char *)get_filename_ext((const char *)resource);
    int i;
    bool handles = false;
    for (i = 0; i < config.extensionCount; i++) {
        if (strcmp(config.extensions[i], extension) == 0) {
            handles = true;
        }
    }

    return handles;
}

/* *
 * ========================================================================
 * The module handler to actually perform the stream security verification.
 * ========================================================================
 * */
static int stream_security_handler(request_rec *r) {
    /* First off, we need to check if this is a call for the stream security handler.
     * If it is, we accept it and do our things, it not, we simply return DECLINED,
     * and Apache will try somewhere else.
     */
    if (!r->handler || strcmp(r->handler, "stream-security")) return (DECLINED);
    if (!config.enabled) return (DECLINED);

    char *httpProtocol = "http://";
    int resourceLength = strlen(httpProtocol) + strlen(r->hostname) + strlen(r->uri) + 1;
    char *httpResource = (char *) apr_palloc(r->pool, sizeof(char) * (resourceLength));
    strncpy(httpResource, httpProtocol, strlen(httpProtocol));
    strncpy(httpResource + strlen(httpProtocol), r->hostname, strlen(r->hostname));
    strncpy(httpResource + strlen(httpProtocol) + strlen(r->hostname), r->uri, strlen(r->uri));
    httpResource[resourceLength - 1] = '\0';

    struct ResourceRequest httpResourceRequest;
    get_resource_request_from_query_string(r->pool, r->args, r->connection->remote_ip, httpResource, &secret_key_collection, &httpResourceRequest);

    if (httpResourceRequest.status == HTTP_OK) {
        if (config.debug) {
            debug_print_data(r, httpResource, httpResourceRequest);
            return OK;
        }
        return DECLINED;
    }

    char *httpsProtocol = "https://";
    if (httpResourceRequest.status == HTTP_FORBIDDEN &&
            strncmp(httpsProtocol, httpResourceRequest.policy.resource, strlen(httpsProtocol)) == 0) {
        /** The resource starts with https so lets try that as the resource URL. */
        resourceLength = strlen(httpsProtocol) + strlen(r->hostname) + strlen(r->uri) + 1;
        char *httpsResource = (char *) apr_palloc(r->pool, sizeof(char) * (resourceLength));
        strncpy(httpsResource, httpsProtocol, strlen(httpsProtocol));
        strncpy(httpsResource + strlen(httpsProtocol), r->hostname, strlen(r->hostname));
        strncpy(httpsResource + strlen(httpsProtocol) + strlen(r->hostname), r->uri, strlen(r->uri));
        httpsResource[resourceLength - 1] = '\0';

        struct ResourceRequest httpsResourceRequest;
        get_resource_request_from_query_string(r->pool, r->args, r->connection->remote_ip, httpsResource, &secret_key_collection, &httpsResourceRequest);

        if (config.debug) {
            debug_print_data(r, httpsResource, httpsResourceRequest);
            return OK;
        }

        if (httpsResourceRequest.status != HTTP_OK) {
            return httpsResourceRequest.status;
        }

        return DECLINED;
    }

    if (config.debug) {
        debug_print_data(r, httpResource, httpResourceRequest);
        return OK;
    }
    return httpResourceRequest.status;
}
