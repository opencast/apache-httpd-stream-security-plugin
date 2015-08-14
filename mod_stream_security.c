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
#include "apr_strings.h"

#include <stdbool.h>

#include "keys.h"
#include "resource_request.h"

#define DEFAULT_KEY_PATH "/etc/httpd/conf/stream-security-keys.json"

#ifndef APACHE2_2
  #ifdef AP_SERVER_MAJORVERSION_NUMBER
    #ifdef AP_SERVER_MINORVERSION_NUMBER
      #if ((AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER == 2))
        #define APACHE2_2
      #endif
    #endif
  #endif
#endif

#ifndef APACHE2_4
  #ifdef AP_SERVER_MAJORVERSION_NUMBER
    #ifdef AP_SERVER_MINORVERSION_NUMBER
      #if ((AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER == 4))
        #define APACHE2_4
      #endif
    #endif
  #endif
#endif

/**
 * =============================================================
 * A struct that defines the configurations for stream security.
 * =============================================================
 * */
typedef struct {
    int         enabled; /* Enable or disable our module. */
    int         debug; /* Enable or disable debug print out of the module. */
    const char  *keyPath; /* The path to the file that holds the keyids and secret keys */
    int         strict; /* Enable strict checking of resources or just the path to the resource */
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

/** Handler for using strict comparison of the resource (use everything or just the path) */
const char* stream_security_set_strict(cmd_parms *cmd, void *cfg, const char *arg) {
    if(!strcasecmp(arg, "on")) config.strict = 1;
    else config.strict = 0;
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
    AP_INIT_TAKE1("streamSecurityStrict", stream_security_set_strict, NULL, RSRC_CONF, "Enable or disable strict checking of resources"),
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
    config.strict = 1;
    /* Hook the request handler */
    ap_hook_handler(stream_security_handler, NULL, NULL, APR_HOOK_LAST);
}

void debug_print_data(request_rec *r, char* resource, struct ResourceRequest resourceRequest) {
    ap_set_content_type(r, "text/html");
    ap_rputs(DOCTYPE_HTML_3_2, r);
    ap_rputs("<HTML>\n", r);
    ap_rprintf(r, "<p>Key Path: '%s'</p>\n", config.keyPath);
    ap_rprintf(r, "<p>Hostname: '%s'</p>\n", r->hostname);
    ap_rprintf(r, "<p>Strict (if 0 then just check path): '%d'</p>\n", config.strict);
    ap_rprintf(r, "<p>URI: '%s'</p>\n", r->uri);
    ap_rprintf(r, "<p>Scheme: '%s'</p>\n", ap_http_scheme(r));
    ap_rprintf(r, "<p>Query String: '%s'</p>\n", r->args);
    ap_rprintf(r, "<p>Signature: '%s'</p>\n", resourceRequest.signature);
    ap_rprintf(r, "<p>Key ID: '%s'</p>\n", resourceRequest.key_id);
    ap_rprintf(r, "<p>Decoded Policy: '%s'</p>\n", resourceRequest.policy.decoded_policy);
    #ifdef APACHE2_2
    char* clientIP = r->connection->remote_ip;
    #endif
    #ifdef APACHE2_4
    char* clientIP = r->connection->client_ip;
    #endif
    ap_rprintf(r, "<p>Request Client IP '%s'</p>\n", clientIP);
    ap_rprintf(r, "<p>Policy Client IP: '%s'</p>\n", resourceRequest.policy.ip_address);
    ap_rprintf(r, "<p>Request Resource: '%s'</p>\n", resource);
    ap_rprintf(r, "<p>Policy Resource: '%s'</p>\n", resourceRequest.policy.resource);
    ap_rprintf(r, "<p>Return Http Status: '%d'</p>\n", resourceRequest.status);
    ap_rprintf(r, "<p>Rejection Reason: '%s'</p>\n", resourceRequest.reason);
    ap_rputs("</HTML>\n", r);
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
    char *protocol;
    if (apr_strnatcmp(ap_http_scheme(r), "https") == 0) {
        protocol = "https://";
    } else {
        protocol = "http://";
    }

    int resourceLength;
    char *resource;
    if (config.strict) {
        resourceLength = strlen(protocol) + strlen(r->hostname) + strlen(r->uri) + 1;
        resource = (char *) apr_pcalloc(r->pool, sizeof(char) * (resourceLength));
        strncpy(resource, protocol, strlen(protocol));
        strncpy(resource + strlen(protocol), r->hostname, strlen(r->hostname));
        strncpy(resource + strlen(protocol) + strlen(r->hostname), r->uri, strlen(r->uri));
        resource[resourceLength - 1] = '\0';
    } else {
        resourceLength = strlen(r->uri) + 1;
        resource = (char *) apr_pcalloc(r->pool, sizeof(char) * (resourceLength));
        strncpy(resource, r->uri, strlen(r->uri));
        resource[resourceLength - 1] = '\0';
    }

    struct ResourceRequest resourceRequest;
    #ifdef APACHE2_2
    char* clientIP = r->connection->remote_ip;
    #endif
    #ifdef APACHE2_4
    char* clientIP = r->connection->client_ip;
    #endif

    get_resource_request_from_query_string(r->pool, config.strict, r->args, clientIP, resource, &secret_key_collection, &resourceRequest);

    if (config.debug) {
        debug_print_data(r, resource, resourceRequest);
        return OK;
    }

    if (resourceRequest.status == HTTP_OK) {
        return DECLINED;
    }

    return resourceRequest.status;
}
