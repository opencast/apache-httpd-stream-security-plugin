/* Include the required headers from httpd */
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

#include <stdbool.h>

#include "keys.h"
#include "resource_request.h"

/**
 * =============================================================
 * A struct that defines the configurations for stream security.
 * =============================================================
 * */
typedef struct {
    int         enabled; /* Enable or disable our module. */
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

/** Handler for specifying the location of the key ids and secret keys for stream security. */
const char* stream_security_set_key_path(cmd_parms *cmd, void *cfg, const char *arg) {
    config.keyPath = arg;
    char *text = get_stream_security_keys(config.keyPath);
    get_key_collection(text, &secret_key_collection);
    return NULL;
}

/** Handler for specifying the location of the key ids and secret keys for stream security. */
const char* stream_security_set_extensions(cmd_parms *cmd, void *cfg, const char *arg) {
    config.extensionCount = 0;
    /*if (arg == NULL || strcmp("", arg)) {
        config.extensionCount = 0;
    }

    int extensionCount = 1;
    int i;
    for (i = 0; i < strlen(arg); i++) {
        if (arg[i] == ',') {
            extensionCount++;
        }
    }

    char *extensions[extensionCount];
    config.extensionCount = extensionCount;

    char *extension = strtok(arg, ",");
    while (extension != NULL) {
        extensionCount++;
        extension = strtok(NULL, ",");
    }*/
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
    AP_INIT_TAKE1("streamSecurityConfigPath", stream_security_set_key_path, NULL, RSRC_CONF, "The path to the file with the key ids and secret keys"),
    AP_INIT_TAKE1("streamSecurityExtensions", stream_security_set_extensions, NULL, RSRC_CONF, "A comma separated list of file extensions that will have url signing applied, others will be served normally. If not specified then all files will need to be signed."),
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
    config.keyPath = "/etc/httpd/keys.properties";
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
    ap_set_content_type(r, "text/plain");
    // Environment
    ap_rprintf(r, "Enabled: %u\n", config.enabled);
    ap_rprintf(r, "Key Path: %s\n", config.keyPath);
    ap_rprintf(r, "Query String %s\n", r->args);
    ap_rprintf(r, "Unparsed URI %s\n", r->unparsed_uri);
    ap_rprintf(r, "URI %s\n", r->uri);
    ap_rprintf(r, "Hostname: %s\n", r->hostname);
    ap_rprintf(r, "Protocol: %s\n", r->protocol);
    ap_rprintf(r, "The Request %s\n", r->the_request);
    ap_rprintf(r, "Content Type %s\n", r->content_type);
    ap_rprintf(r, "Client IP '%s'\n", r->connection->remote_ip);
    // Resource
    ap_rprintf(r, "Resource: %s\n", resource);
    // Resource Request
    ap_rprintf(r, "Status: %d\n", resourceRequest.status);
    ap_rprintf(r, "Signature: %s\n", resourceRequest.signature);
    ap_rprintf(r, "Key ID: %s\n", resourceRequest.key_id);
    ap_rprintf(r, "Policy Greater: %lld \n", resourceRequest.policy.date_greater_than);
    ap_rprintf(r, "Policy Lesser: %lld \n", resourceRequest.policy.date_less_than);
    ap_rprintf(r, "Policy IP: %s\n", resourceRequest.policy.ip_address);
    ap_rprintf(r, "Policy Resource: %s\n", resourceRequest.policy.resource);
    ap_rprintf(r, "Policy Decoded Policy: %s\n", resourceRequest.policy.decoded_policy);
    ap_rprintf(r, "Compare Resource: %s %s\n", resourceRequest.policy.resource, resource);
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
    if (!r->handler || strcmp(r->handler, "stream-security-handler")) return (DECLINED);
    if (!config.enabled) return (DECLINED);

    char *protocol;
    if (strcmp("HTTP/1.1", r->protocol) == 0) {
        protocol = "http://";
    } else {
        protocol = "https://";
    }
    int resourceLength = strlen(protocol) + strlen(r->hostname) + strlen(r->uri) + 1;
    char *resource = (char *) apr_palloc(r->pool, sizeof(char) * (resourceLength));
    strncpy(resource, protocol, strlen(protocol));
    strncpy(resource + strlen(protocol), r->hostname, strlen(r->hostname));
    strncpy(resource + strlen(protocol) + strlen(r->hostname), r->uri, strlen(r->uri));

    struct ResourceRequest resourceRequest;
    get_resource_request_from_query_string(r->pool, r->args, r->connection->remote_ip, resource, &secret_key_collection, &resourceRequest);

    if (resourceRequest.status != HTTP_OK) {
        return resourceRequest.status;
    } else {
        return DECLINED;
    }
}
