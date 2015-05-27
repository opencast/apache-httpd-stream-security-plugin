#ifndef URL_SIGNING_RESOURCE_REQUEST
#define URL_SIGNING_RESOURCE_REQUEST

#include "keys.h"
#include "policy.h"

struct ResourceRequest
{
    int status;
    const char *reason;
    struct Policy policy;
    char *signature;
    char *key_id;
};

void get_resource_request_from_query_string(apr_pool_t *p, char* queryString, char* clientIp, char* resourceUri, struct KeyCollection *keyCollection, struct ResourceRequest *resourceRequest);
#endif
