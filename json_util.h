#ifndef URL_SIGNING_JSON_UTIL
#define URL_SIGNING_JSON_UTIL
#include "httpd.h"
char *get_json_string(apr_pool_t *p, json_t *parent, char *json_key);
long long get_json_long_long(json_t *parent, char *json_key);
#endif
