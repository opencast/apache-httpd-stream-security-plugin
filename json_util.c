#include <jansson.h>
#include <stdlib.h>
#include <string.h>
#include "json_util.h"

/**
 * Gets a mandatory json string value.
 * @param parent
 *      The json object who is a parent to this key : string value pair.
 * @param resource_request
 *      The resource request that is retrieving the string value. Used to update the status in case something goes wrong.
 * @param json_key
 *      The string key that will identify the value to retrieve.
 * @return The string value if available, NULL if not.
 */
char *get_json_string(json_t *parent, char *json_key) {
    json_t *obj = json_object_get(parent, json_key);

    if(!json_is_string(obj)) {
        printf("Didn't find string '%s'\n", json_key);
        return NULL;
    } else {
        char *return_string = (char *)malloc(strlen(json_string_value(obj)) * sizeof(char) + 1);
        strcpy(return_string, json_string_value(obj));
        printf("Found string %s\n", return_string);
        return return_string;
    }
}

long long get_json_long_long(json_t *parent, char *json_key) {
    json_t *value = json_object_get(parent, json_key);
    if(!json_is_integer(value)) {
        printf("The key was: '%s' value was: %s\n", json_key, json_string_value(value));
        return -1;
    } else {
        printf("The new value: %lld\n", (long long)json_integer_value(value));
        return (long long)json_integer_value(value);
    }
}

