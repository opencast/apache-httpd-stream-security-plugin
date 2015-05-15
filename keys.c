#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "keys.h"

#define CONFIG_FILE  "/etc/httpd/conf/stream-security-keys.properties"

/* Return the offset of the first newline in text or the length of
   text if there's no newline */
int newline_offset(const char *text)
{
    const char *newline = strchr(text, '\n');
    if(!newline)
        return strlen(text);
    else
        return (int)(newline - text);
}


void get_key_collection(char *text, struct KeyCollection *secret_key_collection)
{
    size_t i;

    json_t *root;
    json_error_t error;
    json_t *keys;

    if(!text) {
        secret_key_collection = NULL;
        return;
    }

    root = json_loads(text, 0, &error);
    free(text);

    if(!root)
    {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        secret_key_collection = NULL;
        return;
    }

    keys = json_object_get(root, "keys");
    if(!json_is_array(keys))
    {
        fprintf(stderr, "error: keys is not an array\n");
        secret_key_collection = NULL;
        return;
    }

    if (json_array_size(keys) < 1) {
        printf("There were no keys defined so nothing to secure. Make sure you define the necessary keys in %s\n", CONFIG_FILE);
        secret_key_collection = NULL;
        return;
    }

    secret_key_collection->secret_keys = (struct SecretKey *) malloc(sizeof(struct SecretKey) * json_array_size(keys));
    secret_key_collection->count = json_array_size(keys);
    struct SecretKey *secret_keys = secret_key_collection->secret_keys;

    for(i = 0; i < json_array_size(keys); i++)
    {
        json_t *key, *keyId, *secret;
        const char *secret_text;

        key = json_array_get(keys, i);
        if(!json_is_object(key))
        {
            fprintf(stderr, "error: key %zu is not an object\n", i + 1);
            secret_key_collection = NULL;
            return;
        }

        keyId = json_object_get(key, "keyId");
        if(!json_is_string(keyId))
        {
            fprintf(stderr, "error: key %zu: keyId is not a string\n", i + 1);
            secret_key_collection = NULL;
            return;
        }

        secret = json_object_get(key, "secret");
        if(!json_is_string(secret))
        {
            fprintf(stderr, "error: key %zu: secret is not a string\n", i + 1);
            secret_key_collection = NULL;
            return;
        }

        secret_text = json_string_value(secret);
        printf("%.8s %.*s\n",
               json_string_value(keyId),
               newline_offset(secret_text),
               secret_text);

        // Copy the values for the id and secret into the array.
        secret_keys[i].id = (char *)malloc(strlen(json_string_value(keyId)) * sizeof(char) + 1);
        strcpy(secret_keys[i].id, json_string_value(keyId));

        // secret_keys[i].secret = (char *)malloc(sizeof(json_string_value(secret)));
        secret_keys[i].secret = (char *)malloc(strlen(json_string_value(secret)) * sizeof(char) + 1);
        strcpy(secret_keys[i].secret, json_string_value(secret));
    }



    json_decref(root);

    printf("Key Collection Size: %d\n", secret_key_collection->count);
}


char *get_stream_security_keys()
{
    printf("Config File Name is: %s\n", CONFIG_FILE);

    FILE *config_file;
    long lSize;
    char *buffer;

    config_file = fopen(CONFIG_FILE, "r");
    if (config_file == NULL) {
        // TODO httpd error logging.
        printf("Unable to open file\n");
        return NULL;
    }


    fseek( config_file , 0L , SEEK_END);
    lSize = ftell( config_file );
    rewind( config_file );

    /* allocate memory for entire content */
    buffer = calloc( 1, lSize+1 );
    if( !buffer ) fclose(config_file),fputs("memory alloc fails",stderr),exit(1);

    /* copy the file into the buffer */
    if( 1!=fread( buffer , lSize, 1 , config_file) )
    fclose(config_file),free(buffer),fputs("entire read fails",stderr),exit(1);

    /* do your work here, buffer is a string contains the whole text */
     printf("Contents: %s", buffer);
    fclose(config_file);
    return buffer;
}
