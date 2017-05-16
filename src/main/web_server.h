#pragma once
#if !defined(TRUE) || !defined(FALSE)
#define TRUE  1
#define FALSE 0
#endif

struct web_server_data;
struct web_server {
    struct web_server_data *data;
};

int web_server_create(struct web_server **server, const char * port);

int web_server_start(struct web_server *server);

int web_server_stop(struct web_server *server);

int web_server_join(struct web_server *server, uint32_t timeout);

int web_server_destroy(struct web_server **server);