#include <stdint.h>
#include <stdlib.h>
#include "web_server.h"

int main(void) {
    struct web_server *server = NULL;

    web_server_create(&server, "8000");
    web_server_start(server);
    web_server_join(server, (uint32_t)1000);
    web_server_stop(server);
    web_server_destroy(&server);
    return EXIT_SUCCESS;
}