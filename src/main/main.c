#include <stdio.h>
#include <stdlib.h>
#include <mongoose.h>
#include <version.h>

static const char *s_http_port = "8000";
volatile int is_running;

void cs_log_set_level(int);

struct file_writer_data {
    FILE *fp;
    size_t bytes_written;
};

static void handle_upload(struct mg_connection *nc, int ev, void *p) {
    struct file_writer_data *data = (struct file_writer_data *) nc->user_data;
    struct mg_http_multipart_part *mp = (struct mg_http_multipart_part *) p;

    switch (ev) {
        case MG_EV_HTTP_PART_BEGIN: {
            if (data == NULL) {
                data = calloc(1, sizeof(struct file_writer_data));
#if defined(WIN32)
                 tmpfile_s(&data->fp);
#else
                data->fp = tmpfile();
#endif
                data->bytes_written = 0;

                if (data->fp == NULL) {
                    mg_printf(nc, "%s",
                              "HTTP/1.1 500 Failed to open a file\r\n"
                                      "Content-Length: 0\r\n\r\n");
                    nc->flags |= MG_F_SEND_AND_CLOSE;
                    free(data);
                    return;
                }
                nc->user_data = (void *) data;
            }
            break;
        }
        case MG_EV_HTTP_PART_DATA: {
            if (data == NULL || fwrite(mp->data.p, 1, mp->data.len, data->fp) != mp->data.len) {
                mg_printf(nc, "%s",
                          "HTTP/1.1 500 Failed to write to a file\r\n"
                                  "Content-Length: 0\r\n\r\n");
                nc->flags |= MG_F_SEND_AND_CLOSE;
                return;
            }
            data->bytes_written += mp->data.len;
            break;
        }
        case MG_EV_HTTP_PART_END: {
            if (data != NULL) {
                mg_printf(nc,
                          "HTTP/1.1 200 OK\r\n"
                                  "Content-Type: text/plain\r\n"
                                  "Connection: close\r\n\r\n"
                                  "Written %ld of POST data to a temp file\n\n",
                          (long) ftell(data->fp));
                nc->flags |= MG_F_SEND_AND_CLOSE;
                fclose(data->fp);
                free(data);
                nc->user_data = NULL;
            }
            break;
        }
    }
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
    (void) ev_data;
    switch (ev) {
        case MG_EV_HTTP_REQUEST:
            mg_printf(nc, "%s",
                      "HTTP/1.1 200 OK\r\n"
                              "Content-Type: text/html\r\n"
                              "Connection: close\r\n"
                              "\r\n"
                              "<html><body>Upload example."
                              "<form method=\"POST\" action=\"/upload\" "
                              "  enctype=\"multipart/form-data\">"
                              "<input type=\"file\" name=\"file\" /> <br/>"
                              "<input type=\"submit\" value=\"Upload\" />"
                              "</form></body></html>");
            nc->flags |= MG_F_SEND_AND_CLOSE;
            break;
    }
}

int main(void) {
    struct mg_mgr mgr;
    struct mg_connection *nc;

    mg_mgr_init(&mgr, NULL);
    nc = mg_bind(&mgr, s_http_port, ev_handler);

    cs_log_set_level(4);
    mg_register_http_endpoint(nc, "/upload", handle_upload);
    mg_set_protocol_http_websocket(nc);

    printf("Starting service v%s on port %s\n", VERSION_STRING, s_http_port);
    is_running = TRUE;
    while (is_running) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);
    return 0;
}