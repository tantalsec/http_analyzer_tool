#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <tantal.h>

#define READ_BUF_SIZE 1024*1024

#define PROCESS_BUF_SIZE 1024

static void print_usage(FILE * stream, int exit_code) {  
    fprintf(stream, ">>>>>>>>> http analyzer tantal tool <<<<<<<<<\n");
    fprintf(stream, "-h --help            Display the information\n");
    fprintf(stream, "-u --rules filename  Rules filename\n");
    fprintf(stream, "-v --verbose         Print verbose messages\n");
    fprintf(stream, "-d --dump number     Dump result of request processing\n");
    exit(exit_code);
}

static int dump_request(tnl_http_req_t * req, int req_num) {
    char filename[256];
    snprintf(filename, sizeof (filename), "hatt_request_%d.dump", req_num);
    char * buf = NULL;
    size_t packed_size = tnl_http_req_pack(req, &buf);
    if (packed_size == 0 || buf == NULL) {
        return TNL_ERROR;
    }
    FILE * f;
    f = fopen(filename, "wb");
    fwrite(buf, packed_size, 1, f);
    fclose(f);
    free(buf);
    return TNL_OK;
}

static int process_file(tnl_t * t, int fd, int req_to_dump, int verbose) {
    static char buf[READ_BUF_SIZE];
    ssize_t ret;
    size_t file_off = 0;
    int req_num = 1;

    int rc = TNL_OK;

    tnl_http_req_t * req = tnl_http_req_new(t, tnl_heap_allocator());

    if (req == NULL) {
        fprintf(stdout, "Error: %s\n", tnl_error(t));
        return TNL_ERROR;
    }

    while ((ret = read(fd, buf, READ_BUF_SIZE)) != 0) {
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("Error: ");
            rc = TNL_ERROR;
            break;
        }

        size_t read_buf_size = ret;

        size_t process_buf_size = (ret < PROCESS_BUF_SIZE) ? ret : PROCESS_BUF_SIZE;

        size_t process_buf_off = 0;

        if (verbose) {
            fprintf(stdout, ">> Read new chunk: req: %d off: %zu size: %zd\n", req_num, file_off, ret);
        }

        while (process_buf_off < read_buf_size) {
            char * process_chunk = &buf[process_buf_off];

            size_t off = 0;
            size_t len = process_buf_size;

req_check:
            if (verbose) {
                fprintf(stdout, "---- Check: req: %d off: %zu size %zd ", req_num, (file_off + process_buf_off + off), len);
            }

            int rc = tnl_http_req_chunk_check(req, NULL, &process_chunk[off], len, false);

            if (rc == TNL_ERROR) {
                fprintf(stdout, "[ERROR: r: %d %s]\n", req_num, tnl_http_req_error(req));
                tnl_http_req_free(req);
                return TNL_ERROR;
            } else if (rc == TNL_DENY) {
                fprintf(stdout, "[DENY: r: %d point: %d:%d]\n", req_num, tnl_http_req_matched_conditions_id_get(req), tnl_http_req_matched_condition_get(req));
            } else if (rc == TNL_OK) {
                if (verbose) {
                    fprintf(stdout, "[OK: point: %d:%d]\n", tnl_http_req_matched_conditions_id_get(req), tnl_http_req_matched_condition_get(req));
                }
            } else if (rc == TNL_PENDING) {
                if (verbose) {
                    fprintf(stdout, "[PENDING]\n");
                }
            }

            if (tnl_http_req_is_completed(req)) {
                size_t consumed = tnl_http_req_consumed(req);
                off += consumed;
                len -= consumed;
                if (verbose) {
                    fprintf(stdout, "---- Completed req: %d chunk off: %zu len: %zu\n", req_num, off, len);
                }
                if (req_num == req_to_dump) {
                    if (dump_request(req, req_num) == TNL_ERROR) {
                        fprintf(stdout, "---- Dump request error: %s\n", tnl_http_req_error(req));
                        tnl_http_req_free(req);
                        return TNL_ERROR;
                    }
                    fprintf(stdout, "---- Dump: hatt_request_%d.dump\n", req_num);
                }
                tnl_http_req_free(req);
                req = tnl_http_req_new(t, tnl_heap_allocator());
                if (req == NULL) {
                    fprintf(stdout, "Error: %s\n", tnl_error(t));
                    return TNL_ERROR;
                }
                ++req_num;
                if (len > 0) {
                    goto req_check;
                }
            }

            process_buf_off += process_buf_size;
        }

        file_off += ret;

    }

    tnl_http_req_free(req);

    return rc;
}

int main(int argc, char *argv[]) {
    int next_option;

    const char * const short_options = "hu:d:v";
    const struct option long_options[] = {
        {"help",    0, NULL,  'h' },
        {"rules",   1, NULL,  'u' },
        {"dump",    1, NULL,  'd' },
        {"verbose", 0, NULL,  'v' },
        { NULL,     0, NULL,  0}
    };

    const char * rules_filename = NULL;
    int verbose = 0;
    int req_to_dump = 0;

    while((next_option = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (next_option) {
            case 'h' : print_usage(stdout, EXIT_SUCCESS);
		       break;
            case 'u' : rules_filename = optarg;
                       break;
            case 'v' : verbose = 1;
                       break;
            case 'd' : req_to_dump = atoi(optarg);
                       break;
            case '?' : print_usage(stderr, EXIT_FAILURE);
		       break;
            default: abort();
        }
    }

    if (rules_filename == NULL) {
        fprintf(stderr, "Error: empty rules filename\n");
        exit(EXIT_FAILURE);
    }

    char err[TNL_ERR_MAX];
    tnl_t * t = tnl_new(rules_filename, err);
    if (t == NULL) {
        fprintf(stderr, "Error: %s\n", err);
        exit(EXIT_FAILURE);
    }

    if (process_file(t, STDIN_FILENO, req_to_dump, verbose) == TNL_ERROR) {
        tnl_free(t);
        exit(EXIT_FAILURE);
    }

    tnl_free(t);

    return 0;
}
