#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <poll.h>
#include "common.h"

#define PERF_BUFFER_PAGES 64
#define BPF_PROGRAM_PATH "ebpf.o"

// Perf buffer event callback
void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    // printf("Event received on CPU %d, size %u bytes\n", cpu, size);
    // Add your data parsing logic here
}

// Perf buffer lost callback
void handle_lost_events(void *ctx, int cpu, __u64 lost) {
    // fprintf(stderr, "Lost %llu events on CPU %d\n", lost, cpu);
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *perf_map;
    struct perf_buffer *pb;
    int prog_fd, perf_map_fd;

    // Adjust RLIMIT_MEMLOCK to allow loading BPF programs
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit");
        return 1;
    }

    // Load the BPF object file
    obj = bpf_object__open_file(BPF_PROGRAM_PATH, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF program file: %s\n", strerror(errno));
        return 1;
    }

    // Load the BPF program into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Get the BPF program file descriptor
    // prog = bpf_object__next_program(obj, NULL);
    // if (!prog) {
    //     fprintf(stderr, "Failed to find BPF program\n");
    //     bpf_object__close(obj);
    //     return 1;
    // }
    // prog_fd = bpf_program__fd(prog);

    // Find the perf event map
    perf_map = bpf_object__find_map_by_name(obj, "events");
    if (!perf_map) {
        fprintf(stderr, "Failed to find perf event map\n");
        bpf_object__close(obj);
        return 1;
    }
    perf_map_fd = bpf_map__fd(perf_map);

    // Set up the perf buffer
    pb = perf_buffer__new(perf_map_fd, PERF_BUFFER_PAGES, handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    {
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj) {
            const char *prog_name = bpf_program__name(prog);
            if (strcmp(prog_name, "tracepoint_sys_enter_read") == 0) {
                break; // Found the program
            }
        }

        if (!prog) {
            fprintf(stderr, "Failed to find BPF program by name\n");
            bpf_object__close(obj);
            return 1;
        }

        struct bpf_link *link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_read");
        if (!link) {
            fprintf(stderr, "Failed to attach tracepoint: %s\n", strerror(errno));
            bpf_object__close(obj);
            return 1;
        }
        prog = NULL;

        bpf_object__for_each_program(prog, obj) {
            const char *prog_name = bpf_program__name(prog);
            if (strcmp(prog_name, "tracepoint_sys_enter_write") == 0) {
                break; // Found the program
            }
        }

        if (!prog) {
            fprintf(stderr, "Failed to find BPF program by name\n");
            bpf_object__close(obj);
            return 1;
        }

        link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_write");
        if (!link) {
            fprintf(stderr, "Failed to attach tracepoint: %s\n", strerror(errno));
            bpf_object__close(obj);
            return 1;
        }

        // prog = bpf_object__find_program_by_title(obj, "tracepoint_sys_enter_write");
        // if (!prog) {
        //     fprintf(stderr, "Failed to find BPF program by title\n");
        //     bpf_object__close(obj);
        //     return 1;
        // }

        // link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_write");
        // if (!link) {
        //     fprintf(stderr, "Failed to attach tracepoint: %s\n", strerror(errno));
        //     bpf_object__close(obj);
        //     return 1;
        // }

    }

    printf("Polling events...\n");

    // Poll events
    while (1) {
        int ret = perf_buffer__poll(pb, 100 /* timeout in ms */);
        if (ret < 0 && ret != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", ret);
            break;
        }
    }

    // Clean up
    perf_buffer__free(pb);
    bpf_object__close(obj);

    return 0;
}
