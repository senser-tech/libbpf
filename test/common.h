
#ifndef _COMMON_H__
#define _COMMON_H__

#define TASK_COMM_LEN 16
struct data_t {
    uint64_t seq_id;
    uint32_t pid;
    char comm[TASK_COMM_LEN];
    char data[128];
    int bytes;
};
#endif