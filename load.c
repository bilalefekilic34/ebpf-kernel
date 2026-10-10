#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <signal.h>

struct limit_info { __u64 pkt_cnt, bytes_cnt, limit; };
int running = 1;
void stop(int sig) { running = 0; }

int main(int argc, char **argv) {
    signal(SIGINT, stop);

    struct bpf_object *obj = bpf_object__open_file(argv[2], NULL);
    bpf_object__load(obj);
    
    int ifidx = if_nametoindex(argv[1]);
    bpf_xdp_attach(ifidx, bpf_program__fd(bpf_object__next_program(obj, NULL)), 0, NULL);
    
    int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "ip_limit_map"));
    int map2_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "ip_blacklist"));

    FILE *f = fopen("blacklist", "r");
    char line[32];
    __u8 val = 1;
    struct in_addr addr;
    
    while (fscanf(f, "%s", line) != EOF) {
        inet_pton(AF_INET, line, &addr);
        bpf_map_update_elem(map2_fd, &addr.s_addr, &val, BPF_ANY);
    }
    fclose(f);

    __u32 key, *prev;
    struct limit_info info;

    while (running && sleep(2) == 0) {
        for (prev = NULL; bpf_map_get_next_key(map_fd, prev, &key) == 0; prev = &key) {
            bpf_map_lookup_elem(map_fd, &key, &info);
            printf("%s | Pkt: %llu | Bytes: %llu\n", inet_ntoa(*(struct in_addr*)&key), info.pkt_cnt, info.bytes_cnt);
        }
    }

    bpf_xdp_detach(ifidx, 0, NULL);
    bpf_object__close(obj);
    return 0;
}
