#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

pid_t target_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024);
} rb SEC(".maps");

SEC("usdt")
int BPF_USDT(usdt_tracer, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6)
{
    if (target_pid && bpf_get_current_pid_tgid() >> 32 != target_pid)
        return 0;

    struct {
        unsigned long args[6];
    } *event;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->args[0] = (unsigned long)arg1;
    event->args[1] = (unsigned long)arg2;
    event->args[2] = (unsigned long)arg3;
    event->args[3] = (unsigned long)arg4;
    event->args[4] = (unsigned long)arg5;
    event->args[5] = (unsigned long)arg6;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
