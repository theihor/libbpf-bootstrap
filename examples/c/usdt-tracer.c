#include <signal.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "usdt-tracer.skel.h"

static volatile sig_atomic_t exiting;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int print_event(void *ctx, void *data, size_t size)
{
	struct {
		unsigned long args[6];
	} *event = data;

	printf("USDT probe args: 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
	       event->args[0],
	       event->args[1],
	       event->args[2],
	       event->args[3],
	       event->args[4],
	       event->args[5]);

	return 0;
}

#define PAUSED_ON_EXEC (SIGTRAP | (PTRACE_EVENT_EXEC << 8))

static void print_status(int status)
{
	printf("status: 0x%04x\n", status);
}

static pid_t setup_child_process(const char *program_path)
{
	pid_t child_pid = fork();
	if (child_pid < 0) {
		fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
		return 1;
	}

	if (child_pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);
		execl(program_path, program_path, NULL);
		fprintf(stderr, "Failed to exec %s: %s\n", program_path, strerror(errno));
		exit(1);
	}

	int status;
	waitpid(child_pid, &status, 0);
	ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACEEXEC);
	print_status(status);

	ptrace(PTRACE_CONT, child_pid, 0, 0);
	waitpid(child_pid, &status, 0);
	print_status(status);

	if (status>>8 != PAUSED_ON_EXEC) {
		fprintf(stderr, "Child process %d did not pause on exec\n", child_pid);
		exit(1);
	}

	return child_pid;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <binary_path>\n", argv[0]);
		return 1;
	}

	/* Child process is paused on exec if setup was successful */
	const char *program_path = argv[1];
	pid_t child_pid = setup_child_process(program_path);

	struct ring_buffer *rb = NULL;
	struct usdt_tracer_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = usdt_tracer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->bss->target_pid = child_pid;

	err = usdt_tracer_bpf__load(skel);
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 1;
	}

	/* Hardcoded tracepoint! */
	skel->links.usdt_tracer = bpf_program__attach_usdt(
		skel->progs.usdt_tracer, child_pid, program_path, "test", "main_main", NULL);
	if (!skel->links.usdt_tracer) {
		err = errno;
		fprintf(stderr, "Failed to attach BPF program `usdt_tracer`\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), print_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Continue child process */
	ptrace(PTRACE_CONT, child_pid, 0, 0);

	int total_events = 0;
	int nr_events = 0;
	while (!exiting) {
		nr_events = ring_buffer__poll(rb, 100);
		if (nr_events == -EINTR) {
			err = 0;
			break;
		}
		if (nr_events < 0) {
			err = nr_events;
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}

		total_events += nr_events;
		printf("Read %d events, total: %d\n", nr_events, total_events);

		int status;
		if (waitpid(child_pid, &status, WNOHANG) > 0)
			break;

		usleep(100);
	}

cleanup:
	usdt_tracer_bpf__destroy(skel);
	return -err;
}
