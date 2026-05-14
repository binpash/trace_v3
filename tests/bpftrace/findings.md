# bpftrace correctness comparison — findings

A correctness comparison between trace_v3 and the bpftrace+post_process
pipeline surfaced a reproducible bug in trace_v3 where syscall *enter*
events can be silently dropped between the kernel ringbuf and the
userspace worker, without `missed_events` being incremented.

## How to reproduce

After `trace_v3 install`:

```sh
cd tests/correctness
for i in $(seq 1 20); do
    trace_v3 --dep-file /tmp/v3_${i}.deps \
             --trace-file /tmp/v3_${i}.trace \
             --missed-file /tmp/v3_${i}.missed \
             -- ./test-ls.sh >/dev/null 2>&1
    has=$(grep -c '/usr/lib/locale/locale-archive' /tmp/v3_${i}.deps)
    missed=$(cat /tmp/v3_${i}.missed)
    echo "run $i: has_locale_archive=$has  missed_events=$missed"
done
```

Observed (Debian 12, kernel 6.1, 10 runs): 2/10 runs miss the
`/usr/lib/locale/locale-archive` entry. `missed_events` is always 0.

## What is actually missing

`diff` between a "captures" and a "misses" trace shows the *enter* line
is gone from the misses run, while the *exit* line is still present:

```
< openat(fd=-100,path=/usr/lib/locale/locale-archive,fd2=-1,path2=,flags=524288) -> -2
---
>  -> -2
```

(That second ` -> -2` is just the Exit with no preceding Enter.)

Since `dep_tracer.rs::event_stream_handler` expects an Enter at
`event_queue[len-2]` when it sees an Exit, a missing Enter means the
syscall is silently invisible to the Read/Write set.

## Why bpftrace+post catches it

bpftrace prints the enter event as soon as the tracepoint fires; its
perf-buffer reader is in the same address space as the script and there
is no userspace handoff to a worker thread. On 5 runs it never missed
`locale-archive`.

## Implications for the writeup

- This is exactly the failure mode the PDF's §2 motivation calls
  "unacceptable" — incomplete traces produce incorrect dependency
  graphs and the `missed_events` counter does not catch it.
- The bpftrace pipeline is useful not just as a perf baseline but as a
  ground-truth oracle for trace_v3's correctness.

## Suspected root cause

The BPF side submitted the Enter (otherwise we wouldn't see the Exit on
the same syscall). Suspects, roughly in order of likelihood:

1. Userspace ringbuf poll loop loses an event when the child exits
   close to the time the event is submitted — but Exit lands fine, so
   this can't be the whole story.
2. `sys_enter_info_t` parse silently fails (e.g. on a path
   length / dynptr edge case) and the worker `continue`s.
3. A race between the ringbuf poll thread and the channel send to the
   worker thread.

To pin this down: instrument the ringbuf callback in `main.rs` to log
the raw event count and compare with the BPF-side submit count.
