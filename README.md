# File Dependency Tracing

`trace_v3` utilizes several eBPF programs hooked onto system call entry
tracepoints to report event information to the userspace-side application so
that a command's read and write dependencies can be determined.

## Instructions

```sh
cargo build -r
sudo ./install.sh # installs to /usr/local/bin as setuid
trace_v3 install # to install the ebpf programs and maps
```

## Note

`io_uring` is not handled


