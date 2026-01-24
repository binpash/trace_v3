# File Dependency Tracing

`trace_v3` utilizes several eBPF programs hooked onto system call entry
tracepoints to report event information to the userspace-side application so
that a command's read and write dependencies can be determined.


## Note

`io_uring` is not handled


