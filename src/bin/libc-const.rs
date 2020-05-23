
			#[rustfmt::skip]
			#[allow(deprecated)]
			fn main() {
				let author = format!("CC BY-SA-NC 4.0 - {}", env!("CARGO_PKG_HOMEPAGE"));
				let args = clap::App::new("defnew")
					.author(author.as_str())
					.about("libc-const: provides values for libc constants")
					.after_help("Values are hard-coded at compile and are not guaranteed to be correct for your system.")
					.version(clap::crate_version!())
					.setting(clap::AppSettings::SubcommandRequired)
			
.subcommand(clap::App::new("SYS_statx"))
.subcommand(clap::App::new("SYS_pkey_free"))
.subcommand(clap::App::new("SYS_pkey_alloc"))
.subcommand(clap::App::new("SYS_pkey_mprotect"))
.subcommand(clap::App::new("SYS_pwritev2"))
.subcommand(clap::App::new("SYS_preadv2"))
.subcommand(clap::App::new("SYS_copy_file_range"))
.subcommand(clap::App::new("SYS_mlock2"))
.subcommand(clap::App::new("SYS_membarrier"))
.subcommand(clap::App::new("SYS_userfaultfd"))
.subcommand(clap::App::new("SYS_execveat"))
.subcommand(clap::App::new("SYS_bpf"))
.subcommand(clap::App::new("SYS_kexec_file_load"))
.subcommand(clap::App::new("SYS_memfd_create"))
.subcommand(clap::App::new("SYS_getrandom"))
.subcommand(clap::App::new("SYS_seccomp"))
.subcommand(clap::App::new("SYS_renameat2"))
.subcommand(clap::App::new("SYS_sched_getattr"))
.subcommand(clap::App::new("SYS_sched_setattr"))
.subcommand(clap::App::new("SYS_finit_module"))
.subcommand(clap::App::new("SYS_kcmp"))
.subcommand(clap::App::new("SYS_process_vm_writev"))
.subcommand(clap::App::new("SYS_process_vm_readv"))
.subcommand(clap::App::new("SYS_getcpu"))
.subcommand(clap::App::new("SYS_setns"))
.subcommand(clap::App::new("SYS_sendmmsg"))
.subcommand(clap::App::new("SYS_syncfs"))
.subcommand(clap::App::new("SYS_clock_adjtime"))
.subcommand(clap::App::new("SYS_open_by_handle_at"))
.subcommand(clap::App::new("SYS_name_to_handle_at"))
.subcommand(clap::App::new("SYS_prlimit64"))
.subcommand(clap::App::new("SYS_fanotify_mark"))
.subcommand(clap::App::new("SYS_fanotify_init"))
.subcommand(clap::App::new("SYS_recvmmsg"))
.subcommand(clap::App::new("SYS_perf_event_open"))
.subcommand(clap::App::new("SYS_rt_tgsigqueueinfo"))
.subcommand(clap::App::new("SYS_pwritev"))
.subcommand(clap::App::new("SYS_preadv"))
.subcommand(clap::App::new("SYS_inotify_init1"))
.subcommand(clap::App::new("SYS_pipe2"))
.subcommand(clap::App::new("SYS_dup3"))
.subcommand(clap::App::new("SYS_epoll_create1"))
.subcommand(clap::App::new("SYS_eventfd2"))
.subcommand(clap::App::new("SYS_signalfd4"))
.subcommand(clap::App::new("SYS_accept4"))
.subcommand(clap::App::new("SYS_timerfd_gettime"))
.subcommand(clap::App::new("SYS_timerfd_settime"))
.subcommand(clap::App::new("SYS_fallocate"))
.subcommand(clap::App::new("SYS_eventfd"))
.subcommand(clap::App::new("SYS_timerfd_create"))
.subcommand(clap::App::new("SYS_signalfd"))
.subcommand(clap::App::new("SYS_epoll_pwait"))
.subcommand(clap::App::new("SYS_utimensat"))
.subcommand(clap::App::new("SYS_move_pages"))
.subcommand(clap::App::new("SYS_vmsplice"))
.subcommand(clap::App::new("SYS_sync_file_range"))
.subcommand(clap::App::new("SYS_tee"))
.subcommand(clap::App::new("SYS_splice"))
.subcommand(clap::App::new("SYS_get_robust_list"))
.subcommand(clap::App::new("SYS_set_robust_list"))
.subcommand(clap::App::new("SYS_unshare"))
.subcommand(clap::App::new("SYS_ppoll"))
.subcommand(clap::App::new("SYS_pselect6"))
.subcommand(clap::App::new("SYS_faccessat"))
.subcommand(clap::App::new("SYS_fchmodat"))
.subcommand(clap::App::new("SYS_readlinkat"))
.subcommand(clap::App::new("SYS_symlinkat"))
.subcommand(clap::App::new("SYS_linkat"))
.subcommand(clap::App::new("SYS_renameat"))
.subcommand(clap::App::new("SYS_unlinkat"))
.subcommand(clap::App::new("SYS_newfstatat"))
.subcommand(clap::App::new("SYS_futimesat"))
.subcommand(clap::App::new("SYS_fchownat"))
.subcommand(clap::App::new("SYS_mknodat"))
.subcommand(clap::App::new("SYS_mkdirat"))
.subcommand(clap::App::new("SYS_openat"))
.subcommand(clap::App::new("SYS_migrate_pages"))
.subcommand(clap::App::new("SYS_inotify_rm_watch"))
.subcommand(clap::App::new("SYS_inotify_add_watch"))
.subcommand(clap::App::new("SYS_inotify_init"))
.subcommand(clap::App::new("SYS_ioprio_get"))
.subcommand(clap::App::new("SYS_ioprio_set"))
.subcommand(clap::App::new("SYS_keyctl"))
.subcommand(clap::App::new("SYS_request_key"))
.subcommand(clap::App::new("SYS_add_key"))
.subcommand(clap::App::new("SYS_waitid"))
.subcommand(clap::App::new("SYS_kexec_load"))
.subcommand(clap::App::new("SYS_mq_getsetattr"))
.subcommand(clap::App::new("SYS_mq_notify"))
.subcommand(clap::App::new("SYS_mq_timedreceive"))
.subcommand(clap::App::new("SYS_mq_timedsend"))
.subcommand(clap::App::new("SYS_mq_unlink"))
.subcommand(clap::App::new("SYS_mq_open"))
.subcommand(clap::App::new("SYS_get_mempolicy"))
.subcommand(clap::App::new("SYS_set_mempolicy"))
.subcommand(clap::App::new("SYS_mbind"))
.subcommand(clap::App::new("SYS_vserver"))
.subcommand(clap::App::new("SYS_utimes"))
.subcommand(clap::App::new("SYS_tgkill"))
.subcommand(clap::App::new("SYS_epoll_ctl"))
.subcommand(clap::App::new("SYS_epoll_wait"))
.subcommand(clap::App::new("SYS_exit_group"))
.subcommand(clap::App::new("SYS_clock_nanosleep"))
.subcommand(clap::App::new("SYS_clock_getres"))
.subcommand(clap::App::new("SYS_clock_gettime"))
.subcommand(clap::App::new("SYS_clock_settime"))
.subcommand(clap::App::new("SYS_timer_delete"))
.subcommand(clap::App::new("SYS_timer_getoverrun"))
.subcommand(clap::App::new("SYS_timer_gettime"))
.subcommand(clap::App::new("SYS_timer_settime"))
.subcommand(clap::App::new("SYS_timer_create"))
.subcommand(clap::App::new("SYS_fadvise64"))
.subcommand(clap::App::new("SYS_semtimedop"))
.subcommand(clap::App::new("SYS_restart_syscall"))
.subcommand(clap::App::new("SYS_set_tid_address"))
.subcommand(clap::App::new("SYS_getdents64"))
.subcommand(clap::App::new("SYS_remap_file_pages"))
.subcommand(clap::App::new("SYS_epoll_wait_old"))
.subcommand(clap::App::new("SYS_epoll_ctl_old"))
.subcommand(clap::App::new("SYS_epoll_create"))
.subcommand(clap::App::new("SYS_lookup_dcookie"))
.subcommand(clap::App::new("SYS_get_thread_area"))
.subcommand(clap::App::new("SYS_io_cancel"))
.subcommand(clap::App::new("SYS_io_submit"))
.subcommand(clap::App::new("SYS_io_getevents"))
.subcommand(clap::App::new("SYS_io_destroy"))
.subcommand(clap::App::new("SYS_io_setup"))
.subcommand(clap::App::new("SYS_set_thread_area"))
.subcommand(clap::App::new("SYS_sched_getaffinity"))
.subcommand(clap::App::new("SYS_sched_setaffinity"))
.subcommand(clap::App::new("SYS_futex"))
.subcommand(clap::App::new("SYS_time"))
.subcommand(clap::App::new("SYS_tkill"))
.subcommand(clap::App::new("SYS_fremovexattr"))
.subcommand(clap::App::new("SYS_lremovexattr"))
.subcommand(clap::App::new("SYS_removexattr"))
.subcommand(clap::App::new("SYS_flistxattr"))
.subcommand(clap::App::new("SYS_llistxattr"))
.subcommand(clap::App::new("SYS_listxattr"))
.subcommand(clap::App::new("SYS_fgetxattr"))
.subcommand(clap::App::new("SYS_lgetxattr"))
.subcommand(clap::App::new("SYS_getxattr"))
.subcommand(clap::App::new("SYS_fsetxattr"))
.subcommand(clap::App::new("SYS_lsetxattr"))
.subcommand(clap::App::new("SYS_setxattr"))
.subcommand(clap::App::new("SYS_readahead"))
.subcommand(clap::App::new("SYS_gettid"))
.subcommand(clap::App::new("SYS_security"))
.subcommand(clap::App::new("SYS_tuxcall"))
.subcommand(clap::App::new("SYS_afs_syscall"))
.subcommand(clap::App::new("SYS_putpmsg"))
.subcommand(clap::App::new("SYS_getpmsg"))
.subcommand(clap::App::new("SYS_nfsservctl"))
.subcommand(clap::App::new("SYS_quotactl"))
.subcommand(clap::App::new("SYS_query_module"))
.subcommand(clap::App::new("SYS_get_kernel_syms"))
.subcommand(clap::App::new("SYS_delete_module"))
.subcommand(clap::App::new("SYS_init_module"))
.subcommand(clap::App::new("SYS_create_module"))
.subcommand(clap::App::new("SYS_ioperm"))
.subcommand(clap::App::new("SYS_iopl"))
.subcommand(clap::App::new("SYS_setdomainname"))
.subcommand(clap::App::new("SYS_sethostname"))
.subcommand(clap::App::new("SYS_reboot"))
.subcommand(clap::App::new("SYS_swapoff"))
.subcommand(clap::App::new("SYS_swapon"))
.subcommand(clap::App::new("SYS_umount2"))
.subcommand(clap::App::new("SYS_mount"))
.subcommand(clap::App::new("SYS_settimeofday"))
.subcommand(clap::App::new("SYS_acct"))
.subcommand(clap::App::new("SYS_sync"))
.subcommand(clap::App::new("SYS_chroot"))
.subcommand(clap::App::new("SYS_setrlimit"))
.subcommand(clap::App::new("SYS_adjtimex"))
.subcommand(clap::App::new("SYS_arch_prctl"))
.subcommand(clap::App::new("SYS_prctl"))
.subcommand(clap::App::new("SYS__sysctl"))
.subcommand(clap::App::new("SYS_pivot_root"))
.subcommand(clap::App::new("SYS_modify_ldt"))
.subcommand(clap::App::new("SYS_vhangup"))
.subcommand(clap::App::new("SYS_munlockall"))
.subcommand(clap::App::new("SYS_mlockall"))
.subcommand(clap::App::new("SYS_munlock"))
.subcommand(clap::App::new("SYS_mlock"))
.subcommand(clap::App::new("SYS_sched_rr_get_interval"))
.subcommand(clap::App::new("SYS_sched_get_priority_min"))
.subcommand(clap::App::new("SYS_sched_get_priority_max"))
.subcommand(clap::App::new("SYS_sched_getscheduler"))
.subcommand(clap::App::new("SYS_sched_setscheduler"))
.subcommand(clap::App::new("SYS_sched_getparam"))
.subcommand(clap::App::new("SYS_sched_setparam"))
.subcommand(clap::App::new("SYS_setpriority"))
.subcommand(clap::App::new("SYS_getpriority"))
.subcommand(clap::App::new("SYS_sysfs"))
.subcommand(clap::App::new("SYS_fstatfs"))
.subcommand(clap::App::new("SYS_statfs"))
.subcommand(clap::App::new("SYS_ustat"))
.subcommand(clap::App::new("SYS_personality"))
.subcommand(clap::App::new("SYS_uselib"))
.subcommand(clap::App::new("SYS_mknod"))
.subcommand(clap::App::new("SYS_utime"))
.subcommand(clap::App::new("SYS_sigaltstack"))
.subcommand(clap::App::new("SYS_rt_sigsuspend"))
.subcommand(clap::App::new("SYS_rt_sigqueueinfo"))
.subcommand(clap::App::new("SYS_rt_sigtimedwait"))
.subcommand(clap::App::new("SYS_rt_sigpending"))
.subcommand(clap::App::new("SYS_capset"))
.subcommand(clap::App::new("SYS_capget"))
.subcommand(clap::App::new("SYS_getsid"))
.subcommand(clap::App::new("SYS_setfsgid"))
.subcommand(clap::App::new("SYS_setfsuid"))
.subcommand(clap::App::new("SYS_getpgid"))
.subcommand(clap::App::new("SYS_getresgid"))
.subcommand(clap::App::new("SYS_setresgid"))
.subcommand(clap::App::new("SYS_getresuid"))
.subcommand(clap::App::new("SYS_setresuid"))
.subcommand(clap::App::new("SYS_setgroups"))
.subcommand(clap::App::new("SYS_getgroups"))
.subcommand(clap::App::new("SYS_setregid"))
.subcommand(clap::App::new("SYS_setreuid"))
.subcommand(clap::App::new("SYS_setsid"))
.subcommand(clap::App::new("SYS_getpgrp"))
.subcommand(clap::App::new("SYS_getppid"))
.subcommand(clap::App::new("SYS_setpgid"))
.subcommand(clap::App::new("SYS_getegid"))
.subcommand(clap::App::new("SYS_geteuid"))
.subcommand(clap::App::new("SYS_setgid"))
.subcommand(clap::App::new("SYS_setuid"))
.subcommand(clap::App::new("SYS_getgid"))
.subcommand(clap::App::new("SYS_syslog"))
.subcommand(clap::App::new("SYS_getuid"))
.subcommand(clap::App::new("SYS_ptrace"))
.subcommand(clap::App::new("SYS_times"))
.subcommand(clap::App::new("SYS_sysinfo"))
.subcommand(clap::App::new("SYS_getrusage"))
.subcommand(clap::App::new("SYS_getrlimit"))
.subcommand(clap::App::new("SYS_gettimeofday"))
.subcommand(clap::App::new("SYS_umask"))
.subcommand(clap::App::new("SYS_lchown"))
.subcommand(clap::App::new("SYS_fchown"))
.subcommand(clap::App::new("SYS_chown"))
.subcommand(clap::App::new("SYS_fchmod"))
.subcommand(clap::App::new("SYS_chmod"))
.subcommand(clap::App::new("SYS_readlink"))
.subcommand(clap::App::new("SYS_symlink"))
.subcommand(clap::App::new("SYS_unlink"))
.subcommand(clap::App::new("SYS_link"))
.subcommand(clap::App::new("SYS_creat"))
.subcommand(clap::App::new("SYS_rmdir"))
.subcommand(clap::App::new("SYS_mkdir"))
.subcommand(clap::App::new("SYS_rename"))
.subcommand(clap::App::new("SYS_fchdir"))
.subcommand(clap::App::new("SYS_chdir"))
.subcommand(clap::App::new("SYS_getcwd"))
.subcommand(clap::App::new("SYS_getdents"))
.subcommand(clap::App::new("SYS_ftruncate"))
.subcommand(clap::App::new("SYS_truncate"))
.subcommand(clap::App::new("SYS_fdatasync"))
.subcommand(clap::App::new("SYS_fsync"))
.subcommand(clap::App::new("SYS_flock"))
.subcommand(clap::App::new("SYS_fcntl"))
.subcommand(clap::App::new("SYS_msgctl"))
.subcommand(clap::App::new("SYS_msgrcv"))
.subcommand(clap::App::new("SYS_msgsnd"))
.subcommand(clap::App::new("SYS_msgget"))
.subcommand(clap::App::new("SYS_shmdt"))
.subcommand(clap::App::new("SYS_semctl"))
.subcommand(clap::App::new("SYS_semop"))
.subcommand(clap::App::new("SYS_semget"))
.subcommand(clap::App::new("SYS_uname"))
.subcommand(clap::App::new("SYS_kill"))
.subcommand(clap::App::new("SYS_wait4"))
.subcommand(clap::App::new("SYS_exit"))
.subcommand(clap::App::new("SYS_execve"))
.subcommand(clap::App::new("SYS_vfork"))
.subcommand(clap::App::new("SYS_fork"))
.subcommand(clap::App::new("SYS_clone"))
.subcommand(clap::App::new("SYS_getsockopt"))
.subcommand(clap::App::new("SYS_setsockopt"))
.subcommand(clap::App::new("SYS_socketpair"))
.subcommand(clap::App::new("SYS_getpeername"))
.subcommand(clap::App::new("SYS_getsockname"))
.subcommand(clap::App::new("SYS_listen"))
.subcommand(clap::App::new("SYS_bind"))
.subcommand(clap::App::new("SYS_shutdown"))
.subcommand(clap::App::new("SYS_recvmsg"))
.subcommand(clap::App::new("SYS_sendmsg"))
.subcommand(clap::App::new("SYS_recvfrom"))
.subcommand(clap::App::new("SYS_sendto"))
.subcommand(clap::App::new("SYS_accept"))
.subcommand(clap::App::new("SYS_connect"))
.subcommand(clap::App::new("SYS_socket"))
.subcommand(clap::App::new("SYS_sendfile"))
.subcommand(clap::App::new("SYS_getpid"))
.subcommand(clap::App::new("SYS_setitimer"))
.subcommand(clap::App::new("SYS_alarm"))
.subcommand(clap::App::new("SYS_getitimer"))
.subcommand(clap::App::new("SYS_nanosleep"))
.subcommand(clap::App::new("SYS_pause"))
.subcommand(clap::App::new("SYS_dup2"))
.subcommand(clap::App::new("SYS_dup"))
.subcommand(clap::App::new("SYS_shmctl"))
.subcommand(clap::App::new("SYS_shmat"))
.subcommand(clap::App::new("SYS_shmget"))
.subcommand(clap::App::new("SYS_madvise"))
.subcommand(clap::App::new("SYS_mincore"))
.subcommand(clap::App::new("SYS_msync"))
.subcommand(clap::App::new("SYS_mremap"))
.subcommand(clap::App::new("SYS_sched_yield"))
.subcommand(clap::App::new("SYS_select"))
.subcommand(clap::App::new("SYS_pipe"))
.subcommand(clap::App::new("SYS_access"))
.subcommand(clap::App::new("SYS_writev"))
.subcommand(clap::App::new("SYS_readv"))
.subcommand(clap::App::new("SYS_pwrite64"))
.subcommand(clap::App::new("SYS_pread64"))
.subcommand(clap::App::new("SYS_ioctl"))
.subcommand(clap::App::new("SYS_rt_sigreturn"))
.subcommand(clap::App::new("SYS_rt_sigprocmask"))
.subcommand(clap::App::new("SYS_rt_sigaction"))
.subcommand(clap::App::new("SYS_brk"))
.subcommand(clap::App::new("SYS_munmap"))
.subcommand(clap::App::new("SYS_mprotect"))
.subcommand(clap::App::new("SYS_mmap"))
.subcommand(clap::App::new("SYS_lseek"))
.subcommand(clap::App::new("SYS_poll"))
.subcommand(clap::App::new("SYS_lstat"))
.subcommand(clap::App::new("SYS_fstat"))
.subcommand(clap::App::new("SYS_stat"))
.subcommand(clap::App::new("SYS_close"))
.subcommand(clap::App::new("SYS_open"))
.subcommand(clap::App::new("SYS_write"))
.subcommand(clap::App::new("SYS_read"))
.subcommand(clap::App::new("__SIZEOF_PTHREAD_RWLOCK_T"))
.subcommand(clap::App::new("__SIZEOF_PTHREAD_MUTEX_T"))
.subcommand(clap::App::new("REG_CR2"))
.subcommand(clap::App::new("REG_OLDMASK"))
.subcommand(clap::App::new("REG_TRAPNO"))
.subcommand(clap::App::new("REG_ERR"))
.subcommand(clap::App::new("REG_CSGSFS"))
.subcommand(clap::App::new("REG_EFL"))
.subcommand(clap::App::new("REG_RIP"))
.subcommand(clap::App::new("REG_RSP"))
.subcommand(clap::App::new("REG_RCX"))
.subcommand(clap::App::new("REG_RAX"))
.subcommand(clap::App::new("REG_RDX"))
.subcommand(clap::App::new("REG_RBX"))
.subcommand(clap::App::new("REG_RBP"))
.subcommand(clap::App::new("REG_RSI"))
.subcommand(clap::App::new("REG_RDI"))
.subcommand(clap::App::new("REG_R15"))
.subcommand(clap::App::new("REG_R14"))
.subcommand(clap::App::new("REG_R13"))
.subcommand(clap::App::new("REG_R12"))
.subcommand(clap::App::new("REG_R11"))
.subcommand(clap::App::new("REG_R10"))
.subcommand(clap::App::new("REG_R9"))
.subcommand(clap::App::new("REG_R8"))
.subcommand(clap::App::new("GS"))
.subcommand(clap::App::new("FS"))
.subcommand(clap::App::new("ES"))
.subcommand(clap::App::new("DS"))
.subcommand(clap::App::new("GS_BASE"))
.subcommand(clap::App::new("FS_BASE"))
.subcommand(clap::App::new("SS"))
.subcommand(clap::App::new("RSP"))
.subcommand(clap::App::new("EFLAGS"))
.subcommand(clap::App::new("CS"))
.subcommand(clap::App::new("RIP"))
.subcommand(clap::App::new("ORIG_RAX"))
.subcommand(clap::App::new("RDI"))
.subcommand(clap::App::new("RSI"))
.subcommand(clap::App::new("RDX"))
.subcommand(clap::App::new("RCX"))
.subcommand(clap::App::new("RAX"))
.subcommand(clap::App::new("R8"))
.subcommand(clap::App::new("R9"))
.subcommand(clap::App::new("R10"))
.subcommand(clap::App::new("R11"))
.subcommand(clap::App::new("RBX"))
.subcommand(clap::App::new("RBP"))
.subcommand(clap::App::new("R12"))
.subcommand(clap::App::new("R13"))
.subcommand(clap::App::new("R14"))
.subcommand(clap::App::new("R15"))
.subcommand(clap::App::new("FIONREAD"))
.subcommand(clap::App::new("TIOCSWINSZ"))
.subcommand(clap::App::new("TIOCGWINSZ"))
.subcommand(clap::App::new("TIOCOUTQ"))
.subcommand(clap::App::new("TIOCSPGRP"))
.subcommand(clap::App::new("TIOCGPGRP"))
.subcommand(clap::App::new("TIOCINQ"))
.subcommand(clap::App::new("TCFLSH"))
.subcommand(clap::App::new("TCXONC"))
.subcommand(clap::App::new("TCSBRK"))
.subcommand(clap::App::new("TCSETAF"))
.subcommand(clap::App::new("TCSETAW"))
.subcommand(clap::App::new("TCSETA"))
.subcommand(clap::App::new("TCGETA"))
.subcommand(clap::App::new("TCSETSF"))
.subcommand(clap::App::new("TCSETSW"))
.subcommand(clap::App::new("TCSETS"))
.subcommand(clap::App::new("TCGETS"))
.subcommand(clap::App::new("EXTPROC"))
.subcommand(clap::App::new("FLUSHO"))
.subcommand(clap::App::new("TOSTOP"))
.subcommand(clap::App::new("IEXTEN"))
.subcommand(clap::App::new("VMIN"))
.subcommand(clap::App::new("VEOL2"))
.subcommand(clap::App::new("VEOL"))
.subcommand(clap::App::new("B4000000"))
.subcommand(clap::App::new("B3500000"))
.subcommand(clap::App::new("B3000000"))
.subcommand(clap::App::new("B2500000"))
.subcommand(clap::App::new("B2000000"))
.subcommand(clap::App::new("B1500000"))
.subcommand(clap::App::new("B1152000"))
.subcommand(clap::App::new("B1000000"))
.subcommand(clap::App::new("B921600"))
.subcommand(clap::App::new("B576000"))
.subcommand(clap::App::new("B500000"))
.subcommand(clap::App::new("B460800"))
.subcommand(clap::App::new("B230400"))
.subcommand(clap::App::new("B115200"))
.subcommand(clap::App::new("B57600"))
.subcommand(clap::App::new("BOTHER"))
.subcommand(clap::App::new("EXTB"))
.subcommand(clap::App::new("EXTA"))
.subcommand(clap::App::new("B38400"))
.subcommand(clap::App::new("B19200"))
.subcommand(clap::App::new("B9600"))
.subcommand(clap::App::new("B4800"))
.subcommand(clap::App::new("B2400"))
.subcommand(clap::App::new("B1800"))
.subcommand(clap::App::new("B1200"))
.subcommand(clap::App::new("B600"))
.subcommand(clap::App::new("B300"))
.subcommand(clap::App::new("B200"))
.subcommand(clap::App::new("B150"))
.subcommand(clap::App::new("B134"))
.subcommand(clap::App::new("B110"))
.subcommand(clap::App::new("B75"))
.subcommand(clap::App::new("B50"))
.subcommand(clap::App::new("B0"))
.subcommand(clap::App::new("XTABS"))
.subcommand(clap::App::new("VTDLY"))
.subcommand(clap::App::new("FFDLY"))
.subcommand(clap::App::new("BSDLY"))
.subcommand(clap::App::new("TABDLY"))
.subcommand(clap::App::new("CRDLY"))
.subcommand(clap::App::new("NLDLY"))
.subcommand(clap::App::new("OLCUC"))
.subcommand(clap::App::new("VSWTC"))
.subcommand(clap::App::new("CBAUDEX"))
.subcommand(clap::App::new("CIBAUD"))
.subcommand(clap::App::new("NOFLSH"))
.subcommand(clap::App::new("PENDIN"))
.subcommand(clap::App::new("ICANON"))
.subcommand(clap::App::new("ISIG"))
.subcommand(clap::App::new("ECHOCTL"))
.subcommand(clap::App::new("ECHOPRT"))
.subcommand(clap::App::new("ECHONL"))
.subcommand(clap::App::new("ECHOK"))
.subcommand(clap::App::new("ECHOE"))
.subcommand(clap::App::new("ECHOKE"))
.subcommand(clap::App::new("CLOCAL"))
.subcommand(clap::App::new("HUPCL"))
.subcommand(clap::App::new("PARODD"))
.subcommand(clap::App::new("PARENB"))
.subcommand(clap::App::new("CREAD"))
.subcommand(clap::App::new("CSTOPB"))
.subcommand(clap::App::new("CS8"))
.subcommand(clap::App::new("CS7"))
.subcommand(clap::App::new("CS6"))
.subcommand(clap::App::new("CSIZE"))
.subcommand(clap::App::new("ONLCR"))
.subcommand(clap::App::new("IXOFF"))
.subcommand(clap::App::new("IXON"))
.subcommand(clap::App::new("VTIME"))
.subcommand(clap::App::new("VDISCARD"))
.subcommand(clap::App::new("VSTOP"))
.subcommand(clap::App::new("VSTART"))
.subcommand(clap::App::new("VSUSP"))
.subcommand(clap::App::new("VREPRINT"))
.subcommand(clap::App::new("VWERASE"))
.subcommand(clap::App::new("VT1"))
.subcommand(clap::App::new("BS1"))
.subcommand(clap::App::new("FF1"))
.subcommand(clap::App::new("CR3"))
.subcommand(clap::App::new("CR2"))
.subcommand(clap::App::new("CR1"))
.subcommand(clap::App::new("TAB3"))
.subcommand(clap::App::new("TAB2"))
.subcommand(clap::App::new("TAB1"))
.subcommand(clap::App::new("CBAUD"))
.subcommand(clap::App::new("MINSIGSTKSZ"))
.subcommand(clap::App::new("SIGSTKSZ"))
.subcommand(clap::App::new("MCL_FUTURE"))
.subcommand(clap::App::new("MCL_CURRENT"))
.subcommand(clap::App::new("PTRACE_PEEKSIGINFO_SHARED"))
.subcommand(clap::App::new("PTRACE_SETREGS"))
.subcommand(clap::App::new("PTRACE_GETREGS"))
.subcommand(clap::App::new("PTRACE_SETFPXREGS"))
.subcommand(clap::App::new("PTRACE_GETFPXREGS"))
.subcommand(clap::App::new("PTRACE_SETFPREGS"))
.subcommand(clap::App::new("PTRACE_GETFPREGS"))
.subcommand(clap::App::new("FIONBIO"))
.subcommand(clap::App::new("FIONCLEX"))
.subcommand(clap::App::new("FIOCLEX"))
.subcommand(clap::App::new("EREMOTEIO"))
.subcommand(clap::App::new("EISNAM"))
.subcommand(clap::App::new("ENAVAIL"))
.subcommand(clap::App::new("ENOTNAM"))
.subcommand(clap::App::new("EUCLEAN"))
.subcommand(clap::App::new("EDEADLOCK"))
.subcommand(clap::App::new("MAP_SYNC"))
.subcommand(clap::App::new("MAP_STACK"))
.subcommand(clap::App::new("MAP_NONBLOCK"))
.subcommand(clap::App::new("MAP_POPULATE"))
.subcommand(clap::App::new("MAP_EXECUTABLE"))
.subcommand(clap::App::new("MAP_DENYWRITE"))
.subcommand(clap::App::new("MAP_ANONYMOUS"))
.subcommand(clap::App::new("MAP_ANON"))
.subcommand(clap::App::new("MAP_32BIT"))
.subcommand(clap::App::new("MAP_NORESERVE"))
.subcommand(clap::App::new("MAP_LOCKED"))
.subcommand(clap::App::new("MAP_HUGETLB"))
.subcommand(clap::App::new("O_NOFOLLOW"))
.subcommand(clap::App::new("O_DIRECTORY"))
.subcommand(clap::App::new("O_DIRECT"))
.subcommand(clap::App::new("__SIZEOF_PTHREAD_MUTEXATTR_T"))
.subcommand(clap::App::new("__SIZEOF_PTHREAD_CONDATTR_T"))
.subcommand(clap::App::new("EFD_CLOEXEC"))
.subcommand(clap::App::new("EPOLL_CLOEXEC"))
.subcommand(clap::App::new("SA_NOCLDSTOP"))
.subcommand(clap::App::new("SA_RESTART"))
.subcommand(clap::App::new("SA_RESETHAND"))
.subcommand(clap::App::new("SA_NODEFER"))
.subcommand(clap::App::new("EDOTDOT"))
.subcommand(clap::App::new("EPROTO"))
.subcommand(clap::App::new("ECOMM"))
.subcommand(clap::App::new("ESRMNT"))
.subcommand(clap::App::new("EADV"))
.subcommand(clap::App::new("ENOLINK"))
.subcommand(clap::App::new("EREMOTE"))
.subcommand(clap::App::new("ENOPKG"))
.subcommand(clap::App::new("ENONET"))
.subcommand(clap::App::new("ENOSR"))
.subcommand(clap::App::new("ETIME"))
.subcommand(clap::App::new("ENODATA"))
.subcommand(clap::App::new("ENOSTR"))
.subcommand(clap::App::new("EBFONT"))
.subcommand(clap::App::new("O_CLOEXEC"))
.subcommand(clap::App::new("O_TRUNC"))
.subcommand(clap::App::new("NCCS"))
.subcommand(clap::App::new("SFD_CLOEXEC"))
.subcommand(clap::App::new("TIOCM_DSR"))
.subcommand(clap::App::new("TIOCM_RNG"))
.subcommand(clap::App::new("TIOCM_CAR"))
.subcommand(clap::App::new("TIOCM_CTS"))
.subcommand(clap::App::new("TIOCM_SR"))
.subcommand(clap::App::new("TIOCM_ST"))
.subcommand(clap::App::new("TIOCCONS"))
.subcommand(clap::App::new("TIOCMSET"))
.subcommand(clap::App::new("TIOCMBIC"))
.subcommand(clap::App::new("TIOCMBIS"))
.subcommand(clap::App::new("TIOCMGET"))
.subcommand(clap::App::new("TIOCSTI"))
.subcommand(clap::App::new("TIOCSCTTY"))
.subcommand(clap::App::new("TIOCNXCL"))
.subcommand(clap::App::new("TIOCEXCL"))
.subcommand(clap::App::new("TIOCGSERIAL"))
.subcommand(clap::App::new("TIOCLINUX"))
.subcommand(clap::App::new("TCSAFLUSH"))
.subcommand(clap::App::new("TCSADRAIN"))
.subcommand(clap::App::new("TCSANOW"))
.subcommand(clap::App::new("SFD_NONBLOCK"))
.subcommand(clap::App::new("F_UNLCK"))
.subcommand(clap::App::new("F_WRLCK"))
.subcommand(clap::App::new("F_RDLCK"))
.subcommand(clap::App::new("F_OFD_SETLKW"))
.subcommand(clap::App::new("F_OFD_SETLK"))
.subcommand(clap::App::new("F_OFD_GETLK"))
.subcommand(clap::App::new("F_SETLKW"))
.subcommand(clap::App::new("F_SETLK"))
.subcommand(clap::App::new("F_SETOWN"))
.subcommand(clap::App::new("F_GETOWN"))
.subcommand(clap::App::new("F_GETLK"))
.subcommand(clap::App::new("EFD_NONBLOCK"))
.subcommand(clap::App::new("PTRACE_DETACH"))
.subcommand(clap::App::new("O_NDELAY"))
.subcommand(clap::App::new("O_ASYNC"))
.subcommand(clap::App::new("POLLWRBAND"))
.subcommand(clap::App::new("POLLWRNORM"))
.subcommand(clap::App::new("SIG_UNBLOCK"))
.subcommand(clap::App::new("SIG_BLOCK"))
.subcommand(clap::App::new("SIG_SETMASK"))
.subcommand(clap::App::new("SIGPWR"))
.subcommand(clap::App::new("SIGPOLL"))
.subcommand(clap::App::new("SIGUNUSED"))
.subcommand(clap::App::new("SIGSTKFLT"))
.subcommand(clap::App::new("SIGSYS"))
.subcommand(clap::App::new("SIGIO"))
.subcommand(clap::App::new("SIGURG"))
.subcommand(clap::App::new("SIGTSTP"))
.subcommand(clap::App::new("SIGSTOP"))
.subcommand(clap::App::new("SIGCONT"))
.subcommand(clap::App::new("SIGUSR2"))
.subcommand(clap::App::new("SIGUSR1"))
.subcommand(clap::App::new("SIGBUS"))
.subcommand(clap::App::new("SIGCHLD"))
.subcommand(clap::App::new("SIGWINCH"))
.subcommand(clap::App::new("SIGPROF"))
.subcommand(clap::App::new("SIGVTALRM"))
.subcommand(clap::App::new("SIGXFSZ"))
.subcommand(clap::App::new("SIGXCPU"))
.subcommand(clap::App::new("SIGTTOU"))
.subcommand(clap::App::new("SIGTTIN"))
.subcommand(clap::App::new("SA_NOCLDWAIT"))
.subcommand(clap::App::new("SA_SIGINFO"))
.subcommand(clap::App::new("SA_ONSTACK"))
.subcommand(clap::App::new("SOCK_DGRAM"))
.subcommand(clap::App::new("SOCK_STREAM"))
.subcommand(clap::App::new("SO_DETACH_BPF"))
.subcommand(clap::App::new("SO_ATTACH_BPF"))
.subcommand(clap::App::new("SO_INCOMING_CPU"))
.subcommand(clap::App::new("SO_BPF_EXTENSIONS"))
.subcommand(clap::App::new("SO_MAX_PACING_RATE"))
.subcommand(clap::App::new("SO_BUSY_POLL"))
.subcommand(clap::App::new("SO_SELECT_ERR_QUEUE"))
.subcommand(clap::App::new("SO_LOCK_FILTER"))
.subcommand(clap::App::new("SO_NOFCS"))
.subcommand(clap::App::new("SO_PEEK_OFF"))
.subcommand(clap::App::new("SCM_WIFI_STATUS"))
.subcommand(clap::App::new("SO_WIFI_STATUS"))
.subcommand(clap::App::new("SO_RXQ_OVFL"))
.subcommand(clap::App::new("SO_DOMAIN"))
.subcommand(clap::App::new("SO_PROTOCOL"))
.subcommand(clap::App::new("SO_MARK"))
.subcommand(clap::App::new("SCM_TIMESTAMPNS"))
.subcommand(clap::App::new("SO_TIMESTAMPNS"))
.subcommand(clap::App::new("SO_PASSSEC"))
.subcommand(clap::App::new("SO_PEERSEC"))
.subcommand(clap::App::new("SO_ACCEPTCONN"))
.subcommand(clap::App::new("SO_TIMESTAMP"))
.subcommand(clap::App::new("SO_PEERNAME"))
.subcommand(clap::App::new("SO_GET_FILTER"))
.subcommand(clap::App::new("SO_DETACH_FILTER"))
.subcommand(clap::App::new("SO_ATTACH_FILTER"))
.subcommand(clap::App::new("SO_BINDTODEVICE"))
.subcommand(clap::App::new("SO_SECURITY_ENCRYPTION_NETWORK"))
.subcommand(clap::App::new("SO_SECURITY_ENCRYPTION_TRANSPORT"))
.subcommand(clap::App::new("SO_SECURITY_AUTHENTICATION"))
.subcommand(clap::App::new("SO_SNDTIMEO"))
.subcommand(clap::App::new("SO_RCVTIMEO"))
.subcommand(clap::App::new("SO_SNDLOWAT"))
.subcommand(clap::App::new("SO_RCVLOWAT"))
.subcommand(clap::App::new("SO_PEERCRED"))
.subcommand(clap::App::new("SO_PASSCRED"))
.subcommand(clap::App::new("SO_REUSEPORT"))
.subcommand(clap::App::new("SO_BSDCOMPAT"))
.subcommand(clap::App::new("SO_LINGER"))
.subcommand(clap::App::new("SO_PRIORITY"))
.subcommand(clap::App::new("SO_NO_CHECK"))
.subcommand(clap::App::new("SO_OOBINLINE"))
.subcommand(clap::App::new("SO_KEEPALIVE"))
.subcommand(clap::App::new("SO_RCVBUFFORCE"))
.subcommand(clap::App::new("SO_SNDBUFFORCE"))
.subcommand(clap::App::new("SO_RCVBUF"))
.subcommand(clap::App::new("SO_SNDBUF"))
.subcommand(clap::App::new("SO_BROADCAST"))
.subcommand(clap::App::new("SO_DONTROUTE"))
.subcommand(clap::App::new("SO_ERROR"))
.subcommand(clap::App::new("SO_TYPE"))
.subcommand(clap::App::new("SO_REUSEADDR"))
.subcommand(clap::App::new("SOL_SOCKET"))
.subcommand(clap::App::new("ERFKILL"))
.subcommand(clap::App::new("EHWPOISON"))
.subcommand(clap::App::new("ENOTRECOVERABLE"))
.subcommand(clap::App::new("EOWNERDEAD"))
.subcommand(clap::App::new("EKEYREJECTED"))
.subcommand(clap::App::new("EKEYREVOKED"))
.subcommand(clap::App::new("EKEYEXPIRED"))
.subcommand(clap::App::new("ENOKEY"))
.subcommand(clap::App::new("ECANCELED"))
.subcommand(clap::App::new("EMEDIUMTYPE"))
.subcommand(clap::App::new("ENOMEDIUM"))
.subcommand(clap::App::new("EDQUOT"))
.subcommand(clap::App::new("ESTALE"))
.subcommand(clap::App::new("EINPROGRESS"))
.subcommand(clap::App::new("EALREADY"))
.subcommand(clap::App::new("EHOSTUNREACH"))
.subcommand(clap::App::new("EHOSTDOWN"))
.subcommand(clap::App::new("ECONNREFUSED"))
.subcommand(clap::App::new("ETIMEDOUT"))
.subcommand(clap::App::new("ETOOMANYREFS"))
.subcommand(clap::App::new("ESHUTDOWN"))
.subcommand(clap::App::new("ENOTCONN"))
.subcommand(clap::App::new("EISCONN"))
.subcommand(clap::App::new("ENOBUFS"))
.subcommand(clap::App::new("ECONNRESET"))
.subcommand(clap::App::new("ECONNABORTED"))
.subcommand(clap::App::new("ENETRESET"))
.subcommand(clap::App::new("ENETUNREACH"))
.subcommand(clap::App::new("ENETDOWN"))
.subcommand(clap::App::new("EADDRNOTAVAIL"))
.subcommand(clap::App::new("EADDRINUSE"))
.subcommand(clap::App::new("EAFNOSUPPORT"))
.subcommand(clap::App::new("EPFNOSUPPORT"))
.subcommand(clap::App::new("EOPNOTSUPP"))
.subcommand(clap::App::new("ESOCKTNOSUPPORT"))
.subcommand(clap::App::new("EPROTONOSUPPORT"))
.subcommand(clap::App::new("ENOPROTOOPT"))
.subcommand(clap::App::new("EPROTOTYPE"))
.subcommand(clap::App::new("EMSGSIZE"))
.subcommand(clap::App::new("EDESTADDRREQ"))
.subcommand(clap::App::new("ENOTSOCK"))
.subcommand(clap::App::new("EUSERS"))
.subcommand(clap::App::new("ESTRPIPE"))
.subcommand(clap::App::new("ERESTART"))
.subcommand(clap::App::new("EILSEQ"))
.subcommand(clap::App::new("ELIBEXEC"))
.subcommand(clap::App::new("ELIBMAX"))
.subcommand(clap::App::new("ELIBSCN"))
.subcommand(clap::App::new("ELIBBAD"))
.subcommand(clap::App::new("ELIBACC"))
.subcommand(clap::App::new("EREMCHG"))
.subcommand(clap::App::new("EBADMSG"))
.subcommand(clap::App::new("EBADFD"))
.subcommand(clap::App::new("ENOTUNIQ"))
.subcommand(clap::App::new("EOVERFLOW"))
.subcommand(clap::App::new("EMULTIHOP"))
.subcommand(clap::App::new("EBADSLT"))
.subcommand(clap::App::new("EBADRQC"))
.subcommand(clap::App::new("ENOANO"))
.subcommand(clap::App::new("EXFULL"))
.subcommand(clap::App::new("EBADR"))
.subcommand(clap::App::new("EBADE"))
.subcommand(clap::App::new("EL2HLT"))
.subcommand(clap::App::new("ENOCSI"))
.subcommand(clap::App::new("EUNATCH"))
.subcommand(clap::App::new("ELNRNG"))
.subcommand(clap::App::new("EL3RST"))
.subcommand(clap::App::new("EL3HLT"))
.subcommand(clap::App::new("EL2NSYNC"))
.subcommand(clap::App::new("ECHRNG"))
.subcommand(clap::App::new("EIDRM"))
.subcommand(clap::App::new("ENOMSG"))
.subcommand(clap::App::new("ELOOP"))
.subcommand(clap::App::new("ENOTEMPTY"))
.subcommand(clap::App::new("ENOSYS"))
.subcommand(clap::App::new("ENOLCK"))
.subcommand(clap::App::new("ENAMETOOLONG"))
.subcommand(clap::App::new("EDEADLK"))
.subcommand(clap::App::new("MAP_GROWSDOWN"))
.subcommand(clap::App::new("MADV_SOFT_OFFLINE"))
.subcommand(clap::App::new("O_TMPFILE"))
.subcommand(clap::App::new("O_PATH"))
.subcommand(clap::App::new("O_NOATIME"))
.subcommand(clap::App::new("O_FSYNC"))
.subcommand(clap::App::new("O_DSYNC"))
.subcommand(clap::App::new("O_RSYNC"))
.subcommand(clap::App::new("O_SYNC"))
.subcommand(clap::App::new("O_NONBLOCK"))
.subcommand(clap::App::new("O_NOCTTY"))
.subcommand(clap::App::new("O_EXCL"))
.subcommand(clap::App::new("O_CREAT"))
.subcommand(clap::App::new("O_APPEND"))
.subcommand(clap::App::new("RLIMIT_NPROC"))
.subcommand(clap::App::new("RLIMIT_NOFILE"))
.subcommand(clap::App::new("RLIMIT_MEMLOCK"))
.subcommand(clap::App::new("RLIMIT_AS"))
.subcommand(clap::App::new("RLIMIT_RSS"))
.subcommand(clap::App::new("TIOCSRS485"))
.subcommand(clap::App::new("TIOCGRS485"))
.subcommand(clap::App::new("TIOCSSOFTCAR"))
.subcommand(clap::App::new("TIOCGSOFTCAR"))
.subcommand(clap::App::new("RTLD_NOLOAD"))
.subcommand(clap::App::new("RTLD_GLOBAL"))
.subcommand(clap::App::new("RTLD_DEEPBIND"))
.subcommand(clap::App::new("VEOF"))
.subcommand(clap::App::new("POSIX_FADV_NOREUSE"))
.subcommand(clap::App::new("POSIX_FADV_DONTNEED"))
.subcommand(clap::App::new("O_LARGEFILE"))
.subcommand(clap::App::new("__SIZEOF_PTHREAD_RWLOCKATTR_T"))
.subcommand(clap::App::new("RLIM_INFINITY"))
.subcommand(clap::App::new("REG_ERPAREN"))
.subcommand(clap::App::new("REG_ESIZE"))
.subcommand(clap::App::new("REG_EEND"))
.subcommand(clap::App::new("REG_STARTEND"))
.subcommand(clap::App::new("PTHREAD_MUTEX_ADAPTIVE_NP"))
.subcommand(clap::App::new("PTHREAD_STACK_MIN"))
.subcommand(clap::App::new("MAXTC"))
.subcommand(clap::App::new("TIME_BAD"))
.subcommand(clap::App::new("TIME_ERROR"))
.subcommand(clap::App::new("TIME_WAIT"))
.subcommand(clap::App::new("TIME_OOP"))
.subcommand(clap::App::new("TIME_DEL"))
.subcommand(clap::App::new("TIME_INS"))
.subcommand(clap::App::new("TIME_OK"))
.subcommand(clap::App::new("NTP_API"))
.subcommand(clap::App::new("STA_RONLY"))
.subcommand(clap::App::new("STA_CLK"))
.subcommand(clap::App::new("STA_MODE"))
.subcommand(clap::App::new("STA_NANO"))
.subcommand(clap::App::new("STA_CLOCKERR"))
.subcommand(clap::App::new("STA_PPSERROR"))
.subcommand(clap::App::new("STA_PPSWANDER"))
.subcommand(clap::App::new("STA_PPSJITTER"))
.subcommand(clap::App::new("STA_PPSSIGNAL"))
.subcommand(clap::App::new("STA_FREQHOLD"))
.subcommand(clap::App::new("STA_UNSYNC"))
.subcommand(clap::App::new("STA_DEL"))
.subcommand(clap::App::new("STA_INS"))
.subcommand(clap::App::new("STA_FLL"))
.subcommand(clap::App::new("STA_PPSTIME"))
.subcommand(clap::App::new("STA_PPSFREQ"))
.subcommand(clap::App::new("STA_PLL"))
.subcommand(clap::App::new("MOD_NANO"))
.subcommand(clap::App::new("MOD_MICRO"))
.subcommand(clap::App::new("MOD_TAI"))
.subcommand(clap::App::new("MOD_CLKA"))
.subcommand(clap::App::new("MOD_CLKB"))
.subcommand(clap::App::new("MOD_TIMECONST"))
.subcommand(clap::App::new("MOD_STATUS"))
.subcommand(clap::App::new("MOD_ESTERROR"))
.subcommand(clap::App::new("MOD_MAXERROR"))
.subcommand(clap::App::new("MOD_FREQUENCY"))
.subcommand(clap::App::new("MOD_OFFSET"))
.subcommand(clap::App::new("ADJ_OFFSET_SS_READ"))
.subcommand(clap::App::new("ADJ_OFFSET_SINGLESHOT"))
.subcommand(clap::App::new("ADJ_TICK"))
.subcommand(clap::App::new("ADJ_NANO"))
.subcommand(clap::App::new("ADJ_MICRO"))
.subcommand(clap::App::new("ADJ_SETOFFSET"))
.subcommand(clap::App::new("ADJ_TAI"))
.subcommand(clap::App::new("ADJ_TIMECONST"))
.subcommand(clap::App::new("ADJ_STATUS"))
.subcommand(clap::App::new("ADJ_ESTERROR"))
.subcommand(clap::App::new("ADJ_MAXERROR"))
.subcommand(clap::App::new("ADJ_FREQUENCY"))
.subcommand(clap::App::new("ADJ_OFFSET"))
.subcommand(clap::App::new("AT_EXECFN"))
.subcommand(clap::App::new("AT_HWCAP2"))
.subcommand(clap::App::new("AT_RANDOM"))
.subcommand(clap::App::new("AT_BASE_PLATFORM"))
.subcommand(clap::App::new("AT_SECURE"))
.subcommand(clap::App::new("AT_CLKTCK"))
.subcommand(clap::App::new("AT_HWCAP"))
.subcommand(clap::App::new("AT_PLATFORM"))
.subcommand(clap::App::new("AT_EGID"))
.subcommand(clap::App::new("AT_GID"))
.subcommand(clap::App::new("AT_EUID"))
.subcommand(clap::App::new("AT_UID"))
.subcommand(clap::App::new("AT_NOTELF"))
.subcommand(clap::App::new("AT_ENTRY"))
.subcommand(clap::App::new("AT_FLAGS"))
.subcommand(clap::App::new("AT_BASE"))
.subcommand(clap::App::new("AT_PAGESZ"))
.subcommand(clap::App::new("AT_PHNUM"))
.subcommand(clap::App::new("AT_PHENT"))
.subcommand(clap::App::new("AT_PHDR"))
.subcommand(clap::App::new("AT_EXECFD"))
.subcommand(clap::App::new("AT_IGNORE"))
.subcommand(clap::App::new("AT_NULL"))
.subcommand(clap::App::new("STATX_ATTR_AUTOMOUNT"))
.subcommand(clap::App::new("STATX_ATTR_ENCRYPTED"))
.subcommand(clap::App::new("STATX_ATTR_NODUMP"))
.subcommand(clap::App::new("STATX_ATTR_APPEND"))
.subcommand(clap::App::new("STATX_ATTR_IMMUTABLE"))
.subcommand(clap::App::new("STATX_ATTR_COMPRESSED"))
.subcommand(clap::App::new("STATX__RESERVED"))
.subcommand(clap::App::new("STATX_ALL"))
.subcommand(clap::App::new("STATX_BTIME"))
.subcommand(clap::App::new("STATX_BASIC_STATS"))
.subcommand(clap::App::new("STATX_BLOCKS"))
.subcommand(clap::App::new("STATX_SIZE"))
.subcommand(clap::App::new("STATX_INO"))
.subcommand(clap::App::new("STATX_CTIME"))
.subcommand(clap::App::new("STATX_MTIME"))
.subcommand(clap::App::new("STATX_ATIME"))
.subcommand(clap::App::new("STATX_GID"))
.subcommand(clap::App::new("STATX_UID"))
.subcommand(clap::App::new("STATX_NLINK"))
.subcommand(clap::App::new("STATX_MODE"))
.subcommand(clap::App::new("STATX_TYPE"))
.subcommand(clap::App::new("AT_STATX_DONT_SYNC"))
.subcommand(clap::App::new("AT_STATX_FORCE_SYNC"))
.subcommand(clap::App::new("AT_STATX_SYNC_AS_STAT"))
.subcommand(clap::App::new("AT_STATX_SYNC_TYPE"))
.subcommand(clap::App::new("M_ARENA_MAX"))
.subcommand(clap::App::new("M_ARENA_TEST"))
.subcommand(clap::App::new("M_PERTURB"))
.subcommand(clap::App::new("M_CHECK_ACTION"))
.subcommand(clap::App::new("M_MMAP_MAX"))
.subcommand(clap::App::new("M_MMAP_THRESHOLD"))
.subcommand(clap::App::new("M_TOP_PAD"))
.subcommand(clap::App::new("M_TRIM_THRESHOLD"))
.subcommand(clap::App::new("M_KEEP"))
.subcommand(clap::App::new("M_GRAIN"))
.subcommand(clap::App::new("M_NLBLKS"))
.subcommand(clap::App::new("M_MXFAST"))
.subcommand(clap::App::new("NFT_NG_RANDOM"))
.subcommand(clap::App::new("NFT_NG_INCREMENTAL"))
.subcommand(clap::App::new("NFT_TRACETYPE_RULE"))
.subcommand(clap::App::new("NFT_TRACETYPE_RETURN"))
.subcommand(clap::App::new("NFT_TRACETYPE_POLICY"))
.subcommand(clap::App::new("NFT_TRACETYPE_UNSPEC"))
.subcommand(clap::App::new("NFT_NAT_DNAT"))
.subcommand(clap::App::new("NFT_NAT_SNAT"))
.subcommand(clap::App::new("NFT_REJECT_ICMPX_ADMIN_PROHIBITED"))
.subcommand(clap::App::new("NFT_REJECT_ICMPX_HOST_UNREACH"))
.subcommand(clap::App::new("NFT_REJECT_ICMPX_PORT_UNREACH"))
.subcommand(clap::App::new("NFT_REJECT_ICMPX_NO_ROUTE"))
.subcommand(clap::App::new("NFT_REJECT_ICMPX_UNREACH"))
.subcommand(clap::App::new("NFT_REJECT_TCP_RST"))
.subcommand(clap::App::new("NFT_REJECT_ICMP_UNREACH"))
.subcommand(clap::App::new("NFT_QUOTA_F_INV"))
.subcommand(clap::App::new("NFT_QUEUE_FLAG_MASK"))
.subcommand(clap::App::new("NFT_QUEUE_FLAG_CPU_FANOUT"))
.subcommand(clap::App::new("NFT_QUEUE_FLAG_BYPASS"))
.subcommand(clap::App::new("NFT_LIMIT_F_INV"))
.subcommand(clap::App::new("NFT_LIMIT_PKT_BYTES"))
.subcommand(clap::App::new("NFT_LIMIT_PKTS"))
.subcommand(clap::App::new("NFT_CT_BYTES"))
.subcommand(clap::App::new("NFT_CT_PKTS"))
.subcommand(clap::App::new("NFT_CT_LABELS"))
.subcommand(clap::App::new("NFT_CT_PROTO_DST"))
.subcommand(clap::App::new("NFT_CT_PROTO_SRC"))
.subcommand(clap::App::new("NFT_CT_PROTOCOL"))
.subcommand(clap::App::new("NFT_CT_DST"))
.subcommand(clap::App::new("NFT_CT_SRC"))
.subcommand(clap::App::new("NFT_CT_L3PROTOCOL"))
.subcommand(clap::App::new("NFT_CT_HELPER"))
.subcommand(clap::App::new("NFT_CT_EXPIRATION"))
.subcommand(clap::App::new("NFT_CT_SECMARK"))
.subcommand(clap::App::new("NFT_CT_MARK"))
.subcommand(clap::App::new("NFT_CT_STATUS"))
.subcommand(clap::App::new("NFT_CT_DIRECTION"))
.subcommand(clap::App::new("NFT_CT_STATE"))
.subcommand(clap::App::new("NFT_META_PRANDOM"))
.subcommand(clap::App::new("NFT_META_CGROUP"))
.subcommand(clap::App::new("NFT_META_OIFGROUP"))
.subcommand(clap::App::new("NFT_META_IIFGROUP"))
.subcommand(clap::App::new("NFT_META_CPU"))
.subcommand(clap::App::new("NFT_META_PKTTYPE"))
.subcommand(clap::App::new("NFT_META_BRI_OIFNAME"))
.subcommand(clap::App::new("NFT_META_BRI_IIFNAME"))
.subcommand(clap::App::new("NFT_META_L4PROTO"))
.subcommand(clap::App::new("NFT_META_NFPROTO"))
.subcommand(clap::App::new("NFT_META_SECMARK"))
.subcommand(clap::App::new("NFT_META_RTCLASSID"))
.subcommand(clap::App::new("NFT_META_NFTRACE"))
.subcommand(clap::App::new("NFT_META_SKGID"))
.subcommand(clap::App::new("NFT_META_SKUID"))
.subcommand(clap::App::new("NFT_META_OIFTYPE"))
.subcommand(clap::App::new("NFT_META_IIFTYPE"))
.subcommand(clap::App::new("NFT_META_OIFNAME"))
.subcommand(clap::App::new("NFT_META_IIFNAME"))
.subcommand(clap::App::new("NFT_META_OIF"))
.subcommand(clap::App::new("NFT_META_IIF"))
.subcommand(clap::App::new("NFT_META_MARK"))
.subcommand(clap::App::new("NFT_META_PRIORITY"))
.subcommand(clap::App::new("NFT_META_PROTOCOL"))
.subcommand(clap::App::new("NFT_META_LEN"))
.subcommand(clap::App::new("NFT_PAYLOAD_CSUM_INET"))
.subcommand(clap::App::new("NFT_PAYLOAD_CSUM_NONE"))
.subcommand(clap::App::new("NFT_PAYLOAD_TRANSPORT_HEADER"))
.subcommand(clap::App::new("NFT_PAYLOAD_NETWORK_HEADER"))
.subcommand(clap::App::new("NFT_PAYLOAD_LL_HEADER"))
.subcommand(clap::App::new("NFT_DYNSET_F_INV"))
.subcommand(clap::App::new("NFT_DYNSET_OP_UPDATE"))
.subcommand(clap::App::new("NFT_DYNSET_OP_ADD"))
.subcommand(clap::App::new("NFT_LOOKUP_F_INV"))
.subcommand(clap::App::new("NFT_RANGE_NEQ"))
.subcommand(clap::App::new("NFT_RANGE_EQ"))
.subcommand(clap::App::new("NFT_CMP_GTE"))
.subcommand(clap::App::new("NFT_CMP_GT"))
.subcommand(clap::App::new("NFT_CMP_LTE"))
.subcommand(clap::App::new("NFT_CMP_LT"))
.subcommand(clap::App::new("NFT_CMP_NEQ"))
.subcommand(clap::App::new("NFT_CMP_EQ"))
.subcommand(clap::App::new("NFT_BYTEORDER_HTON"))
.subcommand(clap::App::new("NFT_BYTEORDER_NTOH"))
.subcommand(clap::App::new("NFT_DATA_VALUE_MAXLEN"))
.subcommand(clap::App::new("NFT_DATA_RESERVED_MASK"))
.subcommand(clap::App::new("NFT_DATA_VERDICT"))
.subcommand(clap::App::new("NFT_DATA_VALUE"))
.subcommand(clap::App::new("NFT_SET_ELEM_INTERVAL_END"))
.subcommand(clap::App::new("NFT_SET_POL_MEMORY"))
.subcommand(clap::App::new("NFT_SET_POL_PERFORMANCE"))
.subcommand(clap::App::new("NFT_SET_EVAL"))
.subcommand(clap::App::new("NFT_SET_TIMEOUT"))
.subcommand(clap::App::new("NFT_SET_MAP"))
.subcommand(clap::App::new("NFT_SET_INTERVAL"))
.subcommand(clap::App::new("NFT_SET_CONSTANT"))
.subcommand(clap::App::new("NFT_SET_ANONYMOUS"))
.subcommand(clap::App::new("NFT_MSG_MAX"))
.subcommand(clap::App::new("NFT_MSG_GETOBJ_RESET"))
.subcommand(clap::App::new("NFT_MSG_DELOBJ"))
.subcommand(clap::App::new("NFT_MSG_GETOBJ"))
.subcommand(clap::App::new("NFT_MSG_NEWOBJ"))
.subcommand(clap::App::new("NFT_MSG_TRACE"))
.subcommand(clap::App::new("NFT_MSG_GETGEN"))
.subcommand(clap::App::new("NFT_MSG_NEWGEN"))
.subcommand(clap::App::new("NFT_MSG_DELSETELEM"))
.subcommand(clap::App::new("NFT_MSG_GETSETELEM"))
.subcommand(clap::App::new("NFT_MSG_NEWSETELEM"))
.subcommand(clap::App::new("NFT_MSG_DELSET"))
.subcommand(clap::App::new("NFT_MSG_GETSET"))
.subcommand(clap::App::new("NFT_MSG_NEWSET"))
.subcommand(clap::App::new("NFT_MSG_DELRULE"))
.subcommand(clap::App::new("NFT_MSG_GETRULE"))
.subcommand(clap::App::new("NFT_MSG_NEWRULE"))
.subcommand(clap::App::new("NFT_MSG_DELCHAIN"))
.subcommand(clap::App::new("NFT_MSG_GETCHAIN"))
.subcommand(clap::App::new("NFT_MSG_NEWCHAIN"))
.subcommand(clap::App::new("NFT_MSG_DELTABLE"))
.subcommand(clap::App::new("NFT_MSG_GETTABLE"))
.subcommand(clap::App::new("NFT_MSG_NEWTABLE"))
.subcommand(clap::App::new("NFT_RETURN"))
.subcommand(clap::App::new("NFT_GOTO"))
.subcommand(clap::App::new("NFT_JUMP"))
.subcommand(clap::App::new("NFT_BREAK"))
.subcommand(clap::App::new("NFT_CONTINUE"))
.subcommand(clap::App::new("NFT_REG32_SIZE"))
.subcommand(clap::App::new("NFT_REG_SIZE"))
.subcommand(clap::App::new("NFT_REG32_15"))
.subcommand(clap::App::new("NFT_REG32_14"))
.subcommand(clap::App::new("NFT_REG32_13"))
.subcommand(clap::App::new("NFT_REG32_12"))
.subcommand(clap::App::new("NFT_REG32_11"))
.subcommand(clap::App::new("NFT_REG32_10"))
.subcommand(clap::App::new("NFT_REG32_09"))
.subcommand(clap::App::new("NFT_REG32_08"))
.subcommand(clap::App::new("NFT_REG32_07"))
.subcommand(clap::App::new("NFT_REG32_06"))
.subcommand(clap::App::new("NFT_REG32_05"))
.subcommand(clap::App::new("NFT_REG32_04"))
.subcommand(clap::App::new("NFT_REG32_03"))
.subcommand(clap::App::new("NFT_REG32_02"))
.subcommand(clap::App::new("NFT_REG32_01"))
.subcommand(clap::App::new("NFT_REG32_00"))
.subcommand(clap::App::new("__NFT_REG_MAX"))
.subcommand(clap::App::new("NFT_REG_4"))
.subcommand(clap::App::new("NFT_REG_3"))
.subcommand(clap::App::new("NFT_REG_2"))
.subcommand(clap::App::new("NFT_REG_1"))
.subcommand(clap::App::new("NFT_REG_VERDICT"))
.subcommand(clap::App::new("NFT_USERDATA_MAXLEN"))
.subcommand(clap::App::new("NFT_OBJ_MAXNAMELEN"))
.subcommand(clap::App::new("NFT_SET_MAXNAMELEN"))
.subcommand(clap::App::new("NFT_CHAIN_MAXNAMELEN"))
.subcommand(clap::App::new("NFT_TABLE_MAXNAMELEN"))
.subcommand(clap::App::new("KEYCTL_CAPS1_NS_KEY_TAG"))
.subcommand(clap::App::new("KEYCTL_CAPS1_NS_KEYRING_NAME"))
.subcommand(clap::App::new("KEYCTL_CAPS0_MOVE"))
.subcommand(clap::App::new("KEYCTL_CAPS0_RESTRICT_KEYRING"))
.subcommand(clap::App::new("KEYCTL_CAPS0_INVALIDATE"))
.subcommand(clap::App::new("KEYCTL_CAPS0_BIG_KEY"))
.subcommand(clap::App::new("KEYCTL_CAPS0_PUBLIC_KEY"))
.subcommand(clap::App::new("KEYCTL_CAPS0_DIFFIE_HELLMAN"))
.subcommand(clap::App::new("KEYCTL_CAPS0_PERSISTENT_KEYRINGS"))
.subcommand(clap::App::new("KEYCTL_CAPS0_CAPABILITIES"))
.subcommand(clap::App::new("KEYCTL_CAPABILITIES"))
.subcommand(clap::App::new("KEYCTL_MOVE"))
.subcommand(clap::App::new("KEYCTL_SUPPORTS_VERIFY"))
.subcommand(clap::App::new("KEYCTL_SUPPORTS_SIGN"))
.subcommand(clap::App::new("KEYCTL_SUPPORTS_DECRYPT"))
.subcommand(clap::App::new("KEYCTL_SUPPORTS_ENCRYPT"))
.subcommand(clap::App::new("KEYCTL_RESTRICT_KEYRING"))
.subcommand(clap::App::new("KEYCTL_PKEY_VERIFY"))
.subcommand(clap::App::new("KEYCTL_PKEY_SIGN"))
.subcommand(clap::App::new("KEYCTL_PKEY_DECRYPT"))
.subcommand(clap::App::new("KEYCTL_PKEY_ENCRYPT"))
.subcommand(clap::App::new("KEYCTL_PKEY_QUERY"))
.subcommand(clap::App::new("KEYCTL_DH_COMPUTE"))
.subcommand(clap::App::new("NFPROTO_NETDEV"))
.subcommand(clap::App::new("NFPROTO_INET"))
.subcommand(clap::App::new("NF_NETDEV_NUMHOOKS"))
.subcommand(clap::App::new("NF_NETDEV_INGRESS"))
.subcommand(clap::App::new("TIOCM_RI"))
.subcommand(clap::App::new("TIOCM_CD"))
.subcommand(clap::App::new("TIOCM_RTS"))
.subcommand(clap::App::new("TIOCM_DTR"))
.subcommand(clap::App::new("TIOCM_LE"))
.subcommand(clap::App::new("GENL_ID_PMCRAID"))
.subcommand(clap::App::new("GENL_ID_VFS_DQUOT"))
.subcommand(clap::App::new("GENL_UNS_ADMIN_PERM"))
.subcommand(clap::App::new("MAX_LINKS"))
.subcommand(clap::App::new("IFA_F_STABLE_PRIVACY"))
.subcommand(clap::App::new("IFA_F_MCAUTOJOIN"))
.subcommand(clap::App::new("IFA_F_NOPREFIXROUTE"))
.subcommand(clap::App::new("IFA_F_MANAGETEMPADDR"))
.subcommand(clap::App::new("IFA_FLAGS"))
.subcommand(clap::App::new("NDA_SRC_VNI"))
.subcommand(clap::App::new("NDA_LINK_NETNSID"))
.subcommand(clap::App::new("NDA_MASTER"))
.subcommand(clap::App::new("NTF_OFFLOADED"))
.subcommand(clap::App::new("NTF_EXT_LEARNED"))
.subcommand(clap::App::new("RTA_TTL_PROPAGATE"))
.subcommand(clap::App::new("RTA_UID"))
.subcommand(clap::App::new("RTA_PAD"))
.subcommand(clap::App::new("RTA_EXPIRES"))
.subcommand(clap::App::new("RTA_ENCAP"))
.subcommand(clap::App::new("RTA_ENCAP_TYPE"))
.subcommand(clap::App::new("RTA_PREF"))
.subcommand(clap::App::new("RTA_NEWDST"))
.subcommand(clap::App::new("RTA_VIA"))
.subcommand(clap::App::new("RTM_F_FIB_MATCH"))
.subcommand(clap::App::new("RTM_F_LOOKUP_TABLE"))
.subcommand(clap::App::new("RTM_NEWCACHEREPORT"))
.subcommand(clap::App::new("RTM_GETSTATS"))
.subcommand(clap::App::new("RTM_NEWSTATS"))
.subcommand(clap::App::new("RTM_DELNETCONF"))
.subcommand(clap::App::new("TCA_HW_OFFLOAD"))
.subcommand(clap::App::new("TCA_CHAIN"))
.subcommand(clap::App::new("TCA_DUMP_INVISIBLE"))
.subcommand(clap::App::new("TCA_PAD"))
.subcommand(clap::App::new("SEEK_HOLE"))
.subcommand(clap::App::new("SEEK_DATA"))
.subcommand(clap::App::new("EPOLLWAKEUP"))
.subcommand(clap::App::new("PTRACE_PEEKSIGINFO"))
.subcommand(clap::App::new("PTRACE_LISTEN"))
.subcommand(clap::App::new("PTRACE_INTERRUPT"))
.subcommand(clap::App::new("PTRACE_SEIZE"))
.subcommand(clap::App::new("PTRACE_SETREGSET"))
.subcommand(clap::App::new("PTRACE_GETREGSET"))
.subcommand(clap::App::new("PTRACE_SETSIGINFO"))
.subcommand(clap::App::new("PTRACE_GETSIGINFO"))
.subcommand(clap::App::new("PTRACE_GETEVENTMSG"))
.subcommand(clap::App::new("PTRACE_SETOPTIONS"))
.subcommand(clap::App::new("PTRACE_SYSCALL"))
.subcommand(clap::App::new("PTRACE_ATTACH"))
.subcommand(clap::App::new("PTRACE_SINGLESTEP"))
.subcommand(clap::App::new("PTRACE_KILL"))
.subcommand(clap::App::new("PTRACE_CONT"))
.subcommand(clap::App::new("PTRACE_POKEUSER"))
.subcommand(clap::App::new("PTRACE_POKEDATA"))
.subcommand(clap::App::new("PTRACE_POKETEXT"))
.subcommand(clap::App::new("PTRACE_PEEKUSER"))
.subcommand(clap::App::new("PTRACE_PEEKDATA"))
.subcommand(clap::App::new("PTRACE_PEEKTEXT"))
.subcommand(clap::App::new("PTRACE_TRACEME"))
.subcommand(clap::App::new("CPU_SETSIZE"))
.subcommand(clap::App::new("CGROUP2_SUPER_MAGIC"))
.subcommand(clap::App::new("CGROUP_SUPER_MAGIC"))
.subcommand(clap::App::new("USBDEVICE_SUPER_MAGIC"))
.subcommand(clap::App::new("TMPFS_MAGIC"))
.subcommand(clap::App::new("SMB_SUPER_MAGIC"))
.subcommand(clap::App::new("REISERFS_SUPER_MAGIC"))
.subcommand(clap::App::new("QNX4_SUPER_MAGIC"))
.subcommand(clap::App::new("PROC_SUPER_MAGIC"))
.subcommand(clap::App::new("OPENPROM_SUPER_MAGIC"))
.subcommand(clap::App::new("NFS_SUPER_MAGIC"))
.subcommand(clap::App::new("NCP_SUPER_MAGIC"))
.subcommand(clap::App::new("MSDOS_SUPER_MAGIC"))
.subcommand(clap::App::new("MINIX2_SUPER_MAGIC2"))
.subcommand(clap::App::new("MINIX2_SUPER_MAGIC"))
.subcommand(clap::App::new("MINIX_SUPER_MAGIC2"))
.subcommand(clap::App::new("MINIX_SUPER_MAGIC"))
.subcommand(clap::App::new("JFFS2_SUPER_MAGIC"))
.subcommand(clap::App::new("ISOFS_SUPER_MAGIC"))
.subcommand(clap::App::new("HUGETLBFS_MAGIC"))
.subcommand(clap::App::new("HPFS_SUPER_MAGIC"))
.subcommand(clap::App::new("EXT4_SUPER_MAGIC"))
.subcommand(clap::App::new("EXT3_SUPER_MAGIC"))
.subcommand(clap::App::new("EXT2_SUPER_MAGIC"))
.subcommand(clap::App::new("EFS_SUPER_MAGIC"))
.subcommand(clap::App::new("CRAMFS_MAGIC"))
.subcommand(clap::App::new("CODA_SUPER_MAGIC"))
.subcommand(clap::App::new("AFFS_SUPER_MAGIC"))
.subcommand(clap::App::new("ADFS_SUPER_MAGIC"))
.subcommand(clap::App::new("NI_MAXHOST"))
.subcommand(clap::App::new("ST_RELATIME"))
.subcommand(clap::App::new("O_ACCMODE"))
.subcommand(clap::App::new("_SC_LEVEL4_CACHE_LINESIZE"))
.subcommand(clap::App::new("_SC_LEVEL4_CACHE_ASSOC"))
.subcommand(clap::App::new("_SC_LEVEL4_CACHE_SIZE"))
.subcommand(clap::App::new("_SC_LEVEL3_CACHE_LINESIZE"))
.subcommand(clap::App::new("_SC_LEVEL3_CACHE_ASSOC"))
.subcommand(clap::App::new("_SC_LEVEL3_CACHE_SIZE"))
.subcommand(clap::App::new("_SC_LEVEL2_CACHE_LINESIZE"))
.subcommand(clap::App::new("_SC_LEVEL2_CACHE_ASSOC"))
.subcommand(clap::App::new("_SC_LEVEL2_CACHE_SIZE"))
.subcommand(clap::App::new("_SC_LEVEL1_DCACHE_LINESIZE"))
.subcommand(clap::App::new("_SC_LEVEL1_DCACHE_ASSOC"))
.subcommand(clap::App::new("_SC_LEVEL1_DCACHE_SIZE"))
.subcommand(clap::App::new("_SC_LEVEL1_ICACHE_LINESIZE"))
.subcommand(clap::App::new("_SC_LEVEL1_ICACHE_ASSOC"))
.subcommand(clap::App::new("_SC_LEVEL1_ICACHE_SIZE"))
.subcommand(clap::App::new("_SC_USER_GROUPS_R"))
.subcommand(clap::App::new("_SC_USER_GROUPS"))
.subcommand(clap::App::new("_SC_SYSTEM_DATABASE_R"))
.subcommand(clap::App::new("_SC_SYSTEM_DATABASE"))
.subcommand(clap::App::new("_SC_SIGNALS"))
.subcommand(clap::App::new("_SC_REGEX_VERSION"))
.subcommand(clap::App::new("_SC_NETWORKING"))
.subcommand(clap::App::new("_SC_SINGLE_PROCESS"))
.subcommand(clap::App::new("_SC_MULTI_PROCESS"))
.subcommand(clap::App::new("_SC_FILE_SYSTEM"))
.subcommand(clap::App::new("_SC_FILE_LOCKING"))
.subcommand(clap::App::new("_SC_FILE_ATTRIBUTES"))
.subcommand(clap::App::new("_SC_PIPE"))
.subcommand(clap::App::new("_SC_FIFO"))
.subcommand(clap::App::new("_SC_FD_MGMT"))
.subcommand(clap::App::new("_SC_DEVICE_SPECIFIC_R"))
.subcommand(clap::App::new("_SC_DEVICE_SPECIFIC"))
.subcommand(clap::App::new("_SC_DEVICE_IO"))
.subcommand(clap::App::new("_SC_C_LANG_SUPPORT_R"))
.subcommand(clap::App::new("_SC_C_LANG_SUPPORT"))
.subcommand(clap::App::new("_SC_BASE"))
.subcommand(clap::App::new("_SC_NL_TEXTMAX"))
.subcommand(clap::App::new("_SC_NL_SETMAX"))
.subcommand(clap::App::new("_SC_NL_NMAX"))
.subcommand(clap::App::new("_SC_NL_MSGMAX"))
.subcommand(clap::App::new("_SC_NL_LANGMAX"))
.subcommand(clap::App::new("_SC_NL_ARGMAX"))
.subcommand(clap::App::new("_SC_USHRT_MAX"))
.subcommand(clap::App::new("_SC_ULONG_MAX"))
.subcommand(clap::App::new("_SC_UINT_MAX"))
.subcommand(clap::App::new("_SC_UCHAR_MAX"))
.subcommand(clap::App::new("_SC_SHRT_MIN"))
.subcommand(clap::App::new("_SC_SHRT_MAX"))
.subcommand(clap::App::new("_SC_SCHAR_MIN"))
.subcommand(clap::App::new("_SC_SCHAR_MAX"))
.subcommand(clap::App::new("_SC_SSIZE_MAX"))
.subcommand(clap::App::new("_SC_MB_LEN_MAX"))
.subcommand(clap::App::new("_SC_WORD_BIT"))
.subcommand(clap::App::new("_SC_LONG_BIT"))
.subcommand(clap::App::new("_SC_INT_MIN"))
.subcommand(clap::App::new("_SC_INT_MAX"))
.subcommand(clap::App::new("_SC_CHAR_MIN"))
.subcommand(clap::App::new("_SC_CHAR_MAX"))
.subcommand(clap::App::new("_SC_CHAR_BIT"))
.subcommand(clap::App::new("_SC_2_C_VERSION"))
.subcommand(clap::App::new("_SC_T_IOV_MAX"))
.subcommand(clap::App::new("_SC_PII_OSI_M"))
.subcommand(clap::App::new("_SC_PII_OSI_CLTS"))
.subcommand(clap::App::new("_SC_PII_OSI_COTS"))
.subcommand(clap::App::new("_SC_PII_INTERNET_DGRAM"))
.subcommand(clap::App::new("_SC_PII_INTERNET_STREAM"))
.subcommand(clap::App::new("_SC_SELECT"))
.subcommand(clap::App::new("_SC_POLL"))
.subcommand(clap::App::new("_SC_PII_OSI"))
.subcommand(clap::App::new("_SC_PII_INTERNET"))
.subcommand(clap::App::new("_SC_PII_SOCKET"))
.subcommand(clap::App::new("_SC_PII_XTI"))
.subcommand(clap::App::new("_SC_PII"))
.subcommand(clap::App::new("_SC_CHARCLASS_NAME_MAX"))
.subcommand(clap::App::new("_SC_EQUIV_CLASS_MAX"))
.subcommand(clap::App::new("POSIX_MADV_DONTNEED"))
.subcommand(clap::App::new("FOPEN_MAX"))
.subcommand(clap::App::new("TMP_MAX"))
.subcommand(clap::App::new("BUFSIZ"))
.subcommand(clap::App::new("SIGEV_THREAD_ID"))
.subcommand(clap::App::new("DCCP_SERVICE_LIST_MAX_LEN"))
.subcommand(clap::App::new("DCCP_SOCKOPT_CCID_TX_INFO"))
.subcommand(clap::App::new("DCCP_SOCKOPT_CCID_RX_INFO"))
.subcommand(clap::App::new("DCCP_SOCKOPT_QPOLICY_TXQLEN"))
.subcommand(clap::App::new("DCCP_SOCKOPT_QPOLICY_ID"))
.subcommand(clap::App::new("DCCP_SOCKOPT_RX_CCID"))
.subcommand(clap::App::new("DCCP_SOCKOPT_TX_CCID"))
.subcommand(clap::App::new("DCCP_SOCKOPT_CCID"))
.subcommand(clap::App::new("DCCP_SOCKOPT_AVAILABLE_CCIDS"))
.subcommand(clap::App::new("DCCP_SOCKOPT_RECV_CSCOV"))
.subcommand(clap::App::new("DCCP_SOCKOPT_SEND_CSCOV"))
.subcommand(clap::App::new("DCCP_SOCKOPT_SERVER_TIMEWAIT"))
.subcommand(clap::App::new("DCCP_SOCKOPT_GET_CUR_MPS"))
.subcommand(clap::App::new("DCCP_SOCKOPT_CHANGE_R"))
.subcommand(clap::App::new("DCCP_SOCKOPT_CHANGE_L"))
.subcommand(clap::App::new("DCCP_SOCKOPT_SERVICE"))
.subcommand(clap::App::new("DCCP_SOCKOPT_PACKET_SIZE"))
.subcommand(clap::App::new("TCP_FASTOPEN_CONNECT"))
.subcommand(clap::App::new("TCP_TIMESTAMP"))
.subcommand(clap::App::new("TCP_FASTOPEN"))
.subcommand(clap::App::new("TCP_REPAIR_OPTIONS"))
.subcommand(clap::App::new("TCP_QUEUE_SEQ"))
.subcommand(clap::App::new("TCP_REPAIR_QUEUE"))
.subcommand(clap::App::new("TCP_REPAIR"))
.subcommand(clap::App::new("TCP_USER_TIMEOUT"))
.subcommand(clap::App::new("TCP_THIN_DUPACK"))
.subcommand(clap::App::new("TCP_THIN_LINEAR_TIMEOUTS"))
.subcommand(clap::App::new("TCP_COOKIE_TRANSACTIONS"))
.subcommand(clap::App::new("SOCK_PACKET"))
.subcommand(clap::App::new("SOCK_DCCP"))
.subcommand(clap::App::new("SOCK_SEQPACKET"))
.subcommand(clap::App::new("ENOTSUP"))
.subcommand(clap::App::new("LC_ALL_MASK"))
.subcommand(clap::App::new("LC_IDENTIFICATION_MASK"))
.subcommand(clap::App::new("LC_MEASUREMENT_MASK"))
.subcommand(clap::App::new("LC_TELEPHONE_MASK"))
.subcommand(clap::App::new("LC_ADDRESS_MASK"))
.subcommand(clap::App::new("LC_NAME_MASK"))
.subcommand(clap::App::new("LC_PAPER_MASK"))
.subcommand(clap::App::new("LC_IDENTIFICATION"))
.subcommand(clap::App::new("LC_MEASUREMENT"))
.subcommand(clap::App::new("LC_TELEPHONE"))
.subcommand(clap::App::new("LC_ADDRESS"))
.subcommand(clap::App::new("LC_NAME"))
.subcommand(clap::App::new("LC_PAPER"))
.subcommand(clap::App::new("MSG_TRYHARD"))
.subcommand(clap::App::new("SOL_XDP"))
.subcommand(clap::App::new("SOL_NFC"))
.subcommand(clap::App::new("SOL_CAIF"))
.subcommand(clap::App::new("SOL_IUCV"))
.subcommand(clap::App::new("SOL_RDS"))
.subcommand(clap::App::new("SOL_PNPIPE"))
.subcommand(clap::App::new("SOL_PPPOL2TP"))
.subcommand(clap::App::new("SOL_RXRPC"))
.subcommand(clap::App::new("SOCK_NONBLOCK"))
.subcommand(clap::App::new("RTLD_DI_TLS_DATA"))
.subcommand(clap::App::new("RTLD_DI_TLS_MODID"))
.subcommand(clap::App::new("RTLD_DI_PROFILEOUT"))
.subcommand(clap::App::new("RTLD_DI_PROFILENAME"))
.subcommand(clap::App::new("RTLD_DI_ORIGIN"))
.subcommand(clap::App::new("RTLD_DI_SERINFOSIZE"))
.subcommand(clap::App::new("RTLD_DI_SERINFO"))
.subcommand(clap::App::new("RTLD_DI_CONFIGADDR"))
.subcommand(clap::App::new("RTLD_DI_LINKMAP"))
.subcommand(clap::App::new("RTLD_DI_LMID"))
.subcommand(clap::App::new("LM_ID_NEWLM"))
.subcommand(clap::App::new("LM_ID_BASE"))
.subcommand(clap::App::new("ACCOUNTING"))
.subcommand(clap::App::new("DEAD_PROCESS"))
.subcommand(clap::App::new("USER_PROCESS"))
.subcommand(clap::App::new("LOGIN_PROCESS"))
.subcommand(clap::App::new("INIT_PROCESS"))
.subcommand(clap::App::new("OLD_TIME"))
.subcommand(clap::App::new("NEW_TIME"))
.subcommand(clap::App::new("BOOT_TIME"))
.subcommand(clap::App::new("RUN_LVL"))
.subcommand(clap::App::new("EMPTY"))
.subcommand(clap::App::new("__UT_HOSTSIZE"))
.subcommand(clap::App::new("__UT_NAMESIZE"))
.subcommand(clap::App::new("__UT_LINESIZE"))
.subcommand(clap::App::new("MS_RMT_MASK"))
.subcommand(clap::App::new("RLIMIT_NLIMITS"))
.subcommand(clap::App::new("RLIMIT_RTTIME"))
.subcommand(clap::App::new("RLIMIT_RTPRIO"))
.subcommand(clap::App::new("RLIMIT_NICE"))
.subcommand(clap::App::new("RLIMIT_MSGQUEUE"))
.subcommand(clap::App::new("RLIMIT_SIGPENDING"))
.subcommand(clap::App::new("RLIMIT_LOCKS"))
.subcommand(clap::App::new("RLIMIT_CORE"))
.subcommand(clap::App::new("RLIMIT_STACK"))
.subcommand(clap::App::new("RLIMIT_DATA"))
.subcommand(clap::App::new("RLIMIT_FSIZE"))
.subcommand(clap::App::new("RLIMIT_CPU"))
.subcommand(clap::App::new("MAP_HUGE_16GB"))
.subcommand(clap::App::new("MAP_HUGE_2GB"))
.subcommand(clap::App::new("MAP_HUGE_1GB"))
.subcommand(clap::App::new("MAP_HUGE_512MB"))
.subcommand(clap::App::new("MAP_HUGE_256MB"))
.subcommand(clap::App::new("MAP_HUGE_32MB"))
.subcommand(clap::App::new("MAP_HUGE_16MB"))
.subcommand(clap::App::new("MAP_HUGE_8MB"))
.subcommand(clap::App::new("MAP_HUGE_2MB"))
.subcommand(clap::App::new("MAP_HUGE_1MB"))
.subcommand(clap::App::new("MAP_HUGE_512KB"))
.subcommand(clap::App::new("MAP_HUGE_64KB"))
.subcommand(clap::App::new("MAP_HUGE_MASK"))
.subcommand(clap::App::new("MAP_HUGE_SHIFT"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_16GB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_2GB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_1GB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_512MB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_256MB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_32MB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_16MB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_8MB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_2MB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_1MB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_512KB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_64KB"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_MASK"))
.subcommand(clap::App::new("HUGETLB_FLAG_ENCODE_SHIFT"))
.subcommand(clap::App::new("EWOULDBLOCK"))
.subcommand(clap::App::new("ERANGE"))
.subcommand(clap::App::new("EDOM"))
.subcommand(clap::App::new("EPIPE"))
.subcommand(clap::App::new("EMLINK"))
.subcommand(clap::App::new("EROFS"))
.subcommand(clap::App::new("ESPIPE"))
.subcommand(clap::App::new("ENOSPC"))
.subcommand(clap::App::new("EFBIG"))
.subcommand(clap::App::new("ETXTBSY"))
.subcommand(clap::App::new("ENOTTY"))
.subcommand(clap::App::new("EMFILE"))
.subcommand(clap::App::new("ENFILE"))
.subcommand(clap::App::new("EINVAL"))
.subcommand(clap::App::new("EISDIR"))
.subcommand(clap::App::new("ENOTDIR"))
.subcommand(clap::App::new("ENODEV"))
.subcommand(clap::App::new("EXDEV"))
.subcommand(clap::App::new("EEXIST"))
.subcommand(clap::App::new("EBUSY"))
.subcommand(clap::App::new("ENOTBLK"))
.subcommand(clap::App::new("EFAULT"))
.subcommand(clap::App::new("EACCES"))
.subcommand(clap::App::new("ENOMEM"))
.subcommand(clap::App::new("EAGAIN"))
.subcommand(clap::App::new("ECHILD"))
.subcommand(clap::App::new("EBADF"))
.subcommand(clap::App::new("ENOEXEC"))
.subcommand(clap::App::new("E2BIG"))
.subcommand(clap::App::new("ENXIO"))
.subcommand(clap::App::new("EIO"))
.subcommand(clap::App::new("EINTR"))
.subcommand(clap::App::new("ESRCH"))
.subcommand(clap::App::new("ENOENT"))
.subcommand(clap::App::new("EPERM"))
.subcommand(clap::App::new("SO_EE_ORIGIN_TIMESTAMPING"))
.subcommand(clap::App::new("SO_EE_ORIGIN_TXSTATUS"))
.subcommand(clap::App::new("SO_EE_ORIGIN_ICMP6"))
.subcommand(clap::App::new("SO_EE_ORIGIN_ICMP"))
.subcommand(clap::App::new("SO_EE_ORIGIN_LOCAL"))
.subcommand(clap::App::new("SO_EE_ORIGIN_NONE"))
.subcommand(clap::App::new("REG_BADRPT"))
.subcommand(clap::App::new("REG_ESPACE"))
.subcommand(clap::App::new("REG_ERANGE"))
.subcommand(clap::App::new("REG_BADBR"))
.subcommand(clap::App::new("REG_EBRACE"))
.subcommand(clap::App::new("REG_EPAREN"))
.subcommand(clap::App::new("REG_EBRACK"))
.subcommand(clap::App::new("REG_ESUBREG"))
.subcommand(clap::App::new("REG_EESCAPE"))
.subcommand(clap::App::new("REG_ECTYPE"))
.subcommand(clap::App::new("REG_ECOLLATE"))
.subcommand(clap::App::new("REG_BADPAT"))
.subcommand(clap::App::new("REG_NOMATCH"))
.subcommand(clap::App::new("REG_ENOSYS"))
.subcommand(clap::App::new("REG_NOTEOL"))
.subcommand(clap::App::new("REG_NOTBOL"))
.subcommand(clap::App::new("REG_NOSUB"))
.subcommand(clap::App::new("REG_NEWLINE"))
.subcommand(clap::App::new("REG_ICASE"))
.subcommand(clap::App::new("REG_EXTENDED"))
.subcommand(clap::App::new("LINUX_REBOOT_CMD_KEXEC"))
.subcommand(clap::App::new("LINUX_REBOOT_CMD_SW_SUSPEND"))
.subcommand(clap::App::new("LINUX_REBOOT_CMD_RESTART2"))
.subcommand(clap::App::new("LINUX_REBOOT_CMD_POWER_OFF"))
.subcommand(clap::App::new("LINUX_REBOOT_CMD_CAD_OFF"))
.subcommand(clap::App::new("LINUX_REBOOT_CMD_CAD_ON"))
.subcommand(clap::App::new("LINUX_REBOOT_CMD_HALT"))
.subcommand(clap::App::new("LINUX_REBOOT_CMD_RESTART"))
.subcommand(clap::App::new("LINUX_REBOOT_MAGIC2C"))
.subcommand(clap::App::new("LINUX_REBOOT_MAGIC2B"))
.subcommand(clap::App::new("LINUX_REBOOT_MAGIC2A"))
.subcommand(clap::App::new("LINUX_REBOOT_MAGIC2"))
.subcommand(clap::App::new("LINUX_REBOOT_MAGIC1"))
.subcommand(clap::App::new("FUTEX_CMD_MASK"))
.subcommand(clap::App::new("FUTEX_CLOCK_REALTIME"))
.subcommand(clap::App::new("FUTEX_PRIVATE_FLAG"))
.subcommand(clap::App::new("FUTEX_CMP_REQUEUE_PI"))
.subcommand(clap::App::new("FUTEX_WAIT_REQUEUE_PI"))
.subcommand(clap::App::new("FUTEX_WAKE_BITSET"))
.subcommand(clap::App::new("FUTEX_WAIT_BITSET"))
.subcommand(clap::App::new("FUTEX_TRYLOCK_PI"))
.subcommand(clap::App::new("FUTEX_UNLOCK_PI"))
.subcommand(clap::App::new("FUTEX_LOCK_PI"))
.subcommand(clap::App::new("FUTEX_WAKE_OP"))
.subcommand(clap::App::new("FUTEX_CMP_REQUEUE"))
.subcommand(clap::App::new("FUTEX_REQUEUE"))
.subcommand(clap::App::new("FUTEX_FD"))
.subcommand(clap::App::new("FUTEX_WAKE"))
.subcommand(clap::App::new("FUTEX_WAIT"))
.subcommand(clap::App::new("FAN_NOFD"))
.subcommand(clap::App::new("FAN_DENY"))
.subcommand(clap::App::new("FAN_ALLOW"))
.subcommand(clap::App::new("FANOTIFY_METADATA_VERSION"))
.subcommand(clap::App::new("FAN_MARK_FLUSH"))
.subcommand(clap::App::new("FAN_MARK_IGNORED_SURV_MODIFY"))
.subcommand(clap::App::new("FAN_MARK_IGNORED_MASK"))
.subcommand(clap::App::new("FAN_MARK_FILESYSTEM"))
.subcommand(clap::App::new("FAN_MARK_MOUNT"))
.subcommand(clap::App::new("FAN_MARK_INODE"))
.subcommand(clap::App::new("FAN_MARK_ONLYDIR"))
.subcommand(clap::App::new("FAN_MARK_DONT_FOLLOW"))
.subcommand(clap::App::new("FAN_MARK_REMOVE"))
.subcommand(clap::App::new("FAN_MARK_ADD"))
.subcommand(clap::App::new("FAN_UNLIMITED_MARKS"))
.subcommand(clap::App::new("FAN_UNLIMITED_QUEUE"))
.subcommand(clap::App::new("FAN_CLASS_PRE_CONTENT"))
.subcommand(clap::App::new("FAN_CLASS_CONTENT"))
.subcommand(clap::App::new("FAN_CLASS_NOTIF"))
.subcommand(clap::App::new("FAN_NONBLOCK"))
.subcommand(clap::App::new("FAN_CLOEXEC"))
.subcommand(clap::App::new("FAN_CLOSE"))
.subcommand(clap::App::new("FAN_EVENT_ON_CHILD"))
.subcommand(clap::App::new("FAN_ONDIR"))
.subcommand(clap::App::new("FAN_ACCESS_PERM"))
.subcommand(clap::App::new("FAN_OPEN_PERM"))
.subcommand(clap::App::new("FAN_Q_OVERFLOW"))
.subcommand(clap::App::new("FAN_OPEN"))
.subcommand(clap::App::new("FAN_CLOSE_NOWRITE"))
.subcommand(clap::App::new("FAN_CLOSE_WRITE"))
.subcommand(clap::App::new("FAN_MODIFY"))
.subcommand(clap::App::new("FAN_ACCESS"))
.subcommand(clap::App::new("IN_NONBLOCK"))
.subcommand(clap::App::new("IN_CLOEXEC"))
.subcommand(clap::App::new("IN_ALL_EVENTS"))
.subcommand(clap::App::new("IN_ONESHOT"))
.subcommand(clap::App::new("IN_ISDIR"))
.subcommand(clap::App::new("KEYCTL_GET_PERSISTENT"))
.subcommand(clap::App::new("KEYCTL_INVALIDATE"))
.subcommand(clap::App::new("KEYCTL_INSTANTIATE_IOV"))
.subcommand(clap::App::new("KEYCTL_REJECT"))
.subcommand(clap::App::new("KEYCTL_SESSION_TO_PARENT"))
.subcommand(clap::App::new("KEYCTL_GET_SECURITY"))
.subcommand(clap::App::new("KEYCTL_ASSUME_AUTHORITY"))
.subcommand(clap::App::new("KEYCTL_SET_TIMEOUT"))
.subcommand(clap::App::new("KEYCTL_SET_REQKEY_KEYRING"))
.subcommand(clap::App::new("KEYCTL_NEGATE"))
.subcommand(clap::App::new("KEYCTL_INSTANTIATE"))
.subcommand(clap::App::new("KEYCTL_READ"))
.subcommand(clap::App::new("KEYCTL_SEARCH"))
.subcommand(clap::App::new("KEYCTL_UNLINK"))
.subcommand(clap::App::new("KEYCTL_LINK"))
.subcommand(clap::App::new("KEYCTL_CLEAR"))
.subcommand(clap::App::new("KEYCTL_DESCRIBE"))
.subcommand(clap::App::new("KEYCTL_SETPERM"))
.subcommand(clap::App::new("KEYCTL_CHOWN"))
.subcommand(clap::App::new("KEYCTL_REVOKE"))
.subcommand(clap::App::new("KEYCTL_UPDATE"))
.subcommand(clap::App::new("KEYCTL_JOIN_SESSION_KEYRING"))
.subcommand(clap::App::new("KEYCTL_GET_KEYRING_ID"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_REQUESTOR_KEYRING"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_GROUP_KEYRING"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_USER_SESSION_KEYRING"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_USER_KEYRING"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_SESSION_KEYRING"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_PROCESS_KEYRING"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_THREAD_KEYRING"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_DEFAULT"))
.subcommand(clap::App::new("KEY_REQKEY_DEFL_NO_CHANGE"))
.subcommand(clap::App::new("KEY_SPEC_REQUESTOR_KEYRING"))
.subcommand(clap::App::new("KEY_SPEC_REQKEY_AUTH_KEY"))
.subcommand(clap::App::new("KEY_SPEC_GROUP_KEYRING"))
.subcommand(clap::App::new("KEY_SPEC_USER_SESSION_KEYRING"))
.subcommand(clap::App::new("KEY_SPEC_USER_KEYRING"))
.subcommand(clap::App::new("KEY_SPEC_SESSION_KEYRING"))
.subcommand(clap::App::new("KEY_SPEC_PROCESS_KEYRING"))
.subcommand(clap::App::new("KEY_SPEC_THREAD_KEYRING"))
.subcommand(clap::App::new("IN_DONT_FOLLOW"))
.subcommand(clap::App::new("IN_ONLYDIR"))
.subcommand(clap::App::new("IN_IGNORED"))
.subcommand(clap::App::new("IN_Q_OVERFLOW"))
.subcommand(clap::App::new("IN_UNMOUNT"))
.subcommand(clap::App::new("IN_MOVE_SELF"))
.subcommand(clap::App::new("IN_DELETE_SELF"))
.subcommand(clap::App::new("IN_DELETE"))
.subcommand(clap::App::new("IN_CREATE"))
.subcommand(clap::App::new("IN_MOVE"))
.subcommand(clap::App::new("IN_MOVED_TO"))
.subcommand(clap::App::new("IN_MOVED_FROM"))
.subcommand(clap::App::new("IN_OPEN"))
.subcommand(clap::App::new("IN_CLOSE"))
.subcommand(clap::App::new("IN_CLOSE_NOWRITE"))
.subcommand(clap::App::new("IN_CLOSE_WRITE"))
.subcommand(clap::App::new("IN_ATTRIB"))
.subcommand(clap::App::new("IN_MODIFY"))
.subcommand(clap::App::new("IN_ACCESS"))
.subcommand(clap::App::new("VMADDR_PORT_ANY"))
.subcommand(clap::App::new("VMADDR_CID_HOST"))
.subcommand(clap::App::new("VMADDR_CID_RESERVED"))
.subcommand(clap::App::new("VMADDR_CID_HYPERVISOR"))
.subcommand(clap::App::new("VMADDR_CID_ANY"))
.subcommand(clap::App::new("MAP_FIXED_NOREPLACE"))
.subcommand(clap::App::new("MAP_SHARED_VALIDATE"))
.subcommand(clap::App::new("UDP_GRO"))
.subcommand(clap::App::new("UDP_SEGMENT"))
.subcommand(clap::App::new("UDP_NO_CHECK6_RX"))
.subcommand(clap::App::new("UDP_NO_CHECK6_TX"))
.subcommand(clap::App::new("UDP_ENCAP"))
.subcommand(clap::App::new("UDP_CORK"))
.subcommand(clap::App::new("ALG_OP_ENCRYPT"))
.subcommand(clap::App::new("ALG_OP_DECRYPT"))
.subcommand(clap::App::new("ALG_SET_AEAD_AUTHSIZE"))
.subcommand(clap::App::new("ALG_SET_AEAD_ASSOCLEN"))
.subcommand(clap::App::new("ALG_SET_OP"))
.subcommand(clap::App::new("ALG_SET_IV"))
.subcommand(clap::App::new("ALG_SET_KEY"))
.subcommand(clap::App::new("SOF_TIMESTAMPING_RAW_HARDWARE"))
.subcommand(clap::App::new("SOF_TIMESTAMPING_SYS_HARDWARE"))
.subcommand(clap::App::new("SOF_TIMESTAMPING_SOFTWARE"))
.subcommand(clap::App::new("SOF_TIMESTAMPING_RX_SOFTWARE"))
.subcommand(clap::App::new("SOF_TIMESTAMPING_RX_HARDWARE"))
.subcommand(clap::App::new("SOF_TIMESTAMPING_TX_SOFTWARE"))
.subcommand(clap::App::new("SOF_TIMESTAMPING_TX_HARDWARE"))
.subcommand(clap::App::new("MODULE_INIT_IGNORE_VERMAGIC"))
.subcommand(clap::App::new("MODULE_INIT_IGNORE_MODVERSIONS"))
.subcommand(clap::App::new("SCM_TIMESTAMPING"))
.subcommand(clap::App::new("SO_TIMESTAMPING"))
.subcommand(clap::App::new("ATF_MAGIC"))
.subcommand(clap::App::new("ARPD_FLUSH"))
.subcommand(clap::App::new("ARPD_LOOKUP"))
.subcommand(clap::App::new("ARPD_UPDATE"))
.subcommand(clap::App::new("MAX_ADDR_LEN"))
.subcommand(clap::App::new("RTMSG_AR_FAILED"))
.subcommand(clap::App::new("RTMSG_CONTROL"))
.subcommand(clap::App::new("RTMSG_DELRULE"))
.subcommand(clap::App::new("RTMSG_NEWRULE"))
.subcommand(clap::App::new("RTMSG_DELROUTE"))
.subcommand(clap::App::new("RTMSG_NEWROUTE"))
.subcommand(clap::App::new("RTMSG_DELDEVICE"))
.subcommand(clap::App::new("RTMSG_NEWDEVICE"))
.subcommand(clap::App::new("RTMSG_OVERRUN"))
.subcommand(clap::App::new("RT_TABLE_LOCAL"))
.subcommand(clap::App::new("RT_TABLE_MAIN"))
.subcommand(clap::App::new("RT_TABLE_DEFAULT"))
.subcommand(clap::App::new("RT_TABLE_COMPAT"))
.subcommand(clap::App::new("RT_TABLE_UNSPEC"))
.subcommand(clap::App::new("RT_SCOPE_NOWHERE"))
.subcommand(clap::App::new("RT_SCOPE_HOST"))
.subcommand(clap::App::new("RT_SCOPE_LINK"))
.subcommand(clap::App::new("RT_SCOPE_SITE"))
.subcommand(clap::App::new("RT_SCOPE_UNIVERSE"))
.subcommand(clap::App::new("RTPROT_STATIC"))
.subcommand(clap::App::new("RTPROT_BOOT"))
.subcommand(clap::App::new("RTPROT_KERNEL"))
.subcommand(clap::App::new("RTPROT_REDIRECT"))
.subcommand(clap::App::new("RTPROT_UNSPEC"))
.subcommand(clap::App::new("RTN_XRESOLVE"))
.subcommand(clap::App::new("RTN_NAT"))
.subcommand(clap::App::new("RTN_THROW"))
.subcommand(clap::App::new("RTN_PROHIBIT"))
.subcommand(clap::App::new("RTN_UNREACHABLE"))
.subcommand(clap::App::new("RTN_BLACKHOLE"))
.subcommand(clap::App::new("RTN_MULTICAST"))
.subcommand(clap::App::new("RTN_ANYCAST"))
.subcommand(clap::App::new("RTN_BROADCAST"))
.subcommand(clap::App::new("RTN_LOCAL"))
.subcommand(clap::App::new("RTN_UNICAST"))
.subcommand(clap::App::new("RTN_UNSPEC"))
.subcommand(clap::App::new("RTA_MFC_STATS"))
.subcommand(clap::App::new("RTA_MARK"))
.subcommand(clap::App::new("RTA_TABLE"))
.subcommand(clap::App::new("RTA_MP_ALGO"))
.subcommand(clap::App::new("RTA_SESSION"))
.subcommand(clap::App::new("RTA_CACHEINFO"))
.subcommand(clap::App::new("RTA_FLOW"))
.subcommand(clap::App::new("RTA_PROTOINFO"))
.subcommand(clap::App::new("RTA_MULTIPATH"))
.subcommand(clap::App::new("RTA_METRICS"))
.subcommand(clap::App::new("RTA_PREFSRC"))
.subcommand(clap::App::new("RTA_PRIORITY"))
.subcommand(clap::App::new("RTA_GATEWAY"))
.subcommand(clap::App::new("RTA_OIF"))
.subcommand(clap::App::new("RTA_IIF"))
.subcommand(clap::App::new("RTA_SRC"))
.subcommand(clap::App::new("RTA_DST"))
.subcommand(clap::App::new("RTA_UNSPEC"))
.subcommand(clap::App::new("RTM_F_PREFIX"))
.subcommand(clap::App::new("RTM_F_EQUALIZE"))
.subcommand(clap::App::new("RTM_F_CLONED"))
.subcommand(clap::App::new("RTM_F_NOTIFY"))
.subcommand(clap::App::new("RTM_GETNSID"))
.subcommand(clap::App::new("RTM_DELNSID"))
.subcommand(clap::App::new("RTM_NEWNSID"))
.subcommand(clap::App::new("RTM_GETMDB"))
.subcommand(clap::App::new("RTM_DELMDB"))
.subcommand(clap::App::new("RTM_NEWMDB"))
.subcommand(clap::App::new("RTM_GETNETCONF"))
.subcommand(clap::App::new("RTM_NEWNETCONF"))
.subcommand(clap::App::new("RTM_SETDCB"))
.subcommand(clap::App::new("RTM_GETDCB"))
.subcommand(clap::App::new("RTM_GETADDRLABEL"))
.subcommand(clap::App::new("RTM_DELADDRLABEL"))
.subcommand(clap::App::new("RTM_NEWADDRLABEL"))
.subcommand(clap::App::new("RTM_NEWNDUSEROPT"))
.subcommand(clap::App::new("RTM_SETNEIGHTBL"))
.subcommand(clap::App::new("RTM_GETNEIGHTBL"))
.subcommand(clap::App::new("RTM_NEWNEIGHTBL"))
.subcommand(clap::App::new("RTM_GETANYCAST"))
.subcommand(clap::App::new("RTM_GETMULTICAST"))
.subcommand(clap::App::new("RTM_NEWPREFIX"))
.subcommand(clap::App::new("RTM_GETACTION"))
.subcommand(clap::App::new("RTM_DELACTION"))
.subcommand(clap::App::new("RTM_NEWACTION"))
.subcommand(clap::App::new("RTM_GETTFILTER"))
.subcommand(clap::App::new("RTM_DELTFILTER"))
.subcommand(clap::App::new("RTM_NEWTFILTER"))
.subcommand(clap::App::new("RTM_GETTCLASS"))
.subcommand(clap::App::new("RTM_DELTCLASS"))
.subcommand(clap::App::new("RTM_NEWTCLASS"))
.subcommand(clap::App::new("RTM_GETQDISC"))
.subcommand(clap::App::new("RTM_DELQDISC"))
.subcommand(clap::App::new("RTM_NEWQDISC"))
.subcommand(clap::App::new("RTM_GETRULE"))
.subcommand(clap::App::new("RTM_DELRULE"))
.subcommand(clap::App::new("RTM_NEWRULE"))
.subcommand(clap::App::new("RTM_GETNEIGH"))
.subcommand(clap::App::new("RTM_DELNEIGH"))
.subcommand(clap::App::new("RTM_NEWNEIGH"))
.subcommand(clap::App::new("RTM_GETROUTE"))
.subcommand(clap::App::new("RTM_DELROUTE"))
.subcommand(clap::App::new("RTM_NEWROUTE"))
.subcommand(clap::App::new("RTM_GETADDR"))
.subcommand(clap::App::new("RTM_DELADDR"))
.subcommand(clap::App::new("RTM_NEWADDR"))
.subcommand(clap::App::new("RTM_SETLINK"))
.subcommand(clap::App::new("RTM_GETLINK"))
.subcommand(clap::App::new("RTM_DELLINK"))
.subcommand(clap::App::new("RTM_NEWLINK"))
.subcommand(clap::App::new("TCA_STAB"))
.subcommand(clap::App::new("TCA_STATS2"))
.subcommand(clap::App::new("TCA_FCNT"))
.subcommand(clap::App::new("TCA_RATE"))
.subcommand(clap::App::new("TCA_XSTATS"))
.subcommand(clap::App::new("TCA_STATS"))
.subcommand(clap::App::new("TCA_OPTIONS"))
.subcommand(clap::App::new("TCA_KIND"))
.subcommand(clap::App::new("TCA_UNSPEC"))
.subcommand(clap::App::new("NLA_TYPE_MASK"))
.subcommand(clap::App::new("NLA_F_NET_BYTEORDER"))
.subcommand(clap::App::new("NLA_F_NESTED"))
.subcommand(clap::App::new("NETLINK_CAP_ACK"))
.subcommand(clap::App::new("NETLINK_LIST_MEMBERSHIPS"))
.subcommand(clap::App::new("NETLINK_LISTEN_ALL_NSID"))
.subcommand(clap::App::new("NETLINK_TX_RING"))
.subcommand(clap::App::new("NETLINK_RX_RING"))
.subcommand(clap::App::new("NETLINK_NO_ENOBUFS"))
.subcommand(clap::App::new("NETLINK_BROADCAST_ERROR"))
.subcommand(clap::App::new("NETLINK_PKTINFO"))
.subcommand(clap::App::new("NETLINK_DROP_MEMBERSHIP"))
.subcommand(clap::App::new("NETLINK_ADD_MEMBERSHIP"))
.subcommand(clap::App::new("NLM_F_APPEND"))
.subcommand(clap::App::new("NLM_F_CREATE"))
.subcommand(clap::App::new("NLM_F_EXCL"))
.subcommand(clap::App::new("NLM_F_REPLACE"))
.subcommand(clap::App::new("NLM_F_DUMP"))
.subcommand(clap::App::new("NLM_F_ATOMIC"))
.subcommand(clap::App::new("NLM_F_MATCH"))
.subcommand(clap::App::new("NLM_F_ROOT"))
.subcommand(clap::App::new("NLM_F_DUMP_FILTERED"))
.subcommand(clap::App::new("NLM_F_DUMP_INTR"))
.subcommand(clap::App::new("NLM_F_ECHO"))
.subcommand(clap::App::new("NLM_F_ACK"))
.subcommand(clap::App::new("NLM_F_MULTI"))
.subcommand(clap::App::new("NLM_F_REQUEST"))
.subcommand(clap::App::new("NETLINK_INET_DIAG"))
.subcommand(clap::App::new("NETLINK_CRYPTO"))
.subcommand(clap::App::new("NETLINK_RDMA"))
.subcommand(clap::App::new("NETLINK_ECRYPTFS"))
.subcommand(clap::App::new("NETLINK_SCSITRANSPORT"))
.subcommand(clap::App::new("NETLINK_GENERIC"))
.subcommand(clap::App::new("NETLINK_KOBJECT_UEVENT"))
.subcommand(clap::App::new("NETLINK_DNRTMSG"))
.subcommand(clap::App::new("NETLINK_IP6_FW"))
.subcommand(clap::App::new("NETLINK_NETFILTER"))
.subcommand(clap::App::new("NETLINK_CONNECTOR"))
.subcommand(clap::App::new("NETLINK_FIB_LOOKUP"))
.subcommand(clap::App::new("NETLINK_AUDIT"))
.subcommand(clap::App::new("NETLINK_ISCSI"))
.subcommand(clap::App::new("NETLINK_SELINUX"))
.subcommand(clap::App::new("NETLINK_XFRM"))
.subcommand(clap::App::new("NETLINK_NFLOG"))
.subcommand(clap::App::new("NETLINK_SOCK_DIAG"))
.subcommand(clap::App::new("NETLINK_FIREWALL"))
.subcommand(clap::App::new("NETLINK_USERSOCK"))
.subcommand(clap::App::new("NETLINK_UNUSED"))
.subcommand(clap::App::new("NETLINK_ROUTE"))
.subcommand(clap::App::new("NLA_ALIGNTO"))
.subcommand(clap::App::new("NDA_IFINDEX"))
.subcommand(clap::App::new("NDA_VNI"))
.subcommand(clap::App::new("NDA_PORT"))
.subcommand(clap::App::new("NDA_VLAN"))
.subcommand(clap::App::new("NDA_PROBES"))
.subcommand(clap::App::new("NDA_CACHEINFO"))
.subcommand(clap::App::new("NDA_LLADDR"))
.subcommand(clap::App::new("NDA_DST"))
.subcommand(clap::App::new("NDA_UNSPEC"))
.subcommand(clap::App::new("NTF_ROUTER"))
.subcommand(clap::App::new("NTF_PROXY"))
.subcommand(clap::App::new("NTF_MASTER"))
.subcommand(clap::App::new("NTF_SELF"))
.subcommand(clap::App::new("NTF_USE"))
.subcommand(clap::App::new("NUD_PERMANENT"))
.subcommand(clap::App::new("NUD_NOARP"))
.subcommand(clap::App::new("NUD_FAILED"))
.subcommand(clap::App::new("NUD_PROBE"))
.subcommand(clap::App::new("NUD_DELAY"))
.subcommand(clap::App::new("NUD_STALE"))
.subcommand(clap::App::new("NUD_REACHABLE"))
.subcommand(clap::App::new("NUD_INCOMPLETE"))
.subcommand(clap::App::new("NUD_NONE"))
.subcommand(clap::App::new("RT_CLASS_MAX"))
.subcommand(clap::App::new("RT_CLASS_LOCAL"))
.subcommand(clap::App::new("RT_CLASS_MAIN"))
.subcommand(clap::App::new("RT_CLASS_DEFAULT"))
.subcommand(clap::App::new("RT_CLASS_UNSPEC"))
.subcommand(clap::App::new("RTF_ADDRCLASSMASK"))
.subcommand(clap::App::new("RTF_NAT"))
.subcommand(clap::App::new("RTF_BROADCAST"))
.subcommand(clap::App::new("RTF_MULTICAST"))
.subcommand(clap::App::new("RTF_INTERFACE"))
.subcommand(clap::App::new("RTF_LOCAL"))
.subcommand(clap::App::new("RTCF_DIRECTSRC"))
.subcommand(clap::App::new("RTCF_LOG"))
.subcommand(clap::App::new("RTCF_DOREDIRECT"))
.subcommand(clap::App::new("RTCF_NAT"))
.subcommand(clap::App::new("RTCF_MASQ"))
.subcommand(clap::App::new("RTCF_VALVE"))
.subcommand(clap::App::new("RTF_POLICY"))
.subcommand(clap::App::new("RTF_FLOW"))
.subcommand(clap::App::new("RTF_CACHE"))
.subcommand(clap::App::new("RTF_NONEXTHOP"))
.subcommand(clap::App::new("RTF_LINKRT"))
.subcommand(clap::App::new("RTF_ADDRCONF"))
.subcommand(clap::App::new("RTF_ALLONLINK"))
.subcommand(clap::App::new("RTF_DEFAULT"))
.subcommand(clap::App::new("RTF_NOPMTUDISC"))
.subcommand(clap::App::new("RTF_THROW"))
.subcommand(clap::App::new("RTF_NOFORWARD"))
.subcommand(clap::App::new("RTF_XRESOLVE"))
.subcommand(clap::App::new("RTF_STATIC"))
.subcommand(clap::App::new("RTF_REJECT"))
.subcommand(clap::App::new("RTF_IRTT"))
.subcommand(clap::App::new("RTF_WINDOW"))
.subcommand(clap::App::new("RTF_MSS"))
.subcommand(clap::App::new("RTF_MTU"))
.subcommand(clap::App::new("RTF_MODIFIED"))
.subcommand(clap::App::new("RTF_DYNAMIC"))
.subcommand(clap::App::new("RTF_REINSTATE"))
.subcommand(clap::App::new("RTF_HOST"))
.subcommand(clap::App::new("RTF_GATEWAY"))
.subcommand(clap::App::new("RTF_UP"))
.subcommand(clap::App::new("IPTOS_ECN_NOT_ECT"))
.subcommand(clap::App::new("IPTOS_PREC_MASK"))
.subcommand(clap::App::new("IPTOS_TOS_MASK"))
.subcommand(clap::App::new("SIOCSIFMAP"))
.subcommand(clap::App::new("SIOCGIFMAP"))
.subcommand(clap::App::new("SIOCSRARP"))
.subcommand(clap::App::new("SIOCGRARP"))
.subcommand(clap::App::new("SIOCDRARP"))
.subcommand(clap::App::new("SIOCSARP"))
.subcommand(clap::App::new("SIOCGARP"))
.subcommand(clap::App::new("SIOCDARP"))
.subcommand(clap::App::new("SIOCDELMULTI"))
.subcommand(clap::App::new("SIOCADDMULTI"))
.subcommand(clap::App::new("SIOCSIFSLAVE"))
.subcommand(clap::App::new("SIOCGIFSLAVE"))
.subcommand(clap::App::new("SIOCGIFHWADDR"))
.subcommand(clap::App::new("SIOCSIFENCAP"))
.subcommand(clap::App::new("SIOCGIFENCAP"))
.subcommand(clap::App::new("SIOCSIFHWADDR"))
.subcommand(clap::App::new("SIOCSIFMTU"))
.subcommand(clap::App::new("SIOCGIFMTU"))
.subcommand(clap::App::new("SIOCSIFMEM"))
.subcommand(clap::App::new("SIOCGIFMEM"))
.subcommand(clap::App::new("SIOCSIFMETRIC"))
.subcommand(clap::App::new("SIOCGIFMETRIC"))
.subcommand(clap::App::new("SIOCSIFNETMASK"))
.subcommand(clap::App::new("SIOCGIFNETMASK"))
.subcommand(clap::App::new("SIOCSIFBRDADDR"))
.subcommand(clap::App::new("SIOCGIFBRDADDR"))
.subcommand(clap::App::new("SIOCSIFDSTADDR"))
.subcommand(clap::App::new("SIOCGIFDSTADDR"))
.subcommand(clap::App::new("SIOCSIFADDR"))
.subcommand(clap::App::new("SIOCGIFADDR"))
.subcommand(clap::App::new("SIOCSIFFLAGS"))
.subcommand(clap::App::new("SIOCGIFFLAGS"))
.subcommand(clap::App::new("SIOCGIFCONF"))
.subcommand(clap::App::new("SIOCSIFLINK"))
.subcommand(clap::App::new("SIOCGIFNAME"))
.subcommand(clap::App::new("SIOCDELRT"))
.subcommand(clap::App::new("SIOCADDRT"))
.subcommand(clap::App::new("IP6T_SO_ORIGINAL_DST"))
.subcommand(clap::App::new("NF_IP6_PRI_LAST"))
.subcommand(clap::App::new("NF_IP6_PRI_CONNTRACK_HELPER"))
.subcommand(clap::App::new("NF_IP6_PRI_SELINUX_LAST"))
.subcommand(clap::App::new("NF_IP6_PRI_NAT_SRC"))
.subcommand(clap::App::new("NF_IP6_PRI_SECURITY"))
.subcommand(clap::App::new("NF_IP6_PRI_FILTER"))
.subcommand(clap::App::new("NF_IP6_PRI_NAT_DST"))
.subcommand(clap::App::new("NF_IP6_PRI_MANGLE"))
.subcommand(clap::App::new("NF_IP6_PRI_CONNTRACK"))
.subcommand(clap::App::new("NF_IP6_PRI_SELINUX_FIRST"))
.subcommand(clap::App::new("NF_IP6_PRI_RAW"))
.subcommand(clap::App::new("NF_IP6_PRI_CONNTRACK_DEFRAG"))
.subcommand(clap::App::new("NF_IP6_PRI_FIRST"))
.subcommand(clap::App::new("NF_IP6_NUMHOOKS"))
.subcommand(clap::App::new("NF_IP6_POST_ROUTING"))
.subcommand(clap::App::new("NF_IP6_LOCAL_OUT"))
.subcommand(clap::App::new("NF_IP6_FORWARD"))
.subcommand(clap::App::new("NF_IP6_LOCAL_IN"))
.subcommand(clap::App::new("NF_IP6_PRE_ROUTING"))
.subcommand(clap::App::new("NF_IP_PRI_LAST"))
.subcommand(clap::App::new("NF_IP_PRI_CONNTRACK_CONFIRM"))
.subcommand(clap::App::new("NF_IP_PRI_CONNTRACK_HELPER"))
.subcommand(clap::App::new("NF_IP_PRI_SELINUX_LAST"))
.subcommand(clap::App::new("NF_IP_PRI_NAT_SRC"))
.subcommand(clap::App::new("NF_IP_PRI_SECURITY"))
.subcommand(clap::App::new("NF_IP_PRI_FILTER"))
.subcommand(clap::App::new("NF_IP_PRI_NAT_DST"))
.subcommand(clap::App::new("NF_IP_PRI_MANGLE"))
.subcommand(clap::App::new("NF_IP_PRI_CONNTRACK"))
.subcommand(clap::App::new("NF_IP_PRI_SELINUX_FIRST"))
.subcommand(clap::App::new("NF_IP_PRI_RAW"))
.subcommand(clap::App::new("NF_IP_PRI_CONNTRACK_DEFRAG"))
.subcommand(clap::App::new("NF_IP_PRI_FIRST"))
.subcommand(clap::App::new("NF_IP_NUMHOOKS"))
.subcommand(clap::App::new("NF_IP_POST_ROUTING"))
.subcommand(clap::App::new("NF_IP_LOCAL_OUT"))
.subcommand(clap::App::new("NF_IP_FORWARD"))
.subcommand(clap::App::new("NF_IP_LOCAL_IN"))
.subcommand(clap::App::new("NF_IP_PRE_ROUTING"))
.subcommand(clap::App::new("NFPROTO_NUMPROTO"))
.subcommand(clap::App::new("NFPROTO_DECNET"))
.subcommand(clap::App::new("NFPROTO_IPV6"))
.subcommand(clap::App::new("NFPROTO_BRIDGE"))
.subcommand(clap::App::new("NFPROTO_ARP"))
.subcommand(clap::App::new("NFPROTO_IPV4"))
.subcommand(clap::App::new("NFPROTO_UNSPEC"))
.subcommand(clap::App::new("NF_INET_NUMHOOKS"))
.subcommand(clap::App::new("NF_INET_POST_ROUTING"))
.subcommand(clap::App::new("NF_INET_LOCAL_OUT"))
.subcommand(clap::App::new("NF_INET_FORWARD"))
.subcommand(clap::App::new("NF_INET_LOCAL_IN"))
.subcommand(clap::App::new("NF_INET_PRE_ROUTING"))
.subcommand(clap::App::new("NF_VERDICT_BITS"))
.subcommand(clap::App::new("NF_VERDICT_QBITS"))
.subcommand(clap::App::new("NF_VERDICT_QMASK"))
.subcommand(clap::App::new("NF_VERDICT_FLAG_QUEUE_BYPASS"))
.subcommand(clap::App::new("NF_VERDICT_MASK"))
.subcommand(clap::App::new("NF_MAX_VERDICT"))
.subcommand(clap::App::new("NF_STOP"))
.subcommand(clap::App::new("NF_REPEAT"))
.subcommand(clap::App::new("NF_QUEUE"))
.subcommand(clap::App::new("NF_STOLEN"))
.subcommand(clap::App::new("NF_ACCEPT"))
.subcommand(clap::App::new("NF_DROP"))
.subcommand(clap::App::new("PACKET_MR_UNICAST"))
.subcommand(clap::App::new("PACKET_MR_ALLMULTI"))
.subcommand(clap::App::new("PACKET_MR_PROMISC"))
.subcommand(clap::App::new("PACKET_MR_MULTICAST"))
.subcommand(clap::App::new("PACKET_DROP_MEMBERSHIP"))
.subcommand(clap::App::new("PACKET_ADD_MEMBERSHIP"))
.subcommand(clap::App::new("CTRL_ATTR_MCAST_GRP_ID"))
.subcommand(clap::App::new("CTRL_ATTR_MCAST_GRP_NAME"))
.subcommand(clap::App::new("CTRL_ATTR_MCAST_GRP_UNSPEC"))
.subcommand(clap::App::new("CTRL_ATTR_OP_FLAGS"))
.subcommand(clap::App::new("CTRL_ATTR_OP_ID"))
.subcommand(clap::App::new("CTRL_ATTR_OP_UNSPEC"))
.subcommand(clap::App::new("CTRL_ATTR_MCAST_GROUPS"))
.subcommand(clap::App::new("CTRL_ATTR_OPS"))
.subcommand(clap::App::new("CTRL_ATTR_MAXATTR"))
.subcommand(clap::App::new("CTRL_ATTR_HDRSIZE"))
.subcommand(clap::App::new("CTRL_ATTR_VERSION"))
.subcommand(clap::App::new("CTRL_ATTR_FAMILY_NAME"))
.subcommand(clap::App::new("CTRL_ATTR_FAMILY_ID"))
.subcommand(clap::App::new("CTRL_ATTR_UNSPEC"))
.subcommand(clap::App::new("CTRL_CMD_GETMCAST_GRP"))
.subcommand(clap::App::new("CTRL_CMD_DELMCAST_GRP"))
.subcommand(clap::App::new("CTRL_CMD_NEWMCAST_GRP"))
.subcommand(clap::App::new("CTRL_CMD_GETOPS"))
.subcommand(clap::App::new("CTRL_CMD_DELOPS"))
.subcommand(clap::App::new("CTRL_CMD_NEWOPS"))
.subcommand(clap::App::new("CTRL_CMD_GETFAMILY"))
.subcommand(clap::App::new("CTRL_CMD_DELFAMILY"))
.subcommand(clap::App::new("CTRL_CMD_NEWFAMILY"))
.subcommand(clap::App::new("CTRL_CMD_UNSPEC"))
.subcommand(clap::App::new("GENL_ID_CTRL"))
.subcommand(clap::App::new("GENL_CMD_CAP_HASPOL"))
.subcommand(clap::App::new("GENL_CMD_CAP_DUMP"))
.subcommand(clap::App::new("GENL_CMD_CAP_DO"))
.subcommand(clap::App::new("GENL_ADMIN_PERM"))
.subcommand(clap::App::new("GENL_MAX_ID"))
.subcommand(clap::App::new("GENL_MIN_ID"))
.subcommand(clap::App::new("GENL_NAMSIZ"))
.subcommand(clap::App::new("NFQA_SKB_CSUM_NOTVERIFIED"))
.subcommand(clap::App::new("NFQA_SKB_GSO"))
.subcommand(clap::App::new("NFQA_SKB_CSUMNOTREADY"))
.subcommand(clap::App::new("NFQA_CFG_F_MAX"))
.subcommand(clap::App::new("NFQA_CFG_F_SECCTX"))
.subcommand(clap::App::new("NFQA_CFG_F_UID_GID"))
.subcommand(clap::App::new("NFQA_CFG_F_GSO"))
.subcommand(clap::App::new("NFQA_CFG_F_CONNTRACK"))
.subcommand(clap::App::new("NFQA_CFG_F_FAIL_OPEN"))
.subcommand(clap::App::new("NFQA_CFG_FLAGS"))
.subcommand(clap::App::new("NFQA_CFG_MASK"))
.subcommand(clap::App::new("NFQA_CFG_QUEUE_MAXLEN"))
.subcommand(clap::App::new("NFQA_CFG_PARAMS"))
.subcommand(clap::App::new("NFQA_CFG_CMD"))
.subcommand(clap::App::new("NFQA_CFG_UNSPEC"))
.subcommand(clap::App::new("NFQNL_COPY_PACKET"))
.subcommand(clap::App::new("NFQNL_COPY_META"))
.subcommand(clap::App::new("NFQNL_COPY_NONE"))
.subcommand(clap::App::new("NFQNL_CFG_CMD_PF_UNBIND"))
.subcommand(clap::App::new("NFQNL_CFG_CMD_PF_BIND"))
.subcommand(clap::App::new("NFQNL_CFG_CMD_UNBIND"))
.subcommand(clap::App::new("NFQNL_CFG_CMD_BIND"))
.subcommand(clap::App::new("NFQNL_CFG_CMD_NONE"))
.subcommand(clap::App::new("NFQA_SECCTX"))
.subcommand(clap::App::new("NFQA_GID"))
.subcommand(clap::App::new("NFQA_UID"))
.subcommand(clap::App::new("NFQA_EXP"))
.subcommand(clap::App::new("NFQA_SKB_INFO"))
.subcommand(clap::App::new("NFQA_CAP_LEN"))
.subcommand(clap::App::new("NFQA_CT_INFO"))
.subcommand(clap::App::new("NFQA_CT"))
.subcommand(clap::App::new("NFQA_PAYLOAD"))
.subcommand(clap::App::new("NFQA_HWADDR"))
.subcommand(clap::App::new("NFQA_IFINDEX_PHYSOUTDEV"))
.subcommand(clap::App::new("NFQA_IFINDEX_PHYSINDEV"))
.subcommand(clap::App::new("NFQA_IFINDEX_OUTDEV"))
.subcommand(clap::App::new("NFQA_IFINDEX_INDEV"))
.subcommand(clap::App::new("NFQA_TIMESTAMP"))
.subcommand(clap::App::new("NFQA_MARK"))
.subcommand(clap::App::new("NFQA_VERDICT_HDR"))
.subcommand(clap::App::new("NFQA_PACKET_HDR"))
.subcommand(clap::App::new("NFQA_UNSPEC"))
.subcommand(clap::App::new("NFQNL_MSG_VERDICT_BATCH"))
.subcommand(clap::App::new("NFQNL_MSG_CONFIG"))
.subcommand(clap::App::new("NFQNL_MSG_VERDICT"))
.subcommand(clap::App::new("NFQNL_MSG_PACKET"))
.subcommand(clap::App::new("NFULNL_CFG_F_CONNTRACK"))
.subcommand(clap::App::new("NFULNL_CFG_F_SEQ_GLOBAL"))
.subcommand(clap::App::new("NFULNL_CFG_F_SEQ"))
.subcommand(clap::App::new("NFULNL_COPY_PACKET"))
.subcommand(clap::App::new("NFULNL_COPY_META"))
.subcommand(clap::App::new("NFULNL_COPY_NONE"))
.subcommand(clap::App::new("NFULA_CFG_FLAGS"))
.subcommand(clap::App::new("NFULA_CFG_QTHRESH"))
.subcommand(clap::App::new("NFULA_CFG_TIMEOUT"))
.subcommand(clap::App::new("NFULA_CFG_NLBUFSIZ"))
.subcommand(clap::App::new("NFULA_CFG_MODE"))
.subcommand(clap::App::new("NFULA_CFG_CMD"))
.subcommand(clap::App::new("NFULA_CFG_UNSPEC"))
.subcommand(clap::App::new("NFULNL_CFG_CMD_PF_UNBIND"))
.subcommand(clap::App::new("NFULNL_CFG_CMD_PF_BIND"))
.subcommand(clap::App::new("NFULNL_CFG_CMD_UNBIND"))
.subcommand(clap::App::new("NFULNL_CFG_CMD_BIND"))
.subcommand(clap::App::new("NFULNL_CFG_CMD_NONE"))
.subcommand(clap::App::new("NFULA_CT_INFO"))
.subcommand(clap::App::new("NFULA_CT"))
.subcommand(clap::App::new("NFULA_HWLEN"))
.subcommand(clap::App::new("NFULA_HWHEADER"))
.subcommand(clap::App::new("NFULA_HWTYPE"))
.subcommand(clap::App::new("NFULA_GID"))
.subcommand(clap::App::new("NFULA_SEQ_GLOBAL"))
.subcommand(clap::App::new("NFULA_SEQ"))
.subcommand(clap::App::new("NFULA_UID"))
.subcommand(clap::App::new("NFULA_PREFIX"))
.subcommand(clap::App::new("NFULA_PAYLOAD"))
.subcommand(clap::App::new("NFULA_HWADDR"))
.subcommand(clap::App::new("NFULA_IFINDEX_PHYSOUTDEV"))
.subcommand(clap::App::new("NFULA_IFINDEX_PHYSINDEV"))
.subcommand(clap::App::new("NFULA_IFINDEX_OUTDEV"))
.subcommand(clap::App::new("NFULA_IFINDEX_INDEV"))
.subcommand(clap::App::new("NFULA_TIMESTAMP"))
.subcommand(clap::App::new("NFULA_MARK"))
.subcommand(clap::App::new("NFULA_PACKET_HDR"))
.subcommand(clap::App::new("NFULA_UNSPEC"))
.subcommand(clap::App::new("NFULNL_MSG_CONFIG"))
.subcommand(clap::App::new("NFULNL_MSG_PACKET"))
.subcommand(clap::App::new("NFNL_MSG_BATCH_END"))
.subcommand(clap::App::new("NFNL_MSG_BATCH_BEGIN"))
.subcommand(clap::App::new("NFNL_SUBSYS_COUNT"))
.subcommand(clap::App::new("NFNL_SUBSYS_NFT_COMPAT"))
.subcommand(clap::App::new("NFNL_SUBSYS_NFTABLES"))
.subcommand(clap::App::new("NFNL_SUBSYS_CTHELPER"))
.subcommand(clap::App::new("NFNL_SUBSYS_CTNETLINK_TIMEOUT"))
.subcommand(clap::App::new("NFNL_SUBSYS_ACCT"))
.subcommand(clap::App::new("NFNL_SUBSYS_IPSET"))
.subcommand(clap::App::new("NFNL_SUBSYS_OSF"))
.subcommand(clap::App::new("NFNL_SUBSYS_ULOG"))
.subcommand(clap::App::new("NFNL_SUBSYS_QUEUE"))
.subcommand(clap::App::new("NFNL_SUBSYS_CTNETLINK_EXP"))
.subcommand(clap::App::new("NFNL_SUBSYS_CTNETLINK"))
.subcommand(clap::App::new("NFNL_SUBSYS_NONE"))
.subcommand(clap::App::new("NFNETLINK_V0"))
.subcommand(clap::App::new("NFNLGRP_ACCT_QUOTA"))
.subcommand(clap::App::new("NFNLGRP_NFTABLES"))
.subcommand(clap::App::new("NFNLGRP_CONNTRACK_EXP_DESTROY"))
.subcommand(clap::App::new("NFNLGRP_CONNTRACK_EXP_UPDATE"))
.subcommand(clap::App::new("NFNLGRP_CONNTRACK_EXP_NEW"))
.subcommand(clap::App::new("NFNLGRP_CONNTRACK_DESTROY"))
.subcommand(clap::App::new("NFNLGRP_CONNTRACK_UPDATE"))
.subcommand(clap::App::new("NFNLGRP_CONNTRACK_NEW"))
.subcommand(clap::App::new("NFNLGRP_NONE"))
.subcommand(clap::App::new("NLMSG_MIN_TYPE"))
.subcommand(clap::App::new("NLMSG_OVERRUN"))
.subcommand(clap::App::new("NLMSG_DONE"))
.subcommand(clap::App::new("NLMSG_ERROR"))
.subcommand(clap::App::new("NLMSG_NOOP"))
.subcommand(clap::App::new("POSIX_SPAWN_SETSCHEDULER"))
.subcommand(clap::App::new("POSIX_SPAWN_SETSCHEDPARAM"))
.subcommand(clap::App::new("POSIX_SPAWN_SETSIGMASK"))
.subcommand(clap::App::new("POSIX_SPAWN_SETSIGDEF"))
.subcommand(clap::App::new("POSIX_SPAWN_SETPGROUP"))
.subcommand(clap::App::new("POSIX_SPAWN_RESETIDS"))
.subcommand(clap::App::new("ETH_P_CAIF"))
.subcommand(clap::App::new("ETH_P_IEEE802154"))
.subcommand(clap::App::new("ETH_P_PHONET"))
.subcommand(clap::App::new("ETH_P_TRAILER"))
.subcommand(clap::App::new("ETH_P_DSA"))
.subcommand(clap::App::new("ETH_P_ARCNET"))
.subcommand(clap::App::new("ETH_P_HDLC"))
.subcommand(clap::App::new("ETH_P_ECONET"))
.subcommand(clap::App::new("ETH_P_IRDA"))
.subcommand(clap::App::new("ETH_P_CONTROL"))
.subcommand(clap::App::new("ETH_P_MOBITEX"))
.subcommand(clap::App::new("ETH_P_TR_802_2"))
.subcommand(clap::App::new("ETH_P_PPPTALK"))
.subcommand(clap::App::new("ETH_P_CANFD"))
.subcommand(clap::App::new("ETH_P_LOCALTALK"))
.subcommand(clap::App::new("ETH_P_PPP_MP"))
.subcommand(clap::App::new("ETH_P_WAN_PPP"))
.subcommand(clap::App::new("ETH_P_DDCMP"))
.subcommand(clap::App::new("ETH_P_SNAP"))
.subcommand(clap::App::new("ETH_P_802_2"))
.subcommand(clap::App::new("ETH_P_ALL"))
.subcommand(clap::App::new("ETH_P_AX25"))
.subcommand(clap::App::new("ETH_P_802_3"))
.subcommand(clap::App::new("ETH_P_802_3_MIN"))
.subcommand(clap::App::new("ETH_P_AF_IUCV"))
.subcommand(clap::App::new("ETH_P_EDSA"))
.subcommand(clap::App::new("ETH_P_QINQ3"))
.subcommand(clap::App::new("ETH_P_QINQ2"))
.subcommand(clap::App::new("ETH_P_QINQ1"))
.subcommand(clap::App::new("ETH_P_LOOPBACK"))
.subcommand(clap::App::new("ETH_P_80221"))
.subcommand(clap::App::new("ETH_P_FIP"))
.subcommand(clap::App::new("ETH_P_TDLS"))
.subcommand(clap::App::new("ETH_P_FCOE"))
.subcommand(clap::App::new("ETH_P_PRP"))
.subcommand(clap::App::new("ETH_P_1588"))
.subcommand(clap::App::new("ETH_P_MVRP"))
.subcommand(clap::App::new("ETH_P_8021AH"))
.subcommand(clap::App::new("ETH_P_MACSEC"))
.subcommand(clap::App::new("ETH_P_TIPC"))
.subcommand(clap::App::new("ETH_P_802_EX1"))
.subcommand(clap::App::new("ETH_P_8021AD"))
.subcommand(clap::App::new("ETH_P_AOE"))
.subcommand(clap::App::new("ETH_P_PAE"))
.subcommand(clap::App::new("ETH_P_ATMFATE"))
.subcommand(clap::App::new("ETH_P_LINK_CTL"))
.subcommand(clap::App::new("ETH_P_PPP_SES"))
.subcommand(clap::App::new("ETH_P_PPP_DISC"))
.subcommand(clap::App::new("ETH_P_ATMMPOA"))
.subcommand(clap::App::new("ETH_P_MPLS_MC"))
.subcommand(clap::App::new("ETH_P_MPLS_UC"))
.subcommand(clap::App::new("ETH_P_WCCP"))
.subcommand(clap::App::new("ETH_P_SLOW"))
.subcommand(clap::App::new("ETH_P_PAUSE"))
.subcommand(clap::App::new("ETH_P_IPV6"))
.subcommand(clap::App::new("ETH_P_IPX"))
.subcommand(clap::App::new("ETH_P_8021Q"))
.subcommand(clap::App::new("ETH_P_AARP"))
.subcommand(clap::App::new("ETH_P_ATALK"))
.subcommand(clap::App::new("ETH_P_RARP"))
.subcommand(clap::App::new("ETH_P_TEB"))
.subcommand(clap::App::new("ETH_P_SCA"))
.subcommand(clap::App::new("ETH_P_CUST"))
.subcommand(clap::App::new("ETH_P_DIAG"))
.subcommand(clap::App::new("ETH_P_LAT"))
.subcommand(clap::App::new("ETH_P_DNA_RT"))
.subcommand(clap::App::new("ETH_P_DNA_RC"))
.subcommand(clap::App::new("ETH_P_DNA_DL"))
.subcommand(clap::App::new("ETH_P_DEC"))
.subcommand(clap::App::new("ETH_P_BATMAN"))
.subcommand(clap::App::new("ETH_P_IEEEPUPAT"))
.subcommand(clap::App::new("ETH_P_IEEEPUP"))
.subcommand(clap::App::new("ETH_P_BPQ"))
.subcommand(clap::App::new("ETH_P_ARP"))
.subcommand(clap::App::new("ETH_P_X25"))
.subcommand(clap::App::new("ETH_P_IP"))
.subcommand(clap::App::new("ETH_P_PUPAT"))
.subcommand(clap::App::new("ETH_P_PUP"))
.subcommand(clap::App::new("ETH_P_LOOP"))
.subcommand(clap::App::new("ETH_FCS_LEN"))
.subcommand(clap::App::new("ETH_FRAME_LEN"))
.subcommand(clap::App::new("ETH_DATA_LEN"))
.subcommand(clap::App::new("ETH_ZLEN"))
.subcommand(clap::App::new("ETH_HLEN"))
.subcommand(clap::App::new("ETH_ALEN"))
.subcommand(clap::App::new("PT_GNU_RELRO"))
.subcommand(clap::App::new("PT_GNU_STACK"))
.subcommand(clap::App::new("PT_GNU_EH_FRAME"))
.subcommand(clap::App::new("PT_LOOS"))
.subcommand(clap::App::new("PT_NUM"))
.subcommand(clap::App::new("PT_TLS"))
.subcommand(clap::App::new("PT_PHDR"))
.subcommand(clap::App::new("PT_SHLIB"))
.subcommand(clap::App::new("PT_NOTE"))
.subcommand(clap::App::new("PT_INTERP"))
.subcommand(clap::App::new("PT_DYNAMIC"))
.subcommand(clap::App::new("PT_LOAD"))
.subcommand(clap::App::new("PT_NULL"))
.subcommand(clap::App::new("MFD_HUGETLB"))
.subcommand(clap::App::new("MFD_ALLOW_SEALING"))
.subcommand(clap::App::new("MFD_CLOEXEC"))
.subcommand(clap::App::new("CMSPAR"))
.subcommand(clap::App::new("IUTF8"))
.subcommand(clap::App::new("IPV6_FLOWINFO_PRIORITY"))
.subcommand(clap::App::new("IPV6_FLOWINFO_FLOWLABEL"))
.subcommand(clap::App::new("IPV6_FLOWINFO_SEND"))
.subcommand(clap::App::new("IPV6_FLOWLABEL_MGR"))
.subcommand(clap::App::new("IPV6_RECVORIGDSTADDR"))
.subcommand(clap::App::new("IPV6_ORIGDSTADDR"))
.subcommand(clap::App::new("IPV6_FLOWINFO"))
.subcommand(clap::App::new("IP_RECVORIGDSTADDR"))
.subcommand(clap::App::new("IP_ORIGDSTADDR"))
.subcommand(clap::App::new("SO_ORIGINAL_DST"))
.subcommand(clap::App::new("ENOATTR"))
.subcommand(clap::App::new("FALLOC_FL_UNSHARE_RANGE"))
.subcommand(clap::App::new("FALLOC_FL_INSERT_RANGE"))
.subcommand(clap::App::new("FALLOC_FL_ZERO_RANGE"))
.subcommand(clap::App::new("FALLOC_FL_COLLAPSE_RANGE"))
.subcommand(clap::App::new("FALLOC_FL_PUNCH_HOLE"))
.subcommand(clap::App::new("FALLOC_FL_KEEP_SIZE"))
.subcommand(clap::App::new("_POSIX_VDISABLE"))
.subcommand(clap::App::new("XATTR_REPLACE"))
.subcommand(clap::App::new("XATTR_CREATE"))
.subcommand(clap::App::new("TFD_TIMER_ABSTIME"))
.subcommand(clap::App::new("TFD_NONBLOCK"))
.subcommand(clap::App::new("TFD_CLOEXEC"))
.subcommand(clap::App::new("ITIMER_PROF"))
.subcommand(clap::App::new("ITIMER_VIRTUAL"))
.subcommand(clap::App::new("ITIMER_REAL"))
.subcommand(clap::App::new("SECCOMP_MODE_FILTER"))
.subcommand(clap::App::new("SECCOMP_MODE_STRICT"))
.subcommand(clap::App::new("SECCOMP_MODE_DISABLED"))
.subcommand(clap::App::new("GRND_RANDOM"))
.subcommand(clap::App::new("GRND_NONBLOCK"))
.subcommand(clap::App::new("PR_CAP_AMBIENT_CLEAR_ALL"))
.subcommand(clap::App::new("PR_CAP_AMBIENT_LOWER"))
.subcommand(clap::App::new("PR_CAP_AMBIENT_RAISE"))
.subcommand(clap::App::new("PR_CAP_AMBIENT_IS_SET"))
.subcommand(clap::App::new("PR_CAP_AMBIENT"))
.subcommand(clap::App::new("PR_FP_MODE_FRE"))
.subcommand(clap::App::new("PR_FP_MODE_FR"))
.subcommand(clap::App::new("PR_GET_FP_MODE"))
.subcommand(clap::App::new("PR_SET_FP_MODE"))
.subcommand(clap::App::new("PR_MPX_DISABLE_MANAGEMENT"))
.subcommand(clap::App::new("PR_MPX_ENABLE_MANAGEMENT"))
.subcommand(clap::App::new("PR_GET_THP_DISABLE"))
.subcommand(clap::App::new("PR_SET_THP_DISABLE"))
.subcommand(clap::App::new("PR_GET_TID_ADDRESS"))
.subcommand(clap::App::new("PR_GET_NO_NEW_PRIVS"))
.subcommand(clap::App::new("PR_SET_NO_NEW_PRIVS"))
.subcommand(clap::App::new("PR_GET_CHILD_SUBREAPER"))
.subcommand(clap::App::new("PR_SET_CHILD_SUBREAPER"))
.subcommand(clap::App::new("PR_SET_PTRACER"))
.subcommand(clap::App::new("PR_SET_MM_MAP_SIZE"))
.subcommand(clap::App::new("PR_SET_MM_MAP"))
.subcommand(clap::App::new("PR_SET_MM_EXE_FILE"))
.subcommand(clap::App::new("PR_SET_MM_AUXV"))
.subcommand(clap::App::new("PR_SET_MM_ENV_END"))
.subcommand(clap::App::new("PR_SET_MM_ENV_START"))
.subcommand(clap::App::new("PR_SET_MM_ARG_END"))
.subcommand(clap::App::new("PR_SET_MM_ARG_START"))
.subcommand(clap::App::new("PR_SET_MM_BRK"))
.subcommand(clap::App::new("PR_SET_MM_START_BRK"))
.subcommand(clap::App::new("PR_SET_MM_START_STACK"))
.subcommand(clap::App::new("PR_SET_MM_END_DATA"))
.subcommand(clap::App::new("PR_SET_MM_START_DATA"))
.subcommand(clap::App::new("PR_SET_MM_END_CODE"))
.subcommand(clap::App::new("PR_SET_MM_START_CODE"))
.subcommand(clap::App::new("PR_SET_MM"))
.subcommand(clap::App::new("PR_MCE_KILL_GET"))
.subcommand(clap::App::new("PR_MCE_KILL_DEFAULT"))
.subcommand(clap::App::new("PR_MCE_KILL_EARLY"))
.subcommand(clap::App::new("PR_MCE_KILL_LATE"))
.subcommand(clap::App::new("PR_MCE_KILL_SET"))
.subcommand(clap::App::new("PR_MCE_KILL_CLEAR"))
.subcommand(clap::App::new("PR_MCE_KILL"))
.subcommand(clap::App::new("PR_TASK_PERF_EVENTS_ENABLE"))
.subcommand(clap::App::new("PR_TASK_PERF_EVENTS_DISABLE"))
.subcommand(clap::App::new("PR_GET_TIMERSLACK"))
.subcommand(clap::App::new("PR_SET_TIMERSLACK"))
.subcommand(clap::App::new("PR_SET_SECUREBITS"))
.subcommand(clap::App::new("PR_GET_SECUREBITS"))
.subcommand(clap::App::new("PR_TSC_SIGSEGV"))
.subcommand(clap::App::new("PR_TSC_ENABLE"))
.subcommand(clap::App::new("PR_SET_TSC"))
.subcommand(clap::App::new("PR_GET_TSC"))
.subcommand(clap::App::new("PR_CAPBSET_DROP"))
.subcommand(clap::App::new("PR_CAPBSET_READ"))
.subcommand(clap::App::new("PR_SET_SECCOMP"))
.subcommand(clap::App::new("PR_GET_SECCOMP"))
.subcommand(clap::App::new("PR_ENDIAN_PPC_LITTLE"))
.subcommand(clap::App::new("PR_ENDIAN_LITTLE"))
.subcommand(clap::App::new("PR_ENDIAN_BIG"))
.subcommand(clap::App::new("PR_SET_ENDIAN"))
.subcommand(clap::App::new("PR_GET_ENDIAN"))
.subcommand(clap::App::new("PR_GET_NAME"))
.subcommand(clap::App::new("PR_SET_NAME"))
.subcommand(clap::App::new("PR_TIMING_TIMESTAMP"))
.subcommand(clap::App::new("PR_TIMING_STATISTICAL"))
.subcommand(clap::App::new("PR_SET_TIMING"))
.subcommand(clap::App::new("PR_GET_TIMING"))
.subcommand(clap::App::new("PR_FP_EXC_PRECISE"))
.subcommand(clap::App::new("PR_FP_EXC_ASYNC"))
.subcommand(clap::App::new("PR_FP_EXC_NONRECOV"))
.subcommand(clap::App::new("PR_FP_EXC_DISABLED"))
.subcommand(clap::App::new("PR_FP_EXC_INV"))
.subcommand(clap::App::new("PR_FP_EXC_RES"))
.subcommand(clap::App::new("PR_FP_EXC_UND"))
.subcommand(clap::App::new("PR_FP_EXC_OVF"))
.subcommand(clap::App::new("PR_FP_EXC_DIV"))
.subcommand(clap::App::new("PR_FP_EXC_SW_ENABLE"))
.subcommand(clap::App::new("PR_SET_FPEXC"))
.subcommand(clap::App::new("PR_GET_FPEXC"))
.subcommand(clap::App::new("PR_FPEMU_SIGFPE"))
.subcommand(clap::App::new("PR_FPEMU_NOPRINT"))
.subcommand(clap::App::new("PR_SET_FPEMU"))
.subcommand(clap::App::new("PR_GET_FPEMU"))
.subcommand(clap::App::new("PR_SET_KEEPCAPS"))
.subcommand(clap::App::new("PR_GET_KEEPCAPS"))
.subcommand(clap::App::new("PR_UNALIGN_SIGBUS"))
.subcommand(clap::App::new("PR_UNALIGN_NOPRINT"))
.subcommand(clap::App::new("PR_SET_UNALIGN"))
.subcommand(clap::App::new("PR_GET_UNALIGN"))
.subcommand(clap::App::new("PR_SET_DUMPABLE"))
.subcommand(clap::App::new("PR_GET_DUMPABLE"))
.subcommand(clap::App::new("PR_GET_PDEATHSIG"))
.subcommand(clap::App::new("PR_SET_PDEATHSIG"))
.subcommand(clap::App::new("MREMAP_FIXED"))
.subcommand(clap::App::new("MREMAP_MAYMOVE"))
.subcommand(clap::App::new("LIO_NOWAIT"))
.subcommand(clap::App::new("LIO_WAIT"))
.subcommand(clap::App::new("LIO_NOP"))
.subcommand(clap::App::new("LIO_WRITE"))
.subcommand(clap::App::new("LIO_READ"))
.subcommand(clap::App::new("AIO_ALLDONE"))
.subcommand(clap::App::new("AIO_NOTCANCELED"))
.subcommand(clap::App::new("AIO_CANCELED"))
.subcommand(clap::App::new("SYNC_FILE_RANGE_WAIT_AFTER"))
.subcommand(clap::App::new("SYNC_FILE_RANGE_WRITE"))
.subcommand(clap::App::new("SYNC_FILE_RANGE_WAIT_BEFORE"))
.subcommand(clap::App::new("NI_DGRAM"))
.subcommand(clap::App::new("NI_NAMEREQD"))
.subcommand(clap::App::new("NI_NOFQDN"))
.subcommand(clap::App::new("NI_NUMERICSERV"))
.subcommand(clap::App::new("NI_NUMERICHOST"))
.subcommand(clap::App::new("EAI_OVERFLOW"))
.subcommand(clap::App::new("EAI_SYSTEM"))
.subcommand(clap::App::new("EAI_MEMORY"))
.subcommand(clap::App::new("EAI_SERVICE"))
.subcommand(clap::App::new("EAI_SOCKTYPE"))
.subcommand(clap::App::new("EAI_FAMILY"))
.subcommand(clap::App::new("EAI_NODATA"))
.subcommand(clap::App::new("EAI_FAIL"))
.subcommand(clap::App::new("EAI_AGAIN"))
.subcommand(clap::App::new("EAI_NONAME"))
.subcommand(clap::App::new("EAI_BADFLAGS"))
.subcommand(clap::App::new("AI_NUMERICSERV"))
.subcommand(clap::App::new("AI_ADDRCONFIG"))
.subcommand(clap::App::new("AI_ALL"))
.subcommand(clap::App::new("AI_V4MAPPED"))
.subcommand(clap::App::new("AI_NUMERICHOST"))
.subcommand(clap::App::new("AI_CANONNAME"))
.subcommand(clap::App::new("AI_PASSIVE"))
.subcommand(clap::App::new("RB_KEXEC"))
.subcommand(clap::App::new("RB_SW_SUSPEND"))
.subcommand(clap::App::new("RB_POWER_OFF"))
.subcommand(clap::App::new("RB_DISABLE_CAD"))
.subcommand(clap::App::new("RB_ENABLE_CAD"))
.subcommand(clap::App::new("RB_HALT_SYSTEM"))
.subcommand(clap::App::new("RB_AUTOBOOT"))
.subcommand(clap::App::new("LOG_NFACILITIES"))
.subcommand(clap::App::new("EFD_SEMAPHORE"))
.subcommand(clap::App::new("QFMT_VFS_V1"))
.subcommand(clap::App::new("QFMT_VFS_V0"))
.subcommand(clap::App::new("QFMT_VFS_OLD"))
.subcommand(clap::App::new("EPOLLONESHOT"))
.subcommand(clap::App::new("EPOLLEXCLUSIVE"))
.subcommand(clap::App::new("EPOLLRDHUP"))
.subcommand(clap::App::new("SHM_NORESERVE"))
.subcommand(clap::App::new("SHM_HUGETLB"))
.subcommand(clap::App::new("SHM_UNLOCK"))
.subcommand(clap::App::new("SHM_LOCK"))
.subcommand(clap::App::new("SHM_EXEC"))
.subcommand(clap::App::new("SHM_REMAP"))
.subcommand(clap::App::new("SHM_RND"))
.subcommand(clap::App::new("SHM_RDONLY"))
.subcommand(clap::App::new("SHM_W"))
.subcommand(clap::App::new("SHM_R"))
.subcommand(clap::App::new("MSG_COPY"))
.subcommand(clap::App::new("MSG_EXCEPT"))
.subcommand(clap::App::new("MSG_NOERROR"))
.subcommand(clap::App::new("MSG_INFO"))
.subcommand(clap::App::new("MSG_STAT"))
.subcommand(clap::App::new("IPC_INFO"))
.subcommand(clap::App::new("IPC_STAT"))
.subcommand(clap::App::new("IPC_SET"))
.subcommand(clap::App::new("IPC_RMID"))
.subcommand(clap::App::new("IPC_NOWAIT"))
.subcommand(clap::App::new("IPC_EXCL"))
.subcommand(clap::App::new("IPC_CREAT"))
.subcommand(clap::App::new("IPC_PRIVATE"))
.subcommand(clap::App::new("PF_XDP"))
.subcommand(clap::App::new("PF_VSOCK"))
.subcommand(clap::App::new("PF_NFC"))
.subcommand(clap::App::new("PF_MPLS"))
.subcommand(clap::App::new("PF_IB"))
.subcommand(clap::App::new("AF_XDP"))
.subcommand(clap::App::new("AF_VSOCK"))
.subcommand(clap::App::new("AF_NFC"))
.subcommand(clap::App::new("AF_MPLS"))
.subcommand(clap::App::new("AF_IB"))
.subcommand(clap::App::new("IP_UNICAST_IF"))
.subcommand(clap::App::new("IP_MULTICAST_ALL"))
.subcommand(clap::App::new("MCAST_MSFILTER"))
.subcommand(clap::App::new("MCAST_LEAVE_SOURCE_GROUP"))
.subcommand(clap::App::new("MCAST_JOIN_SOURCE_GROUP"))
.subcommand(clap::App::new("MCAST_LEAVE_GROUP"))
.subcommand(clap::App::new("MCAST_UNBLOCK_SOURCE"))
.subcommand(clap::App::new("MCAST_BLOCK_SOURCE"))
.subcommand(clap::App::new("MCAST_JOIN_GROUP"))
.subcommand(clap::App::new("IP_MSFILTER"))
.subcommand(clap::App::new("IPPROTO_MAX"))
.subcommand(clap::App::new("IPPROTO_RAW"))
.subcommand(clap::App::new("IPPROTO_MPLS"))
.subcommand(clap::App::new("IPPROTO_UDPLITE"))
.subcommand(clap::App::new("IPPROTO_MH"))
.subcommand(clap::App::new("IPPROTO_SCTP"))
.subcommand(clap::App::new("IPPROTO_COMP"))
.subcommand(clap::App::new("IPPROTO_PIM"))
.subcommand(clap::App::new("IPPROTO_ENCAP"))
.subcommand(clap::App::new("IPPROTO_BEETPH"))
.subcommand(clap::App::new("IPPROTO_MTP"))
.subcommand(clap::App::new("IPPROTO_DSTOPTS"))
.subcommand(clap::App::new("IPPROTO_NONE"))
.subcommand(clap::App::new("IPPROTO_AH"))
.subcommand(clap::App::new("IPPROTO_ESP"))
.subcommand(clap::App::new("IPPROTO_GRE"))
.subcommand(clap::App::new("IPPROTO_RSVP"))
.subcommand(clap::App::new("IPPROTO_FRAGMENT"))
.subcommand(clap::App::new("IPPROTO_ROUTING"))
.subcommand(clap::App::new("IPPROTO_DCCP"))
.subcommand(clap::App::new("IPPROTO_TP"))
.subcommand(clap::App::new("IPPROTO_IDP"))
.subcommand(clap::App::new("IPPROTO_PUP"))
.subcommand(clap::App::new("IPPROTO_EGP"))
.subcommand(clap::App::new("IPPROTO_IPIP"))
.subcommand(clap::App::new("IPPROTO_IGMP"))
.subcommand(clap::App::new("IPPROTO_HOPOPTS"))
.subcommand(clap::App::new("SCHED_RESET_ON_FORK"))
.subcommand(clap::App::new("SCHED_IDLE"))
.subcommand(clap::App::new("SCHED_BATCH"))
.subcommand(clap::App::new("SCHED_RR"))
.subcommand(clap::App::new("SCHED_FIFO"))
.subcommand(clap::App::new("SCHED_OTHER"))
.subcommand(clap::App::new("RENAME_WHITEOUT"))
.subcommand(clap::App::new("RENAME_EXCHANGE"))
.subcommand(clap::App::new("RENAME_NOREPLACE"))
.subcommand(clap::App::new("__SIZEOF_PTHREAD_COND_T"))
.subcommand(clap::App::new("PTHREAD_PROCESS_SHARED"))
.subcommand(clap::App::new("PTHREAD_PROCESS_PRIVATE"))
.subcommand(clap::App::new("PTHREAD_MUTEX_DEFAULT"))
.subcommand(clap::App::new("PTHREAD_MUTEX_ERRORCHECK"))
.subcommand(clap::App::new("PTHREAD_MUTEX_RECURSIVE"))
.subcommand(clap::App::new("PTHREAD_MUTEX_NORMAL"))
.subcommand(clap::App::new("TCP_MD5SIG"))
.subcommand(clap::App::new("AT_EACCESS"))
.subcommand(clap::App::new("RTLD_NOW"))
.subcommand(clap::App::new("RTLD_NODELETE"))
.subcommand(clap::App::new("ST_NODIRATIME"))
.subcommand(clap::App::new("ST_NOATIME"))
.subcommand(clap::App::new("ST_IMMUTABLE"))
.subcommand(clap::App::new("ST_APPEND"))
.subcommand(clap::App::new("ST_WRITE"))
.subcommand(clap::App::new("ST_MANDLOCK"))
.subcommand(clap::App::new("ST_SYNCHRONOUS"))
.subcommand(clap::App::new("ST_NOEXEC"))
.subcommand(clap::App::new("ST_NODEV"))
.subcommand(clap::App::new("ST_NOSUID"))
.subcommand(clap::App::new("ST_RDONLY"))
.subcommand(clap::App::new("IFF_NOFILTER"))
.subcommand(clap::App::new("IFF_PERSIST"))
.subcommand(clap::App::new("IFF_DETACH_QUEUE"))
.subcommand(clap::App::new("IFF_ATTACH_QUEUE"))
.subcommand(clap::App::new("IFF_MULTI_QUEUE"))
.subcommand(clap::App::new("IFF_TUN_EXCL"))
.subcommand(clap::App::new("IFF_VNET_HDR"))
.subcommand(clap::App::new("IFF_ONE_QUEUE"))
.subcommand(clap::App::new("TUN_TYPE_MASK"))
.subcommand(clap::App::new("TUN_TAP_DEV"))
.subcommand(clap::App::new("TUN_TUN_DEV"))
.subcommand(clap::App::new("TUN_READQ_SIZE"))
.subcommand(clap::App::new("IFF_NO_PI"))
.subcommand(clap::App::new("IFF_TAP"))
.subcommand(clap::App::new("IFF_TUN"))
.subcommand(clap::App::new("IFLA_INFO_SLAVE_DATA"))
.subcommand(clap::App::new("IFLA_INFO_SLAVE_KIND"))
.subcommand(clap::App::new("IFLA_INFO_XSTATS"))
.subcommand(clap::App::new("IFLA_INFO_DATA"))
.subcommand(clap::App::new("IFLA_INFO_KIND"))
.subcommand(clap::App::new("IFLA_INFO_UNSPEC"))
.subcommand(clap::App::new("IFLA_PROTO_DOWN"))
.subcommand(clap::App::new("IFLA_PHYS_PORT_NAME"))
.subcommand(clap::App::new("IFLA_LINK_NETNSID"))
.subcommand(clap::App::new("IFLA_PHYS_SWITCH_ID"))
.subcommand(clap::App::new("IFLA_CARRIER_CHANGES"))
.subcommand(clap::App::new("IFLA_PHYS_PORT_ID"))
.subcommand(clap::App::new("IFLA_CARRIER"))
.subcommand(clap::App::new("IFLA_NUM_RX_QUEUES"))
.subcommand(clap::App::new("IFLA_NUM_TX_QUEUES"))
.subcommand(clap::App::new("IFLA_PROMISCUITY"))
.subcommand(clap::App::new("IFLA_EXT_MASK"))
.subcommand(clap::App::new("IFLA_NET_NS_FD"))
.subcommand(clap::App::new("IFLA_GROUP"))
.subcommand(clap::App::new("IFLA_AF_SPEC"))
.subcommand(clap::App::new("IFLA_PORT_SELF"))
.subcommand(clap::App::new("IFLA_VF_PORTS"))
.subcommand(clap::App::new("IFLA_STATS64"))
.subcommand(clap::App::new("IFLA_VFINFO_LIST"))
.subcommand(clap::App::new("IFLA_NUM_VF"))
.subcommand(clap::App::new("IFLA_IFALIAS"))
.subcommand(clap::App::new("IFLA_NET_NS_PID"))
.subcommand(clap::App::new("IFLA_LINKINFO"))
.subcommand(clap::App::new("IFLA_LINKMODE"))
.subcommand(clap::App::new("IFLA_OPERSTATE"))
.subcommand(clap::App::new("IFLA_WEIGHT"))
.subcommand(clap::App::new("IFLA_MAP"))
.subcommand(clap::App::new("IFLA_TXQLEN"))
.subcommand(clap::App::new("IFLA_PROTINFO"))
.subcommand(clap::App::new("IFLA_WIRELESS"))
.subcommand(clap::App::new("IFLA_MASTER"))
.subcommand(clap::App::new("IFLA_PRIORITY"))
.subcommand(clap::App::new("IFLA_COST"))
.subcommand(clap::App::new("IFLA_STATS"))
.subcommand(clap::App::new("IFLA_QDISC"))
.subcommand(clap::App::new("IFLA_LINK"))
.subcommand(clap::App::new("IFLA_MTU"))
.subcommand(clap::App::new("IFLA_IFNAME"))
.subcommand(clap::App::new("IFLA_BROADCAST"))
.subcommand(clap::App::new("IFLA_ADDRESS"))
.subcommand(clap::App::new("IFLA_UNSPEC"))
.subcommand(clap::App::new("IFA_F_PERMANENT"))
.subcommand(clap::App::new("IFA_F_TENTATIVE"))
.subcommand(clap::App::new("IFA_F_DEPRECATED"))
.subcommand(clap::App::new("IFA_F_HOMEADDRESS"))
.subcommand(clap::App::new("IFA_F_DADFAILED"))
.subcommand(clap::App::new("IFA_F_OPTIMISTIC"))
.subcommand(clap::App::new("IFA_F_NODAD"))
.subcommand(clap::App::new("IFA_F_TEMPORARY"))
.subcommand(clap::App::new("IFA_F_SECONDARY"))
.subcommand(clap::App::new("IFA_MULTICAST"))
.subcommand(clap::App::new("IFA_CACHEINFO"))
.subcommand(clap::App::new("IFA_ANYCAST"))
.subcommand(clap::App::new("IFA_BROADCAST"))
.subcommand(clap::App::new("IFA_LABEL"))
.subcommand(clap::App::new("IFA_LOCAL"))
.subcommand(clap::App::new("IFA_ADDRESS"))
.subcommand(clap::App::new("IFA_UNSPEC"))
.subcommand(clap::App::new("IFF_ECHO"))
.subcommand(clap::App::new("IFF_DORMANT"))
.subcommand(clap::App::new("IFF_LOWER_UP"))
.subcommand(clap::App::new("F_SEAL_FUTURE_WRITE"))
.subcommand(clap::App::new("F_ULOCK"))
.subcommand(clap::App::new("F_TLOCK"))
.subcommand(clap::App::new("F_TEST"))
.subcommand(clap::App::new("F_LOCK"))
.subcommand(clap::App::new("S_IREAD"))
.subcommand(clap::App::new("S_IWRITE"))
.subcommand(clap::App::new("S_IEXEC"))
.subcommand(clap::App::new("POSIX_MADV_WILLNEED"))
.subcommand(clap::App::new("POSIX_MADV_SEQUENTIAL"))
.subcommand(clap::App::new("POSIX_MADV_RANDOM"))
.subcommand(clap::App::new("POSIX_MADV_NORMAL"))
.subcommand(clap::App::new("GLOB_NOMATCH"))
.subcommand(clap::App::new("GLOB_ABORTED"))
.subcommand(clap::App::new("GLOB_NOSPACE"))
.subcommand(clap::App::new("GLOB_NOESCAPE"))
.subcommand(clap::App::new("GLOB_APPEND"))
.subcommand(clap::App::new("GLOB_NOCHECK"))
.subcommand(clap::App::new("GLOB_DOOFFS"))
.subcommand(clap::App::new("GLOB_NOSORT"))
.subcommand(clap::App::new("GLOB_MARK"))
.subcommand(clap::App::new("GLOB_ERR"))
.subcommand(clap::App::new("RLIM_SAVED_CUR"))
.subcommand(clap::App::new("RLIM_SAVED_MAX"))
.subcommand(clap::App::new("_SC_THREAD_ROBUST_PRIO_PROTECT"))
.subcommand(clap::App::new("_SC_THREAD_ROBUST_PRIO_INHERIT"))
.subcommand(clap::App::new("_SC_XOPEN_STREAMS"))
.subcommand(clap::App::new("_SC_TRACE_USER_EVENT_MAX"))
.subcommand(clap::App::new("_SC_TRACE_SYS_MAX"))
.subcommand(clap::App::new("_SC_TRACE_NAME_MAX"))
.subcommand(clap::App::new("_SC_TRACE_EVENT_NAME_MAX"))
.subcommand(clap::App::new("_SC_SS_REPL_MAX"))
.subcommand(clap::App::new("_SC_V7_LPBIG_OFFBIG"))
.subcommand(clap::App::new("_SC_V7_LP64_OFF64"))
.subcommand(clap::App::new("_SC_V7_ILP32_OFFBIG"))
.subcommand(clap::App::new("_SC_V7_ILP32_OFF32"))
.subcommand(clap::App::new("_SC_RAW_SOCKETS"))
.subcommand(clap::App::new("_SC_IPV6"))
.subcommand(clap::App::new("_SC_TRACE_LOG"))
.subcommand(clap::App::new("_SC_TRACE_INHERIT"))
.subcommand(clap::App::new("_SC_TRACE_EVENT_FILTER"))
.subcommand(clap::App::new("_SC_TRACE"))
.subcommand(clap::App::new("_SC_HOST_NAME_MAX"))
.subcommand(clap::App::new("_SC_V6_LPBIG_OFFBIG"))
.subcommand(clap::App::new("_SC_V6_LP64_OFF64"))
.subcommand(clap::App::new("_SC_V6_ILP32_OFFBIG"))
.subcommand(clap::App::new("_SC_V6_ILP32_OFF32"))
.subcommand(clap::App::new("_SC_2_PBS_CHECKPOINT"))
.subcommand(clap::App::new("_SC_STREAMS"))
.subcommand(clap::App::new("_SC_SYMLOOP_MAX"))
.subcommand(clap::App::new("_SC_2_PBS_TRACK"))
.subcommand(clap::App::new("_SC_2_PBS_MESSAGE"))
.subcommand(clap::App::new("_SC_2_PBS_LOCATE"))
.subcommand(clap::App::new("_SC_2_PBS_ACCOUNTING"))
.subcommand(clap::App::new("_SC_2_PBS"))
.subcommand(clap::App::new("_SC_TYPED_MEMORY_OBJECTS"))
.subcommand(clap::App::new("_SC_TIMEOUTS"))
.subcommand(clap::App::new("_SC_THREAD_SPORADIC_SERVER"))
.subcommand(clap::App::new("_SC_SPORADIC_SERVER"))
.subcommand(clap::App::new("_SC_SPAWN"))
.subcommand(clap::App::new("_SC_SHELL"))
.subcommand(clap::App::new("_SC_REGEXP"))
.subcommand(clap::App::new("_SC_SPIN_LOCKS"))
.subcommand(clap::App::new("_SC_READER_WRITER_LOCKS"))
.subcommand(clap::App::new("_SC_MONOTONIC_CLOCK"))
.subcommand(clap::App::new("_SC_THREAD_CPUTIME"))
.subcommand(clap::App::new("_SC_CPUTIME"))
.subcommand(clap::App::new("_SC_CLOCK_SELECTION"))
.subcommand(clap::App::new("_SC_BARRIERS"))
.subcommand(clap::App::new("_SC_ADVISORY_INFO"))
.subcommand(clap::App::new("_SC_XOPEN_REALTIME_THREADS"))
.subcommand(clap::App::new("_SC_XOPEN_REALTIME"))
.subcommand(clap::App::new("_SC_XOPEN_LEGACY"))
.subcommand(clap::App::new("_SC_XBS5_LPBIG_OFFBIG"))
.subcommand(clap::App::new("_SC_XBS5_LP64_OFF64"))
.subcommand(clap::App::new("_SC_XBS5_ILP32_OFFBIG"))
.subcommand(clap::App::new("_SC_XBS5_ILP32_OFF32"))
.subcommand(clap::App::new("_SC_NZERO"))
.subcommand(clap::App::new("_SC_XOPEN_XPG4"))
.subcommand(clap::App::new("_SC_XOPEN_XPG3"))
.subcommand(clap::App::new("_SC_XOPEN_XPG2"))
.subcommand(clap::App::new("_SC_2_UPE"))
.subcommand(clap::App::new("_SC_2_CHAR_TERM"))
.subcommand(clap::App::new("_SC_XOPEN_SHM"))
.subcommand(clap::App::new("_SC_XOPEN_ENH_I18N"))
.subcommand(clap::App::new("_SC_XOPEN_CRYPT"))
.subcommand(clap::App::new("_SC_XOPEN_UNIX"))
.subcommand(clap::App::new("_SC_XOPEN_XCU_VERSION"))
.subcommand(clap::App::new("_SC_XOPEN_VERSION"))
.subcommand(clap::App::new("_SC_PASS_MAX"))
.subcommand(clap::App::new("_SC_ATEXIT_MAX"))
.subcommand(clap::App::new("_SC_AVPHYS_PAGES"))
.subcommand(clap::App::new("_SC_PHYS_PAGES"))
.subcommand(clap::App::new("_SC_NPROCESSORS_ONLN"))
.subcommand(clap::App::new("_SC_NPROCESSORS_CONF"))
.subcommand(clap::App::new("_SC_THREAD_PROCESS_SHARED"))
.subcommand(clap::App::new("_SC_THREAD_PRIO_PROTECT"))
.subcommand(clap::App::new("_SC_THREAD_PRIO_INHERIT"))
.subcommand(clap::App::new("_SC_THREAD_PRIORITY_SCHEDULING"))
.subcommand(clap::App::new("_SC_THREAD_ATTR_STACKSIZE"))
.subcommand(clap::App::new("_SC_THREAD_ATTR_STACKADDR"))
.subcommand(clap::App::new("_SC_THREAD_THREADS_MAX"))
.subcommand(clap::App::new("_SC_THREAD_STACK_MIN"))
.subcommand(clap::App::new("_SC_THREAD_KEYS_MAX"))
.subcommand(clap::App::new("_SC_THREAD_DESTRUCTOR_ITERATIONS"))
.subcommand(clap::App::new("_SC_TTY_NAME_MAX"))
.subcommand(clap::App::new("_SC_LOGIN_NAME_MAX"))
.subcommand(clap::App::new("_SC_GETPW_R_SIZE_MAX"))
.subcommand(clap::App::new("_SC_GETGR_R_SIZE_MAX"))
.subcommand(clap::App::new("_SC_THREAD_SAFE_FUNCTIONS"))
.subcommand(clap::App::new("_SC_THREADS"))
.subcommand(clap::App::new("_SC_IOV_MAX"))
.subcommand(clap::App::new("_SC_UIO_MAXIOV"))
.subcommand(clap::App::new("_SC_2_LOCALEDEF"))
.subcommand(clap::App::new("_SC_2_SW_DEV"))
.subcommand(clap::App::new("_SC_2_FORT_RUN"))
.subcommand(clap::App::new("_SC_2_FORT_DEV"))
.subcommand(clap::App::new("_SC_2_C_DEV"))
.subcommand(clap::App::new("_SC_2_C_BIND"))
.subcommand(clap::App::new("_SC_2_VERSION"))
.subcommand(clap::App::new("_SC_RE_DUP_MAX"))
.subcommand(clap::App::new("_SC_LINE_MAX"))
.subcommand(clap::App::new("_SC_EXPR_NEST_MAX"))
.subcommand(clap::App::new("_SC_COLL_WEIGHTS_MAX"))
.subcommand(clap::App::new("_SC_BC_STRING_MAX"))
.subcommand(clap::App::new("_SC_BC_SCALE_MAX"))
.subcommand(clap::App::new("_SC_BC_DIM_MAX"))
.subcommand(clap::App::new("_SC_BC_BASE_MAX"))
.subcommand(clap::App::new("_SC_TIMER_MAX"))
.subcommand(clap::App::new("_SC_SIGQUEUE_MAX"))
.subcommand(clap::App::new("_SC_SEM_VALUE_MAX"))
.subcommand(clap::App::new("_SC_SEM_NSEMS_MAX"))
.subcommand(clap::App::new("_SC_RTSIG_MAX"))
.subcommand(clap::App::new("_SC_PAGE_SIZE"))
.subcommand(clap::App::new("_SC_PAGESIZE"))
.subcommand(clap::App::new("_SC_VERSION"))
.subcommand(clap::App::new("_SC_MQ_PRIO_MAX"))
.subcommand(clap::App::new("_SC_MQ_OPEN_MAX"))
.subcommand(clap::App::new("_SC_DELAYTIMER_MAX"))
.subcommand(clap::App::new("_SC_AIO_PRIO_DELTA_MAX"))
.subcommand(clap::App::new("_SC_AIO_MAX"))
.subcommand(clap::App::new("_SC_AIO_LISTIO_MAX"))
.subcommand(clap::App::new("_SC_SHARED_MEMORY_OBJECTS"))
.subcommand(clap::App::new("_SC_SEMAPHORES"))
.subcommand(clap::App::new("_SC_MESSAGE_PASSING"))
.subcommand(clap::App::new("_SC_MEMORY_PROTECTION"))
.subcommand(clap::App::new("_SC_MEMLOCK_RANGE"))
.subcommand(clap::App::new("_SC_MEMLOCK"))
.subcommand(clap::App::new("_SC_MAPPED_FILES"))
.subcommand(clap::App::new("_SC_FSYNC"))
.subcommand(clap::App::new("_SC_SYNCHRONIZED_IO"))
.subcommand(clap::App::new("_SC_PRIORITIZED_IO"))
.subcommand(clap::App::new("_SC_ASYNCHRONOUS_IO"))
.subcommand(clap::App::new("_SC_TIMERS"))
.subcommand(clap::App::new("_SC_PRIORITY_SCHEDULING"))
.subcommand(clap::App::new("_SC_REALTIME_SIGNALS"))
.subcommand(clap::App::new("_SC_SAVED_IDS"))
.subcommand(clap::App::new("_SC_JOB_CONTROL"))
.subcommand(clap::App::new("_SC_TZNAME_MAX"))
.subcommand(clap::App::new("_SC_STREAM_MAX"))
.subcommand(clap::App::new("_SC_OPEN_MAX"))
.subcommand(clap::App::new("_SC_NGROUPS_MAX"))
.subcommand(clap::App::new("_SC_CLK_TCK"))
.subcommand(clap::App::new("_SC_CHILD_MAX"))
.subcommand(clap::App::new("_SC_ARG_MAX"))
.subcommand(clap::App::new("MS_NOUSER"))
.subcommand(clap::App::new("_PC_2_SYMLINKS"))
.subcommand(clap::App::new("_PC_SYMLINK_MAX"))
.subcommand(clap::App::new("_PC_ALLOC_SIZE_MIN"))
.subcommand(clap::App::new("_PC_REC_XFER_ALIGN"))
.subcommand(clap::App::new("_PC_REC_MIN_XFER_SIZE"))
.subcommand(clap::App::new("_PC_REC_MAX_XFER_SIZE"))
.subcommand(clap::App::new("_PC_REC_INCR_XFER_SIZE"))
.subcommand(clap::App::new("_PC_FILESIZEBITS"))
.subcommand(clap::App::new("_PC_SOCK_MAXBUF"))
.subcommand(clap::App::new("_PC_PRIO_IO"))
.subcommand(clap::App::new("_PC_ASYNC_IO"))
.subcommand(clap::App::new("_PC_SYNC_IO"))
.subcommand(clap::App::new("_PC_VDISABLE"))
.subcommand(clap::App::new("_PC_NO_TRUNC"))
.subcommand(clap::App::new("_PC_CHOWN_RESTRICTED"))
.subcommand(clap::App::new("_PC_PIPE_BUF"))
.subcommand(clap::App::new("_PC_PATH_MAX"))
.subcommand(clap::App::new("_PC_NAME_MAX"))
.subcommand(clap::App::new("_PC_MAX_INPUT"))
.subcommand(clap::App::new("_PC_MAX_CANON"))
.subcommand(clap::App::new("_PC_LINK_MAX"))
.subcommand(clap::App::new("L_tmpnam"))
.subcommand(clap::App::new("FILENAME_MAX"))
.subcommand(clap::App::new("NOSTR"))
.subcommand(clap::App::new("YESSTR"))
.subcommand(clap::App::new("NOEXPR"))
.subcommand(clap::App::new("YESEXPR"))
.subcommand(clap::App::new("THOUSEP"))
.subcommand(clap::App::new("RADIXCHAR"))
.subcommand(clap::App::new("RUSAGE_CHILDREN"))
.subcommand(clap::App::new("RUSAGE_THREAD"))
.subcommand(clap::App::new("CRNCYSTR"))
.subcommand(clap::App::new("CODESET"))
.subcommand(clap::App::new("ERA_T_FMT"))
.subcommand(clap::App::new("ERA_D_T_FMT"))
.subcommand(clap::App::new("ALT_DIGITS"))
.subcommand(clap::App::new("ERA_D_FMT"))
.subcommand(clap::App::new("ERA"))
.subcommand(clap::App::new("T_FMT_AMPM"))
.subcommand(clap::App::new("T_FMT"))
.subcommand(clap::App::new("D_FMT"))
.subcommand(clap::App::new("D_T_FMT"))
.subcommand(clap::App::new("PM_STR"))
.subcommand(clap::App::new("AM_STR"))
.subcommand(clap::App::new("MON_12"))
.subcommand(clap::App::new("MON_11"))
.subcommand(clap::App::new("MON_10"))
.subcommand(clap::App::new("MON_9"))
.subcommand(clap::App::new("MON_8"))
.subcommand(clap::App::new("MON_7"))
.subcommand(clap::App::new("MON_6"))
.subcommand(clap::App::new("MON_5"))
.subcommand(clap::App::new("MON_4"))
.subcommand(clap::App::new("MON_3"))
.subcommand(clap::App::new("MON_2"))
.subcommand(clap::App::new("MON_1"))
.subcommand(clap::App::new("ABMON_12"))
.subcommand(clap::App::new("ABMON_11"))
.subcommand(clap::App::new("ABMON_10"))
.subcommand(clap::App::new("ABMON_9"))
.subcommand(clap::App::new("ABMON_8"))
.subcommand(clap::App::new("ABMON_7"))
.subcommand(clap::App::new("ABMON_6"))
.subcommand(clap::App::new("ABMON_5"))
.subcommand(clap::App::new("ABMON_4"))
.subcommand(clap::App::new("ABMON_3"))
.subcommand(clap::App::new("ABMON_2"))
.subcommand(clap::App::new("ABMON_1"))
.subcommand(clap::App::new("DAY_7"))
.subcommand(clap::App::new("DAY_6"))
.subcommand(clap::App::new("DAY_5"))
.subcommand(clap::App::new("DAY_4"))
.subcommand(clap::App::new("DAY_3"))
.subcommand(clap::App::new("DAY_2"))
.subcommand(clap::App::new("DAY_1"))
.subcommand(clap::App::new("ABDAY_7"))
.subcommand(clap::App::new("ABDAY_6"))
.subcommand(clap::App::new("ABDAY_5"))
.subcommand(clap::App::new("ABDAY_4"))
.subcommand(clap::App::new("ABDAY_3"))
.subcommand(clap::App::new("ABDAY_2"))
.subcommand(clap::App::new("ABDAY_1"))
.subcommand(clap::App::new("ARPHRD_NONE"))
.subcommand(clap::App::new("ARPHRD_VOID"))
.subcommand(clap::App::new("ARPHRD_IEEE802154"))
.subcommand(clap::App::new("ARPHRD_IEEE80211_RADIOTAP"))
.subcommand(clap::App::new("ARPHRD_IEEE80211_PRISM"))
.subcommand(clap::App::new("ARPHRD_IEEE80211"))
.subcommand(clap::App::new("ARPHRD_IEEE802_TR"))
.subcommand(clap::App::new("ARPHRD_FCFABRIC"))
.subcommand(clap::App::new("ARPHRD_FCPL"))
.subcommand(clap::App::new("ARPHRD_FCAL"))
.subcommand(clap::App::new("ARPHRD_FCPP"))
.subcommand(clap::App::new("ARPHRD_IRDA"))
.subcommand(clap::App::new("ARPHRD_ECONET"))
.subcommand(clap::App::new("ARPHRD_ASH"))
.subcommand(clap::App::new("ARPHRD_HIPPI"))
.subcommand(clap::App::new("ARPHRD_PIMREG"))
.subcommand(clap::App::new("ARPHRD_IPGRE"))
.subcommand(clap::App::new("ARPHRD_IPDDP"))
.subcommand(clap::App::new("ARPHRD_SIT"))
.subcommand(clap::App::new("ARPHRD_BIF"))
.subcommand(clap::App::new("ARPHRD_FDDI"))
.subcommand(clap::App::new("ARPHRD_LOCALTLK"))
.subcommand(clap::App::new("ARPHRD_LOOPBACK"))
.subcommand(clap::App::new("ARPHRD_SKIP"))
.subcommand(clap::App::new("ARPHRD_FRAD"))
.subcommand(clap::App::new("ARPHRD_TUNNEL6"))
.subcommand(clap::App::new("ARPHRD_TUNNEL"))
.subcommand(clap::App::new("ARPHRD_RAWHDLC"))
.subcommand(clap::App::new("ARPHRD_DDCMP"))
.subcommand(clap::App::new("ARPHRD_LAPB"))
.subcommand(clap::App::new("ARPHRD_HDLC"))
.subcommand(clap::App::new("ARPHRD_CISCO"))
.subcommand(clap::App::new("ARPHRD_PPP"))
.subcommand(clap::App::new("ARPHRD_HWX25"))
.subcommand(clap::App::new("ARPHRD_X25"))
.subcommand(clap::App::new("ARPHRD_ROSE"))
.subcommand(clap::App::new("ARPHRD_ADAPT"))
.subcommand(clap::App::new("ARPHRD_RSRVD"))
.subcommand(clap::App::new("ARPHRD_CSLIP6"))
.subcommand(clap::App::new("ARPHRD_SLIP6"))
.subcommand(clap::App::new("ARPHRD_CSLIP"))
.subcommand(clap::App::new("ARPHRD_SLIP"))
.subcommand(clap::App::new("ARPHRD_INFINIBAND"))
.subcommand(clap::App::new("ARPHRD_EUI64"))
.subcommand(clap::App::new("ARPHRD_IEEE1394"))
.subcommand(clap::App::new("ARPHRD_METRICOM"))
.subcommand(clap::App::new("ARPHRD_ATM"))
.subcommand(clap::App::new("ARPHRD_DLCI"))
.subcommand(clap::App::new("ARPHRD_APPLETLK"))
.subcommand(clap::App::new("ARPHRD_ARCNET"))
.subcommand(clap::App::new("ARPHRD_IEEE802"))
.subcommand(clap::App::new("ARPHRD_CHAOS"))
.subcommand(clap::App::new("ARPHRD_PRONET"))
.subcommand(clap::App::new("ARPHRD_AX25"))
.subcommand(clap::App::new("ARPHRD_EETHER"))
.subcommand(clap::App::new("ARPHRD_ETHER"))
.subcommand(clap::App::new("ARPHRD_NETROM"))
.subcommand(clap::App::new("ATF_DONTPUB"))
.subcommand(clap::App::new("ATF_NETMASK"))
.subcommand(clap::App::new("ARPOP_NAK"))
.subcommand(clap::App::new("ARPOP_InREPLY"))
.subcommand(clap::App::new("ARPOP_InREQUEST"))
.subcommand(clap::App::new("ARPOP_RREPLY"))
.subcommand(clap::App::new("ARPOP_RREQUEST"))
.subcommand(clap::App::new("IPOPT_TS_PRESPEC"))
.subcommand(clap::App::new("IPOPT_TS_TSANDADDR"))
.subcommand(clap::App::new("IPOPT_TS_TSONLY"))
.subcommand(clap::App::new("IPOPT_TS"))
.subcommand(clap::App::new("IPOPT_EOL"))
.subcommand(clap::App::new("IPOPT_NOP"))
.subcommand(clap::App::new("MAX_IPOPTLEN"))
.subcommand(clap::App::new("IPOPT_MINOFF"))
.subcommand(clap::App::new("IPOPT_OFFSET"))
.subcommand(clap::App::new("IPOPT_OLEN"))
.subcommand(clap::App::new("IPOPT_OPTVAL"))
.subcommand(clap::App::new("IPDEFTTL"))
.subcommand(clap::App::new("MAXTTL"))
.subcommand(clap::App::new("IPVERSION"))
.subcommand(clap::App::new("IPOPT_RA"))
.subcommand(clap::App::new("IPOPT_SSRR"))
.subcommand(clap::App::new("IPOPT_SID"))
.subcommand(clap::App::new("IPOPT_RR"))
.subcommand(clap::App::new("IPOPT_TIMESTAMP"))
.subcommand(clap::App::new("IPOPT_LSRR"))
.subcommand(clap::App::new("IPOPT_SEC"))
.subcommand(clap::App::new("IPOPT_NOOP"))
.subcommand(clap::App::new("IPOPT_END"))
.subcommand(clap::App::new("IPOPT_RESERVED2"))
.subcommand(clap::App::new("IPOPT_MEASUREMENT"))
.subcommand(clap::App::new("IPOPT_RESERVED1"))
.subcommand(clap::App::new("IPOPT_CONTROL"))
.subcommand(clap::App::new("IPOPT_NUMBER_MASK"))
.subcommand(clap::App::new("IPOPT_CLASS_MASK"))
.subcommand(clap::App::new("IPOPT_COPY"))
.subcommand(clap::App::new("IPTOS_ECN_CE"))
.subcommand(clap::App::new("IPTOS_ECN_ECT0"))
.subcommand(clap::App::new("IPTOS_ECN_ECT1"))
.subcommand(clap::App::new("IPTOS_ECN_MASK"))
.subcommand(clap::App::new("IPTOS_PREC_ROUTINE"))
.subcommand(clap::App::new("IPTOS_PREC_PRIORITY"))
.subcommand(clap::App::new("IPTOS_PREC_IMMEDIATE"))
.subcommand(clap::App::new("IPTOS_PREC_FLASH"))
.subcommand(clap::App::new("IPTOS_PREC_FLASHOVERRIDE"))
.subcommand(clap::App::new("IPTOS_PREC_CRITIC_ECP"))
.subcommand(clap::App::new("IPTOS_PREC_INTERNETCONTROL"))
.subcommand(clap::App::new("IPTOS_PREC_NETCONTROL"))
.subcommand(clap::App::new("IPTOS_MINCOST"))
.subcommand(clap::App::new("IPTOS_RELIABILITY"))
.subcommand(clap::App::new("IPTOS_THROUGHPUT"))
.subcommand(clap::App::new("IPTOS_LOWDELAY"))
.subcommand(clap::App::new("POLLRDBAND"))
.subcommand(clap::App::new("POLLRDNORM"))
.subcommand(clap::App::new("POLLNVAL"))
.subcommand(clap::App::new("POLLHUP"))
.subcommand(clap::App::new("POLLERR"))
.subcommand(clap::App::new("POLLOUT"))
.subcommand(clap::App::new("POLLPRI"))
.subcommand(clap::App::new("POLLIN"))
.subcommand(clap::App::new("UTIME_NOW"))
.subcommand(clap::App::new("UTIME_OMIT"))
.subcommand(clap::App::new("P_PGID"))
.subcommand(clap::App::new("P_PID"))
.subcommand(clap::App::new("P_ALL"))
.subcommand(clap::App::new("SIGEV_THREAD"))
.subcommand(clap::App::new("SIGEV_NONE"))
.subcommand(clap::App::new("SIGEV_SIGNAL"))
.subcommand(clap::App::new("SI_LOAD_SHIFT"))
.subcommand(clap::App::new("PIPE_BUF"))
.subcommand(clap::App::new("LOG_PERROR"))
.subcommand(clap::App::new("LOG_FTP"))
.subcommand(clap::App::new("LOG_AUTHPRIV"))
.subcommand(clap::App::new("LOG_CRON"))
.subcommand(clap::App::new("AT_EMPTY_PATH"))
.subcommand(clap::App::new("AT_NO_AUTOMOUNT"))
.subcommand(clap::App::new("AT_SYMLINK_FOLLOW"))
.subcommand(clap::App::new("AT_REMOVEDIR"))
.subcommand(clap::App::new("AT_SYMLINK_NOFOLLOW"))
.subcommand(clap::App::new("AT_FDCWD"))
.subcommand(clap::App::new("POSIX_FADV_WILLNEED"))
.subcommand(clap::App::new("POSIX_FADV_SEQUENTIAL"))
.subcommand(clap::App::new("POSIX_FADV_RANDOM"))
.subcommand(clap::App::new("POSIX_FADV_NORMAL"))
.subcommand(clap::App::new("RTLD_LAZY"))
.subcommand(clap::App::new("RTLD_LOCAL"))
.subcommand(clap::App::new("SPLICE_F_GIFT"))
.subcommand(clap::App::new("SPLICE_F_MORE"))
.subcommand(clap::App::new("SPLICE_F_NONBLOCK"))
.subcommand(clap::App::new("SPLICE_F_MOVE"))
.subcommand(clap::App::new("__WCLONE"))
.subcommand(clap::App::new("__WALL"))
.subcommand(clap::App::new("__WNOTHREAD"))
.subcommand(clap::App::new("PTRACE_EVENT_SECCOMP"))
.subcommand(clap::App::new("PTRACE_EVENT_EXIT"))
.subcommand(clap::App::new("PTRACE_EVENT_VFORK_DONE"))
.subcommand(clap::App::new("PTRACE_EVENT_EXEC"))
.subcommand(clap::App::new("PTRACE_EVENT_CLONE"))
.subcommand(clap::App::new("PTRACE_EVENT_VFORK"))
.subcommand(clap::App::new("PTRACE_EVENT_FORK"))
.subcommand(clap::App::new("PTRACE_O_MASK"))
.subcommand(clap::App::new("PTRACE_O_SUSPEND_SECCOMP"))
.subcommand(clap::App::new("PTRACE_O_EXITKILL"))
.subcommand(clap::App::new("PTRACE_O_TRACESECCOMP"))
.subcommand(clap::App::new("PTRACE_O_TRACEEXIT"))
.subcommand(clap::App::new("PTRACE_O_TRACEVFORKDONE"))
.subcommand(clap::App::new("PTRACE_O_TRACEEXEC"))
.subcommand(clap::App::new("PTRACE_O_TRACECLONE"))
.subcommand(clap::App::new("PTRACE_O_TRACEVFORK"))
.subcommand(clap::App::new("PTRACE_O_TRACEFORK"))
.subcommand(clap::App::new("PTRACE_O_TRACESYSGOOD"))
.subcommand(clap::App::new("WNOWAIT"))
.subcommand(clap::App::new("WCONTINUED"))
.subcommand(clap::App::new("WEXITED"))
.subcommand(clap::App::new("WSTOPPED"))
.subcommand(clap::App::new("WUNTRACED"))
.subcommand(clap::App::new("WNOHANG"))
.subcommand(clap::App::new("CLONE_NEWCGROUP"))
.subcommand(clap::App::new("CLONE_IO"))
.subcommand(clap::App::new("CLONE_NEWNET"))
.subcommand(clap::App::new("CLONE_NEWPID"))
.subcommand(clap::App::new("CLONE_NEWUSER"))
.subcommand(clap::App::new("CLONE_NEWIPC"))
.subcommand(clap::App::new("CLONE_NEWUTS"))
.subcommand(clap::App::new("CLONE_CHILD_SETTID"))
.subcommand(clap::App::new("CLONE_UNTRACED"))
.subcommand(clap::App::new("CLONE_DETACHED"))
.subcommand(clap::App::new("CLONE_CHILD_CLEARTID"))
.subcommand(clap::App::new("CLONE_PARENT_SETTID"))
.subcommand(clap::App::new("CLONE_SETTLS"))
.subcommand(clap::App::new("CLONE_SYSVSEM"))
.subcommand(clap::App::new("CLONE_NEWNS"))
.subcommand(clap::App::new("CLONE_THREAD"))
.subcommand(clap::App::new("CLONE_PARENT"))
.subcommand(clap::App::new("CLONE_VFORK"))
.subcommand(clap::App::new("CLONE_PTRACE"))
.subcommand(clap::App::new("CLONE_SIGHAND"))
.subcommand(clap::App::new("CLONE_FILES"))
.subcommand(clap::App::new("CLONE_FS"))
.subcommand(clap::App::new("CLONE_VM"))
.subcommand(clap::App::new("OFDEL"))
.subcommand(clap::App::new("OFILL"))
.subcommand(clap::App::new("ONLRET"))
.subcommand(clap::App::new("ONOCR"))
.subcommand(clap::App::new("OCRNL"))
.subcommand(clap::App::new("ECHO"))
.subcommand(clap::App::new("CRTSCTS"))
.subcommand(clap::App::new("CS5"))
.subcommand(clap::App::new("OPOST"))
.subcommand(clap::App::new("IMAXBEL"))
.subcommand(clap::App::new("IXANY"))
.subcommand(clap::App::new("ICRNL"))
.subcommand(clap::App::new("IGNCR"))
.subcommand(clap::App::new("INLCR"))
.subcommand(clap::App::new("ISTRIP"))
.subcommand(clap::App::new("INPCK"))
.subcommand(clap::App::new("PARMRK"))
.subcommand(clap::App::new("IGNPAR"))
.subcommand(clap::App::new("BRKINT"))
.subcommand(clap::App::new("IGNBRK"))
.subcommand(clap::App::new("VLNEXT"))
.subcommand(clap::App::new("VQUIT"))
.subcommand(clap::App::new("VINTR"))
.subcommand(clap::App::new("VKILL"))
.subcommand(clap::App::new("VERASE"))
.subcommand(clap::App::new("VT0"))
.subcommand(clap::App::new("BS0"))
.subcommand(clap::App::new("FF0"))
.subcommand(clap::App::new("CR0"))
.subcommand(clap::App::new("TAB0"))
.subcommand(clap::App::new("NL1"))
.subcommand(clap::App::new("NL0"))
.subcommand(clap::App::new("TCIOFLUSH"))
.subcommand(clap::App::new("TCOFLUSH"))
.subcommand(clap::App::new("TCIFLUSH"))
.subcommand(clap::App::new("TCOON"))
.subcommand(clap::App::new("TCOOFF"))
.subcommand(clap::App::new("TCION"))
.subcommand(clap::App::new("TCIOFF"))
.subcommand(clap::App::new("Q_SETQUOTA"))
.subcommand(clap::App::new("Q_GETQUOTA"))
.subcommand(clap::App::new("Q_QUOTAOFF"))
.subcommand(clap::App::new("Q_QUOTAON"))
.subcommand(clap::App::new("Q_SYNC"))
.subcommand(clap::App::new("MNT_FORCE"))
.subcommand(clap::App::new("QIF_ALL"))
.subcommand(clap::App::new("QIF_TIMES"))
.subcommand(clap::App::new("QIF_USAGE"))
.subcommand(clap::App::new("QIF_LIMITS"))
.subcommand(clap::App::new("QIF_ITIME"))
.subcommand(clap::App::new("QIF_BTIME"))
.subcommand(clap::App::new("QIF_INODES"))
.subcommand(clap::App::new("QIF_ILIMITS"))
.subcommand(clap::App::new("QIF_SPACE"))
.subcommand(clap::App::new("QIF_BLIMITS"))
.subcommand(clap::App::new("Q_SETINFO"))
.subcommand(clap::App::new("Q_GETINFO"))
.subcommand(clap::App::new("Q_GETFMT"))
.subcommand(clap::App::new("MNT_EXPIRE"))
.subcommand(clap::App::new("MNT_DETACH"))
.subcommand(clap::App::new("EPOLL_CTL_DEL"))
.subcommand(clap::App::new("EPOLL_CTL_MOD"))
.subcommand(clap::App::new("EPOLL_CTL_ADD"))
.subcommand(clap::App::new("EPOLLET"))
.subcommand(clap::App::new("EPOLLHUP"))
.subcommand(clap::App::new("EPOLLERR"))
.subcommand(clap::App::new("EPOLLMSG"))
.subcommand(clap::App::new("EPOLLWRBAND"))
.subcommand(clap::App::new("EPOLLWRNORM"))
.subcommand(clap::App::new("EPOLLRDBAND"))
.subcommand(clap::App::new("EPOLLRDNORM"))
.subcommand(clap::App::new("EPOLLOUT"))
.subcommand(clap::App::new("EPOLLPRI"))
.subcommand(clap::App::new("EPOLLIN"))
.subcommand(clap::App::new("FD_SETSIZE"))
.subcommand(clap::App::new("PATH_MAX"))
.subcommand(clap::App::new("SS_DISABLE"))
.subcommand(clap::App::new("SS_ONSTACK"))
.subcommand(clap::App::new("LOCK_UN"))
.subcommand(clap::App::new("LOCK_NB"))
.subcommand(clap::App::new("LOCK_EX"))
.subcommand(clap::App::new("LOCK_SH"))
.subcommand(clap::App::new("SHUT_RDWR"))
.subcommand(clap::App::new("SHUT_WR"))
.subcommand(clap::App::new("SHUT_RD"))
.subcommand(clap::App::new("SO_DEBUG"))
.subcommand(clap::App::new("TCP_CONGESTION"))
.subcommand(clap::App::new("TCP_QUICKACK"))
.subcommand(clap::App::new("TCP_INFO"))
.subcommand(clap::App::new("TCP_WINDOW_CLAMP"))
.subcommand(clap::App::new("TCP_DEFER_ACCEPT"))
.subcommand(clap::App::new("TCP_LINGER2"))
.subcommand(clap::App::new("TCP_SYNCNT"))
.subcommand(clap::App::new("TCP_KEEPCNT"))
.subcommand(clap::App::new("TCP_KEEPINTVL"))
.subcommand(clap::App::new("TCP_KEEPIDLE"))
.subcommand(clap::App::new("TCP_CORK"))
.subcommand(clap::App::new("TCP_MAXSEG"))
.subcommand(clap::App::new("TCP_NODELAY"))
.subcommand(clap::App::new("IP_PMTUDISC_PROBE"))
.subcommand(clap::App::new("IP_PMTUDISC_DO"))
.subcommand(clap::App::new("IP_PMTUDISC_WANT"))
.subcommand(clap::App::new("IP_PMTUDISC_DONT"))
.subcommand(clap::App::new("IPV6_TCLASS"))
.subcommand(clap::App::new("IPV6_RECVTCLASS"))
.subcommand(clap::App::new("IPV6_PKTINFO"))
.subcommand(clap::App::new("IPV6_RECVPKTINFO"))
.subcommand(clap::App::new("IPV6_LEAVE_ANYCAST"))
.subcommand(clap::App::new("IPV6_JOIN_ANYCAST"))
.subcommand(clap::App::new("IPV6_V6ONLY"))
.subcommand(clap::App::new("IPV6_RECVERR"))
.subcommand(clap::App::new("IPV6_MTU"))
.subcommand(clap::App::new("IPV6_MTU_DISCOVER"))
.subcommand(clap::App::new("IPV6_ROUTER_ALERT"))
.subcommand(clap::App::new("IPV6_DROP_MEMBERSHIP"))
.subcommand(clap::App::new("IPV6_ADD_MEMBERSHIP"))
.subcommand(clap::App::new("IPV6_MULTICAST_LOOP"))
.subcommand(clap::App::new("IPV6_MULTICAST_HOPS"))
.subcommand(clap::App::new("IPV6_MULTICAST_IF"))
.subcommand(clap::App::new("IPV6_UNICAST_HOPS"))
.subcommand(clap::App::new("IPV6_NEXTHOP"))
.subcommand(clap::App::new("IPV6_2292HOPLIMIT"))
.subcommand(clap::App::new("IPV6_CHECKSUM"))
.subcommand(clap::App::new("IPV6_2292PKTOPTIONS"))
.subcommand(clap::App::new("IPV6_2292RTHDR"))
.subcommand(clap::App::new("IPV6_2292DSTOPTS"))
.subcommand(clap::App::new("IPV6_2292HOPOPTS"))
.subcommand(clap::App::new("IPV6_2292PKTINFO"))
.subcommand(clap::App::new("IPV6_ADDRFORM"))
.subcommand(clap::App::new("IP_TRANSPARENT"))
.subcommand(clap::App::new("IP_DROP_SOURCE_MEMBERSHIP"))
.subcommand(clap::App::new("IP_ADD_SOURCE_MEMBERSHIP"))
.subcommand(clap::App::new("IP_DROP_MEMBERSHIP"))
.subcommand(clap::App::new("IP_ADD_MEMBERSHIP"))
.subcommand(clap::App::new("IP_RECVERR"))
.subcommand(clap::App::new("IP_RECVTOS"))
.subcommand(clap::App::new("IP_MTU_DISCOVER"))
.subcommand(clap::App::new("IP_PKTINFO"))
.subcommand(clap::App::new("IP_HDRINCL"))
.subcommand(clap::App::new("IP_TTL"))
.subcommand(clap::App::new("IP_TOS"))
.subcommand(clap::App::new("IP_MULTICAST_LOOP"))
.subcommand(clap::App::new("IP_MULTICAST_TTL"))
.subcommand(clap::App::new("IP_MULTICAST_IF"))
.subcommand(clap::App::new("SOCK_RDM"))
.subcommand(clap::App::new("SOCK_RAW"))
.subcommand(clap::App::new("SCM_TIMESTAMP"))
.subcommand(clap::App::new("MSG_CMSG_CLOEXEC"))
.subcommand(clap::App::new("MSG_FASTOPEN"))
.subcommand(clap::App::new("MSG_WAITFORONE"))
.subcommand(clap::App::new("MSG_MORE"))
.subcommand(clap::App::new("MSG_NOSIGNAL"))
.subcommand(clap::App::new("MSG_ERRQUEUE"))
.subcommand(clap::App::new("MSG_RST"))
.subcommand(clap::App::new("MSG_CONFIRM"))
.subcommand(clap::App::new("MSG_SYN"))
.subcommand(clap::App::new("MSG_FIN"))
.subcommand(clap::App::new("MSG_WAITALL"))
.subcommand(clap::App::new("MSG_EOR"))
.subcommand(clap::App::new("MSG_DONTWAIT"))
.subcommand(clap::App::new("MSG_TRUNC"))
.subcommand(clap::App::new("MSG_CTRUNC"))
.subcommand(clap::App::new("MSG_DONTROUTE"))
.subcommand(clap::App::new("MSG_PEEK"))
.subcommand(clap::App::new("MSG_OOB"))
.subcommand(clap::App::new("SOMAXCONN"))
.subcommand(clap::App::new("PF_ALG"))
.subcommand(clap::App::new("PF_CAIF"))
.subcommand(clap::App::new("PF_IEEE802154"))
.subcommand(clap::App::new("PF_PHONET"))
.subcommand(clap::App::new("PF_ISDN"))
.subcommand(clap::App::new("PF_RXRPC"))
.subcommand(clap::App::new("PF_IUCV"))
.subcommand(clap::App::new("PF_BLUETOOTH"))
.subcommand(clap::App::new("PF_TIPC"))
.subcommand(clap::App::new("PF_CAN"))
.subcommand(clap::App::new("PF_LLC"))
.subcommand(clap::App::new("PF_WANPIPE"))
.subcommand(clap::App::new("PF_PPPOX"))
.subcommand(clap::App::new("PF_IRDA"))
.subcommand(clap::App::new("PF_SNA"))
.subcommand(clap::App::new("PF_RDS"))
.subcommand(clap::App::new("PF_ATMSVC"))
.subcommand(clap::App::new("PF_ECONET"))
.subcommand(clap::App::new("PF_ASH"))
.subcommand(clap::App::new("PF_PACKET"))
.subcommand(clap::App::new("PF_ROUTE"))
.subcommand(clap::App::new("PF_NETLINK"))
.subcommand(clap::App::new("PF_KEY"))
.subcommand(clap::App::new("PF_SECURITY"))
.subcommand(clap::App::new("PF_NETBEUI"))
.subcommand(clap::App::new("PF_DECnet"))
.subcommand(clap::App::new("PF_ROSE"))
.subcommand(clap::App::new("PF_INET6"))
.subcommand(clap::App::new("PF_X25"))
.subcommand(clap::App::new("PF_ATMPVC"))
.subcommand(clap::App::new("PF_BRIDGE"))
.subcommand(clap::App::new("PF_NETROM"))
.subcommand(clap::App::new("PF_APPLETALK"))
.subcommand(clap::App::new("PF_IPX"))
.subcommand(clap::App::new("PF_AX25"))
.subcommand(clap::App::new("PF_INET"))
.subcommand(clap::App::new("PF_LOCAL"))
.subcommand(clap::App::new("PF_UNIX"))
.subcommand(clap::App::new("PF_UNSPEC"))
.subcommand(clap::App::new("AF_ALG"))
.subcommand(clap::App::new("AF_CAIF"))
.subcommand(clap::App::new("AF_IEEE802154"))
.subcommand(clap::App::new("AF_PHONET"))
.subcommand(clap::App::new("AF_ISDN"))
.subcommand(clap::App::new("AF_RXRPC"))
.subcommand(clap::App::new("AF_IUCV"))
.subcommand(clap::App::new("AF_BLUETOOTH"))
.subcommand(clap::App::new("AF_TIPC"))
.subcommand(clap::App::new("AF_CAN"))
.subcommand(clap::App::new("AF_LLC"))
.subcommand(clap::App::new("AF_WANPIPE"))
.subcommand(clap::App::new("AF_PPPOX"))
.subcommand(clap::App::new("AF_IRDA"))
.subcommand(clap::App::new("AF_SNA"))
.subcommand(clap::App::new("AF_RDS"))
.subcommand(clap::App::new("AF_ATMSVC"))
.subcommand(clap::App::new("AF_ECONET"))
.subcommand(clap::App::new("AF_ASH"))
.subcommand(clap::App::new("AF_PACKET"))
.subcommand(clap::App::new("AF_ROUTE"))
.subcommand(clap::App::new("AF_NETLINK"))
.subcommand(clap::App::new("AF_KEY"))
.subcommand(clap::App::new("AF_SECURITY"))
.subcommand(clap::App::new("AF_NETBEUI"))
.subcommand(clap::App::new("AF_DECnet"))
.subcommand(clap::App::new("AF_ROSE"))
.subcommand(clap::App::new("AF_INET6"))
.subcommand(clap::App::new("AF_X25"))
.subcommand(clap::App::new("AF_ATMPVC"))
.subcommand(clap::App::new("AF_BRIDGE"))
.subcommand(clap::App::new("AF_NETROM"))
.subcommand(clap::App::new("AF_APPLETALK"))
.subcommand(clap::App::new("AF_IPX"))
.subcommand(clap::App::new("AF_AX25"))
.subcommand(clap::App::new("AF_INET"))
.subcommand(clap::App::new("AF_LOCAL"))
.subcommand(clap::App::new("AF_UNIX"))
.subcommand(clap::App::new("AF_UNSPEC"))
.subcommand(clap::App::new("SOL_ALG"))
.subcommand(clap::App::new("SOL_BLUETOOTH"))
.subcommand(clap::App::new("SOL_TIPC"))
.subcommand(clap::App::new("SOL_NETLINK"))
.subcommand(clap::App::new("SOL_DCCP"))
.subcommand(clap::App::new("SOL_LLC"))
.subcommand(clap::App::new("SOL_NETBEUI"))
.subcommand(clap::App::new("SOL_IRDA"))
.subcommand(clap::App::new("SOL_AAL"))
.subcommand(clap::App::new("SOL_ATM"))
.subcommand(clap::App::new("SOL_PACKET"))
.subcommand(clap::App::new("SOL_X25"))
.subcommand(clap::App::new("SOL_DECNET"))
.subcommand(clap::App::new("SOL_RAW"))
.subcommand(clap::App::new("SOL_ICMPV6"))
.subcommand(clap::App::new("SOL_IPV6"))
.subcommand(clap::App::new("SOL_UDP"))
.subcommand(clap::App::new("SOL_TCP"))
.subcommand(clap::App::new("SOL_IP"))
.subcommand(clap::App::new("IFF_DYNAMIC"))
.subcommand(clap::App::new("IFF_AUTOMEDIA"))
.subcommand(clap::App::new("IFF_PORTSEL"))
.subcommand(clap::App::new("IFF_MULTICAST"))
.subcommand(clap::App::new("IFF_SLAVE"))
.subcommand(clap::App::new("IFF_MASTER"))
.subcommand(clap::App::new("IFF_ALLMULTI"))
.subcommand(clap::App::new("IFF_PROMISC"))
.subcommand(clap::App::new("IFF_NOARP"))
.subcommand(clap::App::new("IFF_RUNNING"))
.subcommand(clap::App::new("IFF_NOTRAILERS"))
.subcommand(clap::App::new("IFF_POINTOPOINT"))
.subcommand(clap::App::new("IFF_LOOPBACK"))
.subcommand(clap::App::new("IFF_DEBUG"))
.subcommand(clap::App::new("IFF_BROADCAST"))
.subcommand(clap::App::new("IFF_UP"))
.subcommand(clap::App::new("MADV_HWPOISON"))
.subcommand(clap::App::new("MADV_DODUMP"))
.subcommand(clap::App::new("MADV_DONTDUMP"))
.subcommand(clap::App::new("MADV_NOHUGEPAGE"))
.subcommand(clap::App::new("MADV_HUGEPAGE"))
.subcommand(clap::App::new("MADV_UNMERGEABLE"))
.subcommand(clap::App::new("MADV_MERGEABLE"))
.subcommand(clap::App::new("MADV_DOFORK"))
.subcommand(clap::App::new("MADV_DONTFORK"))
.subcommand(clap::App::new("MADV_REMOVE"))
.subcommand(clap::App::new("MADV_FREE"))
.subcommand(clap::App::new("MADV_DONTNEED"))
.subcommand(clap::App::new("MADV_WILLNEED"))
.subcommand(clap::App::new("MADV_SEQUENTIAL"))
.subcommand(clap::App::new("MADV_RANDOM"))
.subcommand(clap::App::new("MADV_NORMAL"))
.subcommand(clap::App::new("MAP_TYPE"))
.subcommand(clap::App::new("PROT_GROWSUP"))
.subcommand(clap::App::new("PROT_GROWSDOWN"))
.subcommand(clap::App::new("SCM_CREDENTIALS"))
.subcommand(clap::App::new("SCM_RIGHTS"))
.subcommand(clap::App::new("MS_MGC_MSK"))
.subcommand(clap::App::new("MS_MGC_VAL"))
.subcommand(clap::App::new("MS_ACTIVE"))
.subcommand(clap::App::new("MS_STRICTATIME"))
.subcommand(clap::App::new("MS_I_VERSION"))
.subcommand(clap::App::new("MS_KERNMOUNT"))
.subcommand(clap::App::new("MS_RELATIME"))
.subcommand(clap::App::new("MS_SHARED"))
.subcommand(clap::App::new("MS_SLAVE"))
.subcommand(clap::App::new("MS_PRIVATE"))
.subcommand(clap::App::new("MS_UNBINDABLE"))
.subcommand(clap::App::new("MS_POSIXACL"))
.subcommand(clap::App::new("MS_SILENT"))
.subcommand(clap::App::new("MS_REC"))
.subcommand(clap::App::new("MS_MOVE"))
.subcommand(clap::App::new("MS_BIND"))
.subcommand(clap::App::new("MS_NODIRATIME"))
.subcommand(clap::App::new("MS_NOATIME"))
.subcommand(clap::App::new("MS_DIRSYNC"))
.subcommand(clap::App::new("MS_MANDLOCK"))
.subcommand(clap::App::new("MS_REMOUNT"))
.subcommand(clap::App::new("MS_SYNCHRONOUS"))
.subcommand(clap::App::new("MS_NOEXEC"))
.subcommand(clap::App::new("MS_NODEV"))
.subcommand(clap::App::new("MS_NOSUID"))
.subcommand(clap::App::new("MS_RDONLY"))
.subcommand(clap::App::new("MS_SYNC"))
.subcommand(clap::App::new("MS_INVALIDATE"))
.subcommand(clap::App::new("MS_ASYNC"))
.subcommand(clap::App::new("MAP_FIXED"))
.subcommand(clap::App::new("MAP_PRIVATE"))
.subcommand(clap::App::new("MAP_SHARED"))
.subcommand(clap::App::new("MAP_FILE"))
.subcommand(clap::App::new("LC_MESSAGES_MASK"))
.subcommand(clap::App::new("LC_MONETARY_MASK"))
.subcommand(clap::App::new("LC_COLLATE_MASK"))
.subcommand(clap::App::new("LC_TIME_MASK"))
.subcommand(clap::App::new("LC_NUMERIC_MASK"))
.subcommand(clap::App::new("LC_CTYPE_MASK"))
.subcommand(clap::App::new("LC_ALL"))
.subcommand(clap::App::new("LC_MESSAGES"))
.subcommand(clap::App::new("LC_MONETARY"))
.subcommand(clap::App::new("LC_COLLATE"))
.subcommand(clap::App::new("LC_TIME"))
.subcommand(clap::App::new("LC_NUMERIC"))
.subcommand(clap::App::new("LC_CTYPE"))
.subcommand(clap::App::new("PROT_EXEC"))
.subcommand(clap::App::new("PROT_WRITE"))
.subcommand(clap::App::new("PROT_READ"))
.subcommand(clap::App::new("PROT_NONE"))
.subcommand(clap::App::new("SIGTERM"))
.subcommand(clap::App::new("SIGALRM"))
.subcommand(clap::App::new("SIGPIPE"))
.subcommand(clap::App::new("SIGSEGV"))
.subcommand(clap::App::new("SIGKILL"))
.subcommand(clap::App::new("SIGFPE"))
.subcommand(clap::App::new("SIGABRT"))
.subcommand(clap::App::new("SIGILL"))
.subcommand(clap::App::new("SIGQUIT"))
.subcommand(clap::App::new("SIGINT"))
.subcommand(clap::App::new("SIGHUP"))
.subcommand(clap::App::new("STDERR_FILENO"))
.subcommand(clap::App::new("STDOUT_FILENO"))
.subcommand(clap::App::new("STDIN_FILENO"))
.subcommand(clap::App::new("X_OK"))
.subcommand(clap::App::new("W_OK"))
.subcommand(clap::App::new("R_OK"))
.subcommand(clap::App::new("F_OK"))
.subcommand(clap::App::new("S_IROTH"))
.subcommand(clap::App::new("S_IWOTH"))
.subcommand(clap::App::new("S_IXOTH"))
.subcommand(clap::App::new("S_IRWXO"))
.subcommand(clap::App::new("S_IRGRP"))
.subcommand(clap::App::new("S_IWGRP"))
.subcommand(clap::App::new("S_IXGRP"))
.subcommand(clap::App::new("S_IRWXG"))
.subcommand(clap::App::new("S_IRUSR"))
.subcommand(clap::App::new("S_IWUSR"))
.subcommand(clap::App::new("S_IXUSR"))
.subcommand(clap::App::new("S_IRWXU"))
.subcommand(clap::App::new("S_IFMT"))
.subcommand(clap::App::new("S_IFSOCK"))
.subcommand(clap::App::new("S_IFLNK"))
.subcommand(clap::App::new("S_IFREG"))
.subcommand(clap::App::new("S_IFDIR"))
.subcommand(clap::App::new("S_IFBLK"))
.subcommand(clap::App::new("S_IFCHR"))
.subcommand(clap::App::new("S_IFIFO"))
.subcommand(clap::App::new("SOCK_CLOEXEC"))
.subcommand(clap::App::new("O_RDWR"))
.subcommand(clap::App::new("O_WRONLY"))
.subcommand(clap::App::new("O_RDONLY"))
.subcommand(clap::App::new("RUSAGE_SELF"))
.subcommand(clap::App::new("TIMER_ABSTIME"))
.subcommand(clap::App::new("CLOCK_TAI"))
.subcommand(clap::App::new("CLOCK_BOOTTIME_ALARM"))
.subcommand(clap::App::new("CLOCK_REALTIME_ALARM"))
.subcommand(clap::App::new("CLOCK_BOOTTIME"))
.subcommand(clap::App::new("CLOCK_MONOTONIC_COARSE"))
.subcommand(clap::App::new("CLOCK_REALTIME_COARSE"))
.subcommand(clap::App::new("CLOCK_MONOTONIC_RAW"))
.subcommand(clap::App::new("CLOCK_THREAD_CPUTIME_ID"))
.subcommand(clap::App::new("CLOCK_PROCESS_CPUTIME_ID"))
.subcommand(clap::App::new("CLOCK_MONOTONIC"))
.subcommand(clap::App::new("CLOCK_REALTIME"))
.subcommand(clap::App::new("PTHREAD_CREATE_DETACHED"))
.subcommand(clap::App::new("PTHREAD_CREATE_JOINABLE"))
.subcommand(clap::App::new("SIGTRAP"))
.subcommand(clap::App::new("F_SEAL_WRITE"))
.subcommand(clap::App::new("F_SEAL_GROW"))
.subcommand(clap::App::new("F_SEAL_SHRINK"))
.subcommand(clap::App::new("F_SEAL_SEAL"))
.subcommand(clap::App::new("F_GET_SEALS"))
.subcommand(clap::App::new("F_ADD_SEALS"))
.subcommand(clap::App::new("F_GETPIPE_SZ"))
.subcommand(clap::App::new("F_SETPIPE_SZ"))
.subcommand(clap::App::new("F_DUPFD_CLOEXEC"))
.subcommand(clap::App::new("F_CANCELLK"))
.subcommand(clap::App::new("F_NOTIFY"))
.subcommand(clap::App::new("F_GETLEASE"))
.subcommand(clap::App::new("F_SETLEASE"))
.subcommand(clap::App::new("F_SETFL"))
.subcommand(clap::App::new("F_GETFL"))
.subcommand(clap::App::new("F_SETFD"))
.subcommand(clap::App::new("F_GETFD"))
.subcommand(clap::App::new("F_DUPFD"))
.subcommand(clap::App::new("_IOLBF"))
.subcommand(clap::App::new("_IONBF"))
.subcommand(clap::App::new("_IOFBF"))
.subcommand(clap::App::new("SEEK_END"))
.subcommand(clap::App::new("SEEK_CUR"))
.subcommand(clap::App::new("SEEK_SET"))
.subcommand(clap::App::new("EOF"))
.subcommand(clap::App::new("RAND_MAX"))
.subcommand(clap::App::new("EXIT_SUCCESS"))
.subcommand(clap::App::new("EXIT_FAILURE"))
.subcommand(clap::App::new("ATF_USETRAILERS"))
.subcommand(clap::App::new("ATF_PUBL"))
.subcommand(clap::App::new("ATF_PERM"))
.subcommand(clap::App::new("ATF_COM"))
.subcommand(clap::App::new("ARPOP_REPLY"))
.subcommand(clap::App::new("ARPOP_REQUEST"))
.subcommand(clap::App::new("INADDR_NONE"))
.subcommand(clap::App::new("INADDR_BROADCAST"))
.subcommand(clap::App::new("INADDR_ANY"))
.subcommand(clap::App::new("INADDR_LOOPBACK"))
.subcommand(clap::App::new("IPPROTO_IPV6"))
.subcommand(clap::App::new("IPPROTO_IP"))
.subcommand(clap::App::new("IPPROTO_UDP"))
.subcommand(clap::App::new("IPPROTO_TCP"))
.subcommand(clap::App::new("IPPROTO_ICMPV6"))
.subcommand(clap::App::new("IPPROTO_ICMP"))
.subcommand(clap::App::new("PRIO_MAX"))
.subcommand(clap::App::new("PRIO_MIN"))
.subcommand(clap::App::new("PRIO_USER"))
.subcommand(clap::App::new("PRIO_PGRP"))
.subcommand(clap::App::new("PRIO_PROCESS"))
.subcommand(clap::App::new("LOG_FACMASK"))
.subcommand(clap::App::new("LOG_PRIMASK"))
.subcommand(clap::App::new("LOG_NOWAIT"))
.subcommand(clap::App::new("LOG_NDELAY"))
.subcommand(clap::App::new("LOG_ODELAY"))
.subcommand(clap::App::new("LOG_CONS"))
.subcommand(clap::App::new("LOG_PID"))
.subcommand(clap::App::new("LOG_LOCAL7"))
.subcommand(clap::App::new("LOG_LOCAL6"))
.subcommand(clap::App::new("LOG_LOCAL5"))
.subcommand(clap::App::new("LOG_LOCAL4"))
.subcommand(clap::App::new("LOG_LOCAL3"))
.subcommand(clap::App::new("LOG_LOCAL2"))
.subcommand(clap::App::new("LOG_LOCAL1"))
.subcommand(clap::App::new("LOG_LOCAL0"))
.subcommand(clap::App::new("LOG_UUCP"))
.subcommand(clap::App::new("LOG_NEWS"))
.subcommand(clap::App::new("LOG_LPR"))
.subcommand(clap::App::new("LOG_SYSLOG"))
.subcommand(clap::App::new("LOG_AUTH"))
.subcommand(clap::App::new("LOG_DAEMON"))
.subcommand(clap::App::new("LOG_MAIL"))
.subcommand(clap::App::new("LOG_USER"))
.subcommand(clap::App::new("LOG_KERN"))
.subcommand(clap::App::new("LOG_DEBUG"))
.subcommand(clap::App::new("LOG_INFO"))
.subcommand(clap::App::new("LOG_NOTICE"))
.subcommand(clap::App::new("LOG_WARNING"))
.subcommand(clap::App::new("LOG_ERR"))
.subcommand(clap::App::new("LOG_CRIT"))
.subcommand(clap::App::new("LOG_ALERT"))
.subcommand(clap::App::new("LOG_EMERG"))
.subcommand(clap::App::new("IFNAMSIZ"))
.subcommand(clap::App::new("IF_NAMESIZE"))
.subcommand(clap::App::new("S_ISVTX"))
.subcommand(clap::App::new("S_ISGID"))
.subcommand(clap::App::new("S_ISUID"))
.subcommand(clap::App::new("SIGIOT"))
.subcommand(clap::App::new("GRPQUOTA"))
.subcommand(clap::App::new("USRQUOTA"))
.subcommand(clap::App::new("FD_CLOEXEC"))
.subcommand(clap::App::new("DT_SOCK"))
.subcommand(clap::App::new("DT_LNK"))
.subcommand(clap::App::new("DT_REG"))
.subcommand(clap::App::new("DT_BLK"))
.subcommand(clap::App::new("DT_DIR"))
.subcommand(clap::App::new("DT_CHR"))
.subcommand(clap::App::new("DT_FIFO"))
.subcommand(clap::App::new("DT_UNKNOWN"))
.subcommand(clap::App::new("SIG_ERR"))
.subcommand(clap::App::new("SIG_IGN"))
.subcommand(clap::App::new("SIG_DFL"))
.subcommand(clap::App::new("INT_MAX"))
.subcommand(clap::App::new("INT_MIN"))
.subcommand(clap::App::new("TIOCCBRK"))
.subcommand(clap::App::new("TIOCSBRK"))
.subcommand(clap::App::new("IPV6_HOPLIMIT"))

			.get_matches();

			println!("{}", match args.subcommand_name().unwrap() {
			
"SYS_statx" => libc::SYS_statx.to_string(),
"SYS_pkey_free" => libc::SYS_pkey_free.to_string(),
"SYS_pkey_alloc" => libc::SYS_pkey_alloc.to_string(),
"SYS_pkey_mprotect" => libc::SYS_pkey_mprotect.to_string(),
"SYS_pwritev2" => libc::SYS_pwritev2.to_string(),
"SYS_preadv2" => libc::SYS_preadv2.to_string(),
"SYS_copy_file_range" => libc::SYS_copy_file_range.to_string(),
"SYS_mlock2" => libc::SYS_mlock2.to_string(),
"SYS_membarrier" => libc::SYS_membarrier.to_string(),
"SYS_userfaultfd" => libc::SYS_userfaultfd.to_string(),
"SYS_execveat" => libc::SYS_execveat.to_string(),
"SYS_bpf" => libc::SYS_bpf.to_string(),
"SYS_kexec_file_load" => libc::SYS_kexec_file_load.to_string(),
"SYS_memfd_create" => libc::SYS_memfd_create.to_string(),
"SYS_getrandom" => libc::SYS_getrandom.to_string(),
"SYS_seccomp" => libc::SYS_seccomp.to_string(),
"SYS_renameat2" => libc::SYS_renameat2.to_string(),
"SYS_sched_getattr" => libc::SYS_sched_getattr.to_string(),
"SYS_sched_setattr" => libc::SYS_sched_setattr.to_string(),
"SYS_finit_module" => libc::SYS_finit_module.to_string(),
"SYS_kcmp" => libc::SYS_kcmp.to_string(),
"SYS_process_vm_writev" => libc::SYS_process_vm_writev.to_string(),
"SYS_process_vm_readv" => libc::SYS_process_vm_readv.to_string(),
"SYS_getcpu" => libc::SYS_getcpu.to_string(),
"SYS_setns" => libc::SYS_setns.to_string(),
"SYS_sendmmsg" => libc::SYS_sendmmsg.to_string(),
"SYS_syncfs" => libc::SYS_syncfs.to_string(),
"SYS_clock_adjtime" => libc::SYS_clock_adjtime.to_string(),
"SYS_open_by_handle_at" => libc::SYS_open_by_handle_at.to_string(),
"SYS_name_to_handle_at" => libc::SYS_name_to_handle_at.to_string(),
"SYS_prlimit64" => libc::SYS_prlimit64.to_string(),
"SYS_fanotify_mark" => libc::SYS_fanotify_mark.to_string(),
"SYS_fanotify_init" => libc::SYS_fanotify_init.to_string(),
"SYS_recvmmsg" => libc::SYS_recvmmsg.to_string(),
"SYS_perf_event_open" => libc::SYS_perf_event_open.to_string(),
"SYS_rt_tgsigqueueinfo" => libc::SYS_rt_tgsigqueueinfo.to_string(),
"SYS_pwritev" => libc::SYS_pwritev.to_string(),
"SYS_preadv" => libc::SYS_preadv.to_string(),
"SYS_inotify_init1" => libc::SYS_inotify_init1.to_string(),
"SYS_pipe2" => libc::SYS_pipe2.to_string(),
"SYS_dup3" => libc::SYS_dup3.to_string(),
"SYS_epoll_create1" => libc::SYS_epoll_create1.to_string(),
"SYS_eventfd2" => libc::SYS_eventfd2.to_string(),
"SYS_signalfd4" => libc::SYS_signalfd4.to_string(),
"SYS_accept4" => libc::SYS_accept4.to_string(),
"SYS_timerfd_gettime" => libc::SYS_timerfd_gettime.to_string(),
"SYS_timerfd_settime" => libc::SYS_timerfd_settime.to_string(),
"SYS_fallocate" => libc::SYS_fallocate.to_string(),
"SYS_eventfd" => libc::SYS_eventfd.to_string(),
"SYS_timerfd_create" => libc::SYS_timerfd_create.to_string(),
"SYS_signalfd" => libc::SYS_signalfd.to_string(),
"SYS_epoll_pwait" => libc::SYS_epoll_pwait.to_string(),
"SYS_utimensat" => libc::SYS_utimensat.to_string(),
"SYS_move_pages" => libc::SYS_move_pages.to_string(),
"SYS_vmsplice" => libc::SYS_vmsplice.to_string(),
"SYS_sync_file_range" => libc::SYS_sync_file_range.to_string(),
"SYS_tee" => libc::SYS_tee.to_string(),
"SYS_splice" => libc::SYS_splice.to_string(),
"SYS_get_robust_list" => libc::SYS_get_robust_list.to_string(),
"SYS_set_robust_list" => libc::SYS_set_robust_list.to_string(),
"SYS_unshare" => libc::SYS_unshare.to_string(),
"SYS_ppoll" => libc::SYS_ppoll.to_string(),
"SYS_pselect6" => libc::SYS_pselect6.to_string(),
"SYS_faccessat" => libc::SYS_faccessat.to_string(),
"SYS_fchmodat" => libc::SYS_fchmodat.to_string(),
"SYS_readlinkat" => libc::SYS_readlinkat.to_string(),
"SYS_symlinkat" => libc::SYS_symlinkat.to_string(),
"SYS_linkat" => libc::SYS_linkat.to_string(),
"SYS_renameat" => libc::SYS_renameat.to_string(),
"SYS_unlinkat" => libc::SYS_unlinkat.to_string(),
"SYS_newfstatat" => libc::SYS_newfstatat.to_string(),
"SYS_futimesat" => libc::SYS_futimesat.to_string(),
"SYS_fchownat" => libc::SYS_fchownat.to_string(),
"SYS_mknodat" => libc::SYS_mknodat.to_string(),
"SYS_mkdirat" => libc::SYS_mkdirat.to_string(),
"SYS_openat" => libc::SYS_openat.to_string(),
"SYS_migrate_pages" => libc::SYS_migrate_pages.to_string(),
"SYS_inotify_rm_watch" => libc::SYS_inotify_rm_watch.to_string(),
"SYS_inotify_add_watch" => libc::SYS_inotify_add_watch.to_string(),
"SYS_inotify_init" => libc::SYS_inotify_init.to_string(),
"SYS_ioprio_get" => libc::SYS_ioprio_get.to_string(),
"SYS_ioprio_set" => libc::SYS_ioprio_set.to_string(),
"SYS_keyctl" => libc::SYS_keyctl.to_string(),
"SYS_request_key" => libc::SYS_request_key.to_string(),
"SYS_add_key" => libc::SYS_add_key.to_string(),
"SYS_waitid" => libc::SYS_waitid.to_string(),
"SYS_kexec_load" => libc::SYS_kexec_load.to_string(),
"SYS_mq_getsetattr" => libc::SYS_mq_getsetattr.to_string(),
"SYS_mq_notify" => libc::SYS_mq_notify.to_string(),
"SYS_mq_timedreceive" => libc::SYS_mq_timedreceive.to_string(),
"SYS_mq_timedsend" => libc::SYS_mq_timedsend.to_string(),
"SYS_mq_unlink" => libc::SYS_mq_unlink.to_string(),
"SYS_mq_open" => libc::SYS_mq_open.to_string(),
"SYS_get_mempolicy" => libc::SYS_get_mempolicy.to_string(),
"SYS_set_mempolicy" => libc::SYS_set_mempolicy.to_string(),
"SYS_mbind" => libc::SYS_mbind.to_string(),
"SYS_vserver" => libc::SYS_vserver.to_string(),
"SYS_utimes" => libc::SYS_utimes.to_string(),
"SYS_tgkill" => libc::SYS_tgkill.to_string(),
"SYS_epoll_ctl" => libc::SYS_epoll_ctl.to_string(),
"SYS_epoll_wait" => libc::SYS_epoll_wait.to_string(),
"SYS_exit_group" => libc::SYS_exit_group.to_string(),
"SYS_clock_nanosleep" => libc::SYS_clock_nanosleep.to_string(),
"SYS_clock_getres" => libc::SYS_clock_getres.to_string(),
"SYS_clock_gettime" => libc::SYS_clock_gettime.to_string(),
"SYS_clock_settime" => libc::SYS_clock_settime.to_string(),
"SYS_timer_delete" => libc::SYS_timer_delete.to_string(),
"SYS_timer_getoverrun" => libc::SYS_timer_getoverrun.to_string(),
"SYS_timer_gettime" => libc::SYS_timer_gettime.to_string(),
"SYS_timer_settime" => libc::SYS_timer_settime.to_string(),
"SYS_timer_create" => libc::SYS_timer_create.to_string(),
"SYS_fadvise64" => libc::SYS_fadvise64.to_string(),
"SYS_semtimedop" => libc::SYS_semtimedop.to_string(),
"SYS_restart_syscall" => libc::SYS_restart_syscall.to_string(),
"SYS_set_tid_address" => libc::SYS_set_tid_address.to_string(),
"SYS_getdents64" => libc::SYS_getdents64.to_string(),
"SYS_remap_file_pages" => libc::SYS_remap_file_pages.to_string(),
"SYS_epoll_wait_old" => libc::SYS_epoll_wait_old.to_string(),
"SYS_epoll_ctl_old" => libc::SYS_epoll_ctl_old.to_string(),
"SYS_epoll_create" => libc::SYS_epoll_create.to_string(),
"SYS_lookup_dcookie" => libc::SYS_lookup_dcookie.to_string(),
"SYS_get_thread_area" => libc::SYS_get_thread_area.to_string(),
"SYS_io_cancel" => libc::SYS_io_cancel.to_string(),
"SYS_io_submit" => libc::SYS_io_submit.to_string(),
"SYS_io_getevents" => libc::SYS_io_getevents.to_string(),
"SYS_io_destroy" => libc::SYS_io_destroy.to_string(),
"SYS_io_setup" => libc::SYS_io_setup.to_string(),
"SYS_set_thread_area" => libc::SYS_set_thread_area.to_string(),
"SYS_sched_getaffinity" => libc::SYS_sched_getaffinity.to_string(),
"SYS_sched_setaffinity" => libc::SYS_sched_setaffinity.to_string(),
"SYS_futex" => libc::SYS_futex.to_string(),
"SYS_time" => libc::SYS_time.to_string(),
"SYS_tkill" => libc::SYS_tkill.to_string(),
"SYS_fremovexattr" => libc::SYS_fremovexattr.to_string(),
"SYS_lremovexattr" => libc::SYS_lremovexattr.to_string(),
"SYS_removexattr" => libc::SYS_removexattr.to_string(),
"SYS_flistxattr" => libc::SYS_flistxattr.to_string(),
"SYS_llistxattr" => libc::SYS_llistxattr.to_string(),
"SYS_listxattr" => libc::SYS_listxattr.to_string(),
"SYS_fgetxattr" => libc::SYS_fgetxattr.to_string(),
"SYS_lgetxattr" => libc::SYS_lgetxattr.to_string(),
"SYS_getxattr" => libc::SYS_getxattr.to_string(),
"SYS_fsetxattr" => libc::SYS_fsetxattr.to_string(),
"SYS_lsetxattr" => libc::SYS_lsetxattr.to_string(),
"SYS_setxattr" => libc::SYS_setxattr.to_string(),
"SYS_readahead" => libc::SYS_readahead.to_string(),
"SYS_gettid" => libc::SYS_gettid.to_string(),
"SYS_security" => libc::SYS_security.to_string(),
"SYS_tuxcall" => libc::SYS_tuxcall.to_string(),
"SYS_afs_syscall" => libc::SYS_afs_syscall.to_string(),
"SYS_putpmsg" => libc::SYS_putpmsg.to_string(),
"SYS_getpmsg" => libc::SYS_getpmsg.to_string(),
"SYS_nfsservctl" => libc::SYS_nfsservctl.to_string(),
"SYS_quotactl" => libc::SYS_quotactl.to_string(),
"SYS_query_module" => libc::SYS_query_module.to_string(),
"SYS_get_kernel_syms" => libc::SYS_get_kernel_syms.to_string(),
"SYS_delete_module" => libc::SYS_delete_module.to_string(),
"SYS_init_module" => libc::SYS_init_module.to_string(),
"SYS_create_module" => libc::SYS_create_module.to_string(),
"SYS_ioperm" => libc::SYS_ioperm.to_string(),
"SYS_iopl" => libc::SYS_iopl.to_string(),
"SYS_setdomainname" => libc::SYS_setdomainname.to_string(),
"SYS_sethostname" => libc::SYS_sethostname.to_string(),
"SYS_reboot" => libc::SYS_reboot.to_string(),
"SYS_swapoff" => libc::SYS_swapoff.to_string(),
"SYS_swapon" => libc::SYS_swapon.to_string(),
"SYS_umount2" => libc::SYS_umount2.to_string(),
"SYS_mount" => libc::SYS_mount.to_string(),
"SYS_settimeofday" => libc::SYS_settimeofday.to_string(),
"SYS_acct" => libc::SYS_acct.to_string(),
"SYS_sync" => libc::SYS_sync.to_string(),
"SYS_chroot" => libc::SYS_chroot.to_string(),
"SYS_setrlimit" => libc::SYS_setrlimit.to_string(),
"SYS_adjtimex" => libc::SYS_adjtimex.to_string(),
"SYS_arch_prctl" => libc::SYS_arch_prctl.to_string(),
"SYS_prctl" => libc::SYS_prctl.to_string(),
"SYS__sysctl" => libc::SYS__sysctl.to_string(),
"SYS_pivot_root" => libc::SYS_pivot_root.to_string(),
"SYS_modify_ldt" => libc::SYS_modify_ldt.to_string(),
"SYS_vhangup" => libc::SYS_vhangup.to_string(),
"SYS_munlockall" => libc::SYS_munlockall.to_string(),
"SYS_mlockall" => libc::SYS_mlockall.to_string(),
"SYS_munlock" => libc::SYS_munlock.to_string(),
"SYS_mlock" => libc::SYS_mlock.to_string(),
"SYS_sched_rr_get_interval" => libc::SYS_sched_rr_get_interval.to_string(),
"SYS_sched_get_priority_min" => libc::SYS_sched_get_priority_min.to_string(),
"SYS_sched_get_priority_max" => libc::SYS_sched_get_priority_max.to_string(),
"SYS_sched_getscheduler" => libc::SYS_sched_getscheduler.to_string(),
"SYS_sched_setscheduler" => libc::SYS_sched_setscheduler.to_string(),
"SYS_sched_getparam" => libc::SYS_sched_getparam.to_string(),
"SYS_sched_setparam" => libc::SYS_sched_setparam.to_string(),
"SYS_setpriority" => libc::SYS_setpriority.to_string(),
"SYS_getpriority" => libc::SYS_getpriority.to_string(),
"SYS_sysfs" => libc::SYS_sysfs.to_string(),
"SYS_fstatfs" => libc::SYS_fstatfs.to_string(),
"SYS_statfs" => libc::SYS_statfs.to_string(),
"SYS_ustat" => libc::SYS_ustat.to_string(),
"SYS_personality" => libc::SYS_personality.to_string(),
"SYS_uselib" => libc::SYS_uselib.to_string(),
"SYS_mknod" => libc::SYS_mknod.to_string(),
"SYS_utime" => libc::SYS_utime.to_string(),
"SYS_sigaltstack" => libc::SYS_sigaltstack.to_string(),
"SYS_rt_sigsuspend" => libc::SYS_rt_sigsuspend.to_string(),
"SYS_rt_sigqueueinfo" => libc::SYS_rt_sigqueueinfo.to_string(),
"SYS_rt_sigtimedwait" => libc::SYS_rt_sigtimedwait.to_string(),
"SYS_rt_sigpending" => libc::SYS_rt_sigpending.to_string(),
"SYS_capset" => libc::SYS_capset.to_string(),
"SYS_capget" => libc::SYS_capget.to_string(),
"SYS_getsid" => libc::SYS_getsid.to_string(),
"SYS_setfsgid" => libc::SYS_setfsgid.to_string(),
"SYS_setfsuid" => libc::SYS_setfsuid.to_string(),
"SYS_getpgid" => libc::SYS_getpgid.to_string(),
"SYS_getresgid" => libc::SYS_getresgid.to_string(),
"SYS_setresgid" => libc::SYS_setresgid.to_string(),
"SYS_getresuid" => libc::SYS_getresuid.to_string(),
"SYS_setresuid" => libc::SYS_setresuid.to_string(),
"SYS_setgroups" => libc::SYS_setgroups.to_string(),
"SYS_getgroups" => libc::SYS_getgroups.to_string(),
"SYS_setregid" => libc::SYS_setregid.to_string(),
"SYS_setreuid" => libc::SYS_setreuid.to_string(),
"SYS_setsid" => libc::SYS_setsid.to_string(),
"SYS_getpgrp" => libc::SYS_getpgrp.to_string(),
"SYS_getppid" => libc::SYS_getppid.to_string(),
"SYS_setpgid" => libc::SYS_setpgid.to_string(),
"SYS_getegid" => libc::SYS_getegid.to_string(),
"SYS_geteuid" => libc::SYS_geteuid.to_string(),
"SYS_setgid" => libc::SYS_setgid.to_string(),
"SYS_setuid" => libc::SYS_setuid.to_string(),
"SYS_getgid" => libc::SYS_getgid.to_string(),
"SYS_syslog" => libc::SYS_syslog.to_string(),
"SYS_getuid" => libc::SYS_getuid.to_string(),
"SYS_ptrace" => libc::SYS_ptrace.to_string(),
"SYS_times" => libc::SYS_times.to_string(),
"SYS_sysinfo" => libc::SYS_sysinfo.to_string(),
"SYS_getrusage" => libc::SYS_getrusage.to_string(),
"SYS_getrlimit" => libc::SYS_getrlimit.to_string(),
"SYS_gettimeofday" => libc::SYS_gettimeofday.to_string(),
"SYS_umask" => libc::SYS_umask.to_string(),
"SYS_lchown" => libc::SYS_lchown.to_string(),
"SYS_fchown" => libc::SYS_fchown.to_string(),
"SYS_chown" => libc::SYS_chown.to_string(),
"SYS_fchmod" => libc::SYS_fchmod.to_string(),
"SYS_chmod" => libc::SYS_chmod.to_string(),
"SYS_readlink" => libc::SYS_readlink.to_string(),
"SYS_symlink" => libc::SYS_symlink.to_string(),
"SYS_unlink" => libc::SYS_unlink.to_string(),
"SYS_link" => libc::SYS_link.to_string(),
"SYS_creat" => libc::SYS_creat.to_string(),
"SYS_rmdir" => libc::SYS_rmdir.to_string(),
"SYS_mkdir" => libc::SYS_mkdir.to_string(),
"SYS_rename" => libc::SYS_rename.to_string(),
"SYS_fchdir" => libc::SYS_fchdir.to_string(),
"SYS_chdir" => libc::SYS_chdir.to_string(),
"SYS_getcwd" => libc::SYS_getcwd.to_string(),
"SYS_getdents" => libc::SYS_getdents.to_string(),
"SYS_ftruncate" => libc::SYS_ftruncate.to_string(),
"SYS_truncate" => libc::SYS_truncate.to_string(),
"SYS_fdatasync" => libc::SYS_fdatasync.to_string(),
"SYS_fsync" => libc::SYS_fsync.to_string(),
"SYS_flock" => libc::SYS_flock.to_string(),
"SYS_fcntl" => libc::SYS_fcntl.to_string(),
"SYS_msgctl" => libc::SYS_msgctl.to_string(),
"SYS_msgrcv" => libc::SYS_msgrcv.to_string(),
"SYS_msgsnd" => libc::SYS_msgsnd.to_string(),
"SYS_msgget" => libc::SYS_msgget.to_string(),
"SYS_shmdt" => libc::SYS_shmdt.to_string(),
"SYS_semctl" => libc::SYS_semctl.to_string(),
"SYS_semop" => libc::SYS_semop.to_string(),
"SYS_semget" => libc::SYS_semget.to_string(),
"SYS_uname" => libc::SYS_uname.to_string(),
"SYS_kill" => libc::SYS_kill.to_string(),
"SYS_wait4" => libc::SYS_wait4.to_string(),
"SYS_exit" => libc::SYS_exit.to_string(),
"SYS_execve" => libc::SYS_execve.to_string(),
"SYS_vfork" => libc::SYS_vfork.to_string(),
"SYS_fork" => libc::SYS_fork.to_string(),
"SYS_clone" => libc::SYS_clone.to_string(),
"SYS_getsockopt" => libc::SYS_getsockopt.to_string(),
"SYS_setsockopt" => libc::SYS_setsockopt.to_string(),
"SYS_socketpair" => libc::SYS_socketpair.to_string(),
"SYS_getpeername" => libc::SYS_getpeername.to_string(),
"SYS_getsockname" => libc::SYS_getsockname.to_string(),
"SYS_listen" => libc::SYS_listen.to_string(),
"SYS_bind" => libc::SYS_bind.to_string(),
"SYS_shutdown" => libc::SYS_shutdown.to_string(),
"SYS_recvmsg" => libc::SYS_recvmsg.to_string(),
"SYS_sendmsg" => libc::SYS_sendmsg.to_string(),
"SYS_recvfrom" => libc::SYS_recvfrom.to_string(),
"SYS_sendto" => libc::SYS_sendto.to_string(),
"SYS_accept" => libc::SYS_accept.to_string(),
"SYS_connect" => libc::SYS_connect.to_string(),
"SYS_socket" => libc::SYS_socket.to_string(),
"SYS_sendfile" => libc::SYS_sendfile.to_string(),
"SYS_getpid" => libc::SYS_getpid.to_string(),
"SYS_setitimer" => libc::SYS_setitimer.to_string(),
"SYS_alarm" => libc::SYS_alarm.to_string(),
"SYS_getitimer" => libc::SYS_getitimer.to_string(),
"SYS_nanosleep" => libc::SYS_nanosleep.to_string(),
"SYS_pause" => libc::SYS_pause.to_string(),
"SYS_dup2" => libc::SYS_dup2.to_string(),
"SYS_dup" => libc::SYS_dup.to_string(),
"SYS_shmctl" => libc::SYS_shmctl.to_string(),
"SYS_shmat" => libc::SYS_shmat.to_string(),
"SYS_shmget" => libc::SYS_shmget.to_string(),
"SYS_madvise" => libc::SYS_madvise.to_string(),
"SYS_mincore" => libc::SYS_mincore.to_string(),
"SYS_msync" => libc::SYS_msync.to_string(),
"SYS_mremap" => libc::SYS_mremap.to_string(),
"SYS_sched_yield" => libc::SYS_sched_yield.to_string(),
"SYS_select" => libc::SYS_select.to_string(),
"SYS_pipe" => libc::SYS_pipe.to_string(),
"SYS_access" => libc::SYS_access.to_string(),
"SYS_writev" => libc::SYS_writev.to_string(),
"SYS_readv" => libc::SYS_readv.to_string(),
"SYS_pwrite64" => libc::SYS_pwrite64.to_string(),
"SYS_pread64" => libc::SYS_pread64.to_string(),
"SYS_ioctl" => libc::SYS_ioctl.to_string(),
"SYS_rt_sigreturn" => libc::SYS_rt_sigreturn.to_string(),
"SYS_rt_sigprocmask" => libc::SYS_rt_sigprocmask.to_string(),
"SYS_rt_sigaction" => libc::SYS_rt_sigaction.to_string(),
"SYS_brk" => libc::SYS_brk.to_string(),
"SYS_munmap" => libc::SYS_munmap.to_string(),
"SYS_mprotect" => libc::SYS_mprotect.to_string(),
"SYS_mmap" => libc::SYS_mmap.to_string(),
"SYS_lseek" => libc::SYS_lseek.to_string(),
"SYS_poll" => libc::SYS_poll.to_string(),
"SYS_lstat" => libc::SYS_lstat.to_string(),
"SYS_fstat" => libc::SYS_fstat.to_string(),
"SYS_stat" => libc::SYS_stat.to_string(),
"SYS_close" => libc::SYS_close.to_string(),
"SYS_open" => libc::SYS_open.to_string(),
"SYS_write" => libc::SYS_write.to_string(),
"SYS_read" => libc::SYS_read.to_string(),
"__SIZEOF_PTHREAD_RWLOCK_T" => libc::__SIZEOF_PTHREAD_RWLOCK_T.to_string(),
"__SIZEOF_PTHREAD_MUTEX_T" => libc::__SIZEOF_PTHREAD_MUTEX_T.to_string(),
"REG_CR2" => libc::REG_CR2.to_string(),
"REG_OLDMASK" => libc::REG_OLDMASK.to_string(),
"REG_TRAPNO" => libc::REG_TRAPNO.to_string(),
"REG_ERR" => libc::REG_ERR.to_string(),
"REG_CSGSFS" => libc::REG_CSGSFS.to_string(),
"REG_EFL" => libc::REG_EFL.to_string(),
"REG_RIP" => libc::REG_RIP.to_string(),
"REG_RSP" => libc::REG_RSP.to_string(),
"REG_RCX" => libc::REG_RCX.to_string(),
"REG_RAX" => libc::REG_RAX.to_string(),
"REG_RDX" => libc::REG_RDX.to_string(),
"REG_RBX" => libc::REG_RBX.to_string(),
"REG_RBP" => libc::REG_RBP.to_string(),
"REG_RSI" => libc::REG_RSI.to_string(),
"REG_RDI" => libc::REG_RDI.to_string(),
"REG_R15" => libc::REG_R15.to_string(),
"REG_R14" => libc::REG_R14.to_string(),
"REG_R13" => libc::REG_R13.to_string(),
"REG_R12" => libc::REG_R12.to_string(),
"REG_R11" => libc::REG_R11.to_string(),
"REG_R10" => libc::REG_R10.to_string(),
"REG_R9" => libc::REG_R9.to_string(),
"REG_R8" => libc::REG_R8.to_string(),
"GS" => libc::GS.to_string(),
"FS" => libc::FS.to_string(),
"ES" => libc::ES.to_string(),
"DS" => libc::DS.to_string(),
"GS_BASE" => libc::GS_BASE.to_string(),
"FS_BASE" => libc::FS_BASE.to_string(),
"SS" => libc::SS.to_string(),
"RSP" => libc::RSP.to_string(),
"EFLAGS" => libc::EFLAGS.to_string(),
"CS" => libc::CS.to_string(),
"RIP" => libc::RIP.to_string(),
"ORIG_RAX" => libc::ORIG_RAX.to_string(),
"RDI" => libc::RDI.to_string(),
"RSI" => libc::RSI.to_string(),
"RDX" => libc::RDX.to_string(),
"RCX" => libc::RCX.to_string(),
"RAX" => libc::RAX.to_string(),
"R8" => libc::R8.to_string(),
"R9" => libc::R9.to_string(),
"R10" => libc::R10.to_string(),
"R11" => libc::R11.to_string(),
"RBX" => libc::RBX.to_string(),
"RBP" => libc::RBP.to_string(),
"R12" => libc::R12.to_string(),
"R13" => libc::R13.to_string(),
"R14" => libc::R14.to_string(),
"R15" => libc::R15.to_string(),
"FIONREAD" => libc::FIONREAD.to_string(),
"TIOCSWINSZ" => libc::TIOCSWINSZ.to_string(),
"TIOCGWINSZ" => libc::TIOCGWINSZ.to_string(),
"TIOCOUTQ" => libc::TIOCOUTQ.to_string(),
"TIOCSPGRP" => libc::TIOCSPGRP.to_string(),
"TIOCGPGRP" => libc::TIOCGPGRP.to_string(),
"TIOCINQ" => libc::TIOCINQ.to_string(),
"TCFLSH" => libc::TCFLSH.to_string(),
"TCXONC" => libc::TCXONC.to_string(),
"TCSBRK" => libc::TCSBRK.to_string(),
"TCSETAF" => libc::TCSETAF.to_string(),
"TCSETAW" => libc::TCSETAW.to_string(),
"TCSETA" => libc::TCSETA.to_string(),
"TCGETA" => libc::TCGETA.to_string(),
"TCSETSF" => libc::TCSETSF.to_string(),
"TCSETSW" => libc::TCSETSW.to_string(),
"TCSETS" => libc::TCSETS.to_string(),
"TCGETS" => libc::TCGETS.to_string(),
"EXTPROC" => libc::EXTPROC.to_string(),
"FLUSHO" => libc::FLUSHO.to_string(),
"TOSTOP" => libc::TOSTOP.to_string(),
"IEXTEN" => libc::IEXTEN.to_string(),
"VMIN" => libc::VMIN.to_string(),
"VEOL2" => libc::VEOL2.to_string(),
"VEOL" => libc::VEOL.to_string(),
"B4000000" => libc::B4000000.to_string(),
"B3500000" => libc::B3500000.to_string(),
"B3000000" => libc::B3000000.to_string(),
"B2500000" => libc::B2500000.to_string(),
"B2000000" => libc::B2000000.to_string(),
"B1500000" => libc::B1500000.to_string(),
"B1152000" => libc::B1152000.to_string(),
"B1000000" => libc::B1000000.to_string(),
"B921600" => libc::B921600.to_string(),
"B576000" => libc::B576000.to_string(),
"B500000" => libc::B500000.to_string(),
"B460800" => libc::B460800.to_string(),
"B230400" => libc::B230400.to_string(),
"B115200" => libc::B115200.to_string(),
"B57600" => libc::B57600.to_string(),
"BOTHER" => libc::BOTHER.to_string(),
"EXTB" => libc::EXTB.to_string(),
"EXTA" => libc::EXTA.to_string(),
"B38400" => libc::B38400.to_string(),
"B19200" => libc::B19200.to_string(),
"B9600" => libc::B9600.to_string(),
"B4800" => libc::B4800.to_string(),
"B2400" => libc::B2400.to_string(),
"B1800" => libc::B1800.to_string(),
"B1200" => libc::B1200.to_string(),
"B600" => libc::B600.to_string(),
"B300" => libc::B300.to_string(),
"B200" => libc::B200.to_string(),
"B150" => libc::B150.to_string(),
"B134" => libc::B134.to_string(),
"B110" => libc::B110.to_string(),
"B75" => libc::B75.to_string(),
"B50" => libc::B50.to_string(),
"B0" => libc::B0.to_string(),
"XTABS" => libc::XTABS.to_string(),
"VTDLY" => libc::VTDLY.to_string(),
"FFDLY" => libc::FFDLY.to_string(),
"BSDLY" => libc::BSDLY.to_string(),
"TABDLY" => libc::TABDLY.to_string(),
"CRDLY" => libc::CRDLY.to_string(),
"NLDLY" => libc::NLDLY.to_string(),
"OLCUC" => libc::OLCUC.to_string(),
"VSWTC" => libc::VSWTC.to_string(),
"CBAUDEX" => libc::CBAUDEX.to_string(),
"CIBAUD" => libc::CIBAUD.to_string(),
"NOFLSH" => libc::NOFLSH.to_string(),
"PENDIN" => libc::PENDIN.to_string(),
"ICANON" => libc::ICANON.to_string(),
"ISIG" => libc::ISIG.to_string(),
"ECHOCTL" => libc::ECHOCTL.to_string(),
"ECHOPRT" => libc::ECHOPRT.to_string(),
"ECHONL" => libc::ECHONL.to_string(),
"ECHOK" => libc::ECHOK.to_string(),
"ECHOE" => libc::ECHOE.to_string(),
"ECHOKE" => libc::ECHOKE.to_string(),
"CLOCAL" => libc::CLOCAL.to_string(),
"HUPCL" => libc::HUPCL.to_string(),
"PARODD" => libc::PARODD.to_string(),
"PARENB" => libc::PARENB.to_string(),
"CREAD" => libc::CREAD.to_string(),
"CSTOPB" => libc::CSTOPB.to_string(),
"CS8" => libc::CS8.to_string(),
"CS7" => libc::CS7.to_string(),
"CS6" => libc::CS6.to_string(),
"CSIZE" => libc::CSIZE.to_string(),
"ONLCR" => libc::ONLCR.to_string(),
"IXOFF" => libc::IXOFF.to_string(),
"IXON" => libc::IXON.to_string(),
"VTIME" => libc::VTIME.to_string(),
"VDISCARD" => libc::VDISCARD.to_string(),
"VSTOP" => libc::VSTOP.to_string(),
"VSTART" => libc::VSTART.to_string(),
"VSUSP" => libc::VSUSP.to_string(),
"VREPRINT" => libc::VREPRINT.to_string(),
"VWERASE" => libc::VWERASE.to_string(),
"VT1" => libc::VT1.to_string(),
"BS1" => libc::BS1.to_string(),
"FF1" => libc::FF1.to_string(),
"CR3" => libc::CR3.to_string(),
"CR2" => libc::CR2.to_string(),
"CR1" => libc::CR1.to_string(),
"TAB3" => libc::TAB3.to_string(),
"TAB2" => libc::TAB2.to_string(),
"TAB1" => libc::TAB1.to_string(),
"CBAUD" => libc::CBAUD.to_string(),
"MINSIGSTKSZ" => libc::MINSIGSTKSZ.to_string(),
"SIGSTKSZ" => libc::SIGSTKSZ.to_string(),
"MCL_FUTURE" => libc::MCL_FUTURE.to_string(),
"MCL_CURRENT" => libc::MCL_CURRENT.to_string(),
"PTRACE_PEEKSIGINFO_SHARED" => libc::PTRACE_PEEKSIGINFO_SHARED.to_string(),
"PTRACE_SETREGS" => libc::PTRACE_SETREGS.to_string(),
"PTRACE_GETREGS" => libc::PTRACE_GETREGS.to_string(),
"PTRACE_SETFPXREGS" => libc::PTRACE_SETFPXREGS.to_string(),
"PTRACE_GETFPXREGS" => libc::PTRACE_GETFPXREGS.to_string(),
"PTRACE_SETFPREGS" => libc::PTRACE_SETFPREGS.to_string(),
"PTRACE_GETFPREGS" => libc::PTRACE_GETFPREGS.to_string(),
"FIONBIO" => libc::FIONBIO.to_string(),
"FIONCLEX" => libc::FIONCLEX.to_string(),
"FIOCLEX" => libc::FIOCLEX.to_string(),
"EREMOTEIO" => libc::EREMOTEIO.to_string(),
"EISNAM" => libc::EISNAM.to_string(),
"ENAVAIL" => libc::ENAVAIL.to_string(),
"ENOTNAM" => libc::ENOTNAM.to_string(),
"EUCLEAN" => libc::EUCLEAN.to_string(),
"EDEADLOCK" => libc::EDEADLOCK.to_string(),
"MAP_SYNC" => libc::MAP_SYNC.to_string(),
"MAP_STACK" => libc::MAP_STACK.to_string(),
"MAP_NONBLOCK" => libc::MAP_NONBLOCK.to_string(),
"MAP_POPULATE" => libc::MAP_POPULATE.to_string(),
"MAP_EXECUTABLE" => libc::MAP_EXECUTABLE.to_string(),
"MAP_DENYWRITE" => libc::MAP_DENYWRITE.to_string(),
"MAP_ANONYMOUS" => libc::MAP_ANONYMOUS.to_string(),
"MAP_ANON" => libc::MAP_ANON.to_string(),
"MAP_32BIT" => libc::MAP_32BIT.to_string(),
"MAP_NORESERVE" => libc::MAP_NORESERVE.to_string(),
"MAP_LOCKED" => libc::MAP_LOCKED.to_string(),
"MAP_HUGETLB" => libc::MAP_HUGETLB.to_string(),
"O_NOFOLLOW" => libc::O_NOFOLLOW.to_string(),
"O_DIRECTORY" => libc::O_DIRECTORY.to_string(),
"O_DIRECT" => libc::O_DIRECT.to_string(),
"__SIZEOF_PTHREAD_MUTEXATTR_T" => libc::__SIZEOF_PTHREAD_MUTEXATTR_T.to_string(),
"__SIZEOF_PTHREAD_CONDATTR_T" => libc::__SIZEOF_PTHREAD_CONDATTR_T.to_string(),
"EFD_CLOEXEC" => libc::EFD_CLOEXEC.to_string(),
"EPOLL_CLOEXEC" => libc::EPOLL_CLOEXEC.to_string(),
"SA_NOCLDSTOP" => libc::SA_NOCLDSTOP.to_string(),
"SA_RESTART" => libc::SA_RESTART.to_string(),
"SA_RESETHAND" => libc::SA_RESETHAND.to_string(),
"SA_NODEFER" => libc::SA_NODEFER.to_string(),
"EDOTDOT" => libc::EDOTDOT.to_string(),
"EPROTO" => libc::EPROTO.to_string(),
"ECOMM" => libc::ECOMM.to_string(),
"ESRMNT" => libc::ESRMNT.to_string(),
"EADV" => libc::EADV.to_string(),
"ENOLINK" => libc::ENOLINK.to_string(),
"EREMOTE" => libc::EREMOTE.to_string(),
"ENOPKG" => libc::ENOPKG.to_string(),
"ENONET" => libc::ENONET.to_string(),
"ENOSR" => libc::ENOSR.to_string(),
"ETIME" => libc::ETIME.to_string(),
"ENODATA" => libc::ENODATA.to_string(),
"ENOSTR" => libc::ENOSTR.to_string(),
"EBFONT" => libc::EBFONT.to_string(),
"O_CLOEXEC" => libc::O_CLOEXEC.to_string(),
"O_TRUNC" => libc::O_TRUNC.to_string(),
"NCCS" => libc::NCCS.to_string(),
"SFD_CLOEXEC" => libc::SFD_CLOEXEC.to_string(),
"TIOCM_DSR" => libc::TIOCM_DSR.to_string(),
"TIOCM_RNG" => libc::TIOCM_RNG.to_string(),
"TIOCM_CAR" => libc::TIOCM_CAR.to_string(),
"TIOCM_CTS" => libc::TIOCM_CTS.to_string(),
"TIOCM_SR" => libc::TIOCM_SR.to_string(),
"TIOCM_ST" => libc::TIOCM_ST.to_string(),
"TIOCCONS" => libc::TIOCCONS.to_string(),
"TIOCMSET" => libc::TIOCMSET.to_string(),
"TIOCMBIC" => libc::TIOCMBIC.to_string(),
"TIOCMBIS" => libc::TIOCMBIS.to_string(),
"TIOCMGET" => libc::TIOCMGET.to_string(),
"TIOCSTI" => libc::TIOCSTI.to_string(),
"TIOCSCTTY" => libc::TIOCSCTTY.to_string(),
"TIOCNXCL" => libc::TIOCNXCL.to_string(),
"TIOCEXCL" => libc::TIOCEXCL.to_string(),
"TIOCGSERIAL" => libc::TIOCGSERIAL.to_string(),
"TIOCLINUX" => libc::TIOCLINUX.to_string(),
"TCSAFLUSH" => libc::TCSAFLUSH.to_string(),
"TCSADRAIN" => libc::TCSADRAIN.to_string(),
"TCSANOW" => libc::TCSANOW.to_string(),
"SFD_NONBLOCK" => libc::SFD_NONBLOCK.to_string(),
"F_UNLCK" => libc::F_UNLCK.to_string(),
"F_WRLCK" => libc::F_WRLCK.to_string(),
"F_RDLCK" => libc::F_RDLCK.to_string(),
"F_OFD_SETLKW" => libc::F_OFD_SETLKW.to_string(),
"F_OFD_SETLK" => libc::F_OFD_SETLK.to_string(),
"F_OFD_GETLK" => libc::F_OFD_GETLK.to_string(),
"F_SETLKW" => libc::F_SETLKW.to_string(),
"F_SETLK" => libc::F_SETLK.to_string(),
"F_SETOWN" => libc::F_SETOWN.to_string(),
"F_GETOWN" => libc::F_GETOWN.to_string(),
"F_GETLK" => libc::F_GETLK.to_string(),
"EFD_NONBLOCK" => libc::EFD_NONBLOCK.to_string(),
"PTRACE_DETACH" => libc::PTRACE_DETACH.to_string(),
"O_NDELAY" => libc::O_NDELAY.to_string(),
"O_ASYNC" => libc::O_ASYNC.to_string(),
"POLLWRBAND" => libc::POLLWRBAND.to_string(),
"POLLWRNORM" => libc::POLLWRNORM.to_string(),
"SIG_UNBLOCK" => libc::SIG_UNBLOCK.to_string(),
"SIG_BLOCK" => libc::SIG_BLOCK.to_string(),
"SIG_SETMASK" => libc::SIG_SETMASK.to_string(),
"SIGPWR" => libc::SIGPWR.to_string(),
"SIGPOLL" => libc::SIGPOLL.to_string(),
"SIGUNUSED" => libc::SIGUNUSED.to_string(),
"SIGSTKFLT" => libc::SIGSTKFLT.to_string(),
"SIGSYS" => libc::SIGSYS.to_string(),
"SIGIO" => libc::SIGIO.to_string(),
"SIGURG" => libc::SIGURG.to_string(),
"SIGTSTP" => libc::SIGTSTP.to_string(),
"SIGSTOP" => libc::SIGSTOP.to_string(),
"SIGCONT" => libc::SIGCONT.to_string(),
"SIGUSR2" => libc::SIGUSR2.to_string(),
"SIGUSR1" => libc::SIGUSR1.to_string(),
"SIGBUS" => libc::SIGBUS.to_string(),
"SIGCHLD" => libc::SIGCHLD.to_string(),
"SIGWINCH" => libc::SIGWINCH.to_string(),
"SIGPROF" => libc::SIGPROF.to_string(),
"SIGVTALRM" => libc::SIGVTALRM.to_string(),
"SIGXFSZ" => libc::SIGXFSZ.to_string(),
"SIGXCPU" => libc::SIGXCPU.to_string(),
"SIGTTOU" => libc::SIGTTOU.to_string(),
"SIGTTIN" => libc::SIGTTIN.to_string(),
"SA_NOCLDWAIT" => libc::SA_NOCLDWAIT.to_string(),
"SA_SIGINFO" => libc::SA_SIGINFO.to_string(),
"SA_ONSTACK" => libc::SA_ONSTACK.to_string(),
"SOCK_DGRAM" => libc::SOCK_DGRAM.to_string(),
"SOCK_STREAM" => libc::SOCK_STREAM.to_string(),
"SO_DETACH_BPF" => libc::SO_DETACH_BPF.to_string(),
"SO_ATTACH_BPF" => libc::SO_ATTACH_BPF.to_string(),
"SO_INCOMING_CPU" => libc::SO_INCOMING_CPU.to_string(),
"SO_BPF_EXTENSIONS" => libc::SO_BPF_EXTENSIONS.to_string(),
"SO_MAX_PACING_RATE" => libc::SO_MAX_PACING_RATE.to_string(),
"SO_BUSY_POLL" => libc::SO_BUSY_POLL.to_string(),
"SO_SELECT_ERR_QUEUE" => libc::SO_SELECT_ERR_QUEUE.to_string(),
"SO_LOCK_FILTER" => libc::SO_LOCK_FILTER.to_string(),
"SO_NOFCS" => libc::SO_NOFCS.to_string(),
"SO_PEEK_OFF" => libc::SO_PEEK_OFF.to_string(),
"SCM_WIFI_STATUS" => libc::SCM_WIFI_STATUS.to_string(),
"SO_WIFI_STATUS" => libc::SO_WIFI_STATUS.to_string(),
"SO_RXQ_OVFL" => libc::SO_RXQ_OVFL.to_string(),
"SO_DOMAIN" => libc::SO_DOMAIN.to_string(),
"SO_PROTOCOL" => libc::SO_PROTOCOL.to_string(),
"SO_MARK" => libc::SO_MARK.to_string(),
"SCM_TIMESTAMPNS" => libc::SCM_TIMESTAMPNS.to_string(),
"SO_TIMESTAMPNS" => libc::SO_TIMESTAMPNS.to_string(),
"SO_PASSSEC" => libc::SO_PASSSEC.to_string(),
"SO_PEERSEC" => libc::SO_PEERSEC.to_string(),
"SO_ACCEPTCONN" => libc::SO_ACCEPTCONN.to_string(),
"SO_TIMESTAMP" => libc::SO_TIMESTAMP.to_string(),
"SO_PEERNAME" => libc::SO_PEERNAME.to_string(),
"SO_GET_FILTER" => libc::SO_GET_FILTER.to_string(),
"SO_DETACH_FILTER" => libc::SO_DETACH_FILTER.to_string(),
"SO_ATTACH_FILTER" => libc::SO_ATTACH_FILTER.to_string(),
"SO_BINDTODEVICE" => libc::SO_BINDTODEVICE.to_string(),
"SO_SECURITY_ENCRYPTION_NETWORK" => libc::SO_SECURITY_ENCRYPTION_NETWORK.to_string(),
"SO_SECURITY_ENCRYPTION_TRANSPORT" => libc::SO_SECURITY_ENCRYPTION_TRANSPORT.to_string(),
"SO_SECURITY_AUTHENTICATION" => libc::SO_SECURITY_AUTHENTICATION.to_string(),
"SO_SNDTIMEO" => libc::SO_SNDTIMEO.to_string(),
"SO_RCVTIMEO" => libc::SO_RCVTIMEO.to_string(),
"SO_SNDLOWAT" => libc::SO_SNDLOWAT.to_string(),
"SO_RCVLOWAT" => libc::SO_RCVLOWAT.to_string(),
"SO_PEERCRED" => libc::SO_PEERCRED.to_string(),
"SO_PASSCRED" => libc::SO_PASSCRED.to_string(),
"SO_REUSEPORT" => libc::SO_REUSEPORT.to_string(),
"SO_BSDCOMPAT" => libc::SO_BSDCOMPAT.to_string(),
"SO_LINGER" => libc::SO_LINGER.to_string(),
"SO_PRIORITY" => libc::SO_PRIORITY.to_string(),
"SO_NO_CHECK" => libc::SO_NO_CHECK.to_string(),
"SO_OOBINLINE" => libc::SO_OOBINLINE.to_string(),
"SO_KEEPALIVE" => libc::SO_KEEPALIVE.to_string(),
"SO_RCVBUFFORCE" => libc::SO_RCVBUFFORCE.to_string(),
"SO_SNDBUFFORCE" => libc::SO_SNDBUFFORCE.to_string(),
"SO_RCVBUF" => libc::SO_RCVBUF.to_string(),
"SO_SNDBUF" => libc::SO_SNDBUF.to_string(),
"SO_BROADCAST" => libc::SO_BROADCAST.to_string(),
"SO_DONTROUTE" => libc::SO_DONTROUTE.to_string(),
"SO_ERROR" => libc::SO_ERROR.to_string(),
"SO_TYPE" => libc::SO_TYPE.to_string(),
"SO_REUSEADDR" => libc::SO_REUSEADDR.to_string(),
"SOL_SOCKET" => libc::SOL_SOCKET.to_string(),
"ERFKILL" => libc::ERFKILL.to_string(),
"EHWPOISON" => libc::EHWPOISON.to_string(),
"ENOTRECOVERABLE" => libc::ENOTRECOVERABLE.to_string(),
"EOWNERDEAD" => libc::EOWNERDEAD.to_string(),
"EKEYREJECTED" => libc::EKEYREJECTED.to_string(),
"EKEYREVOKED" => libc::EKEYREVOKED.to_string(),
"EKEYEXPIRED" => libc::EKEYEXPIRED.to_string(),
"ENOKEY" => libc::ENOKEY.to_string(),
"ECANCELED" => libc::ECANCELED.to_string(),
"EMEDIUMTYPE" => libc::EMEDIUMTYPE.to_string(),
"ENOMEDIUM" => libc::ENOMEDIUM.to_string(),
"EDQUOT" => libc::EDQUOT.to_string(),
"ESTALE" => libc::ESTALE.to_string(),
"EINPROGRESS" => libc::EINPROGRESS.to_string(),
"EALREADY" => libc::EALREADY.to_string(),
"EHOSTUNREACH" => libc::EHOSTUNREACH.to_string(),
"EHOSTDOWN" => libc::EHOSTDOWN.to_string(),
"ECONNREFUSED" => libc::ECONNREFUSED.to_string(),
"ETIMEDOUT" => libc::ETIMEDOUT.to_string(),
"ETOOMANYREFS" => libc::ETOOMANYREFS.to_string(),
"ESHUTDOWN" => libc::ESHUTDOWN.to_string(),
"ENOTCONN" => libc::ENOTCONN.to_string(),
"EISCONN" => libc::EISCONN.to_string(),
"ENOBUFS" => libc::ENOBUFS.to_string(),
"ECONNRESET" => libc::ECONNRESET.to_string(),
"ECONNABORTED" => libc::ECONNABORTED.to_string(),
"ENETRESET" => libc::ENETRESET.to_string(),
"ENETUNREACH" => libc::ENETUNREACH.to_string(),
"ENETDOWN" => libc::ENETDOWN.to_string(),
"EADDRNOTAVAIL" => libc::EADDRNOTAVAIL.to_string(),
"EADDRINUSE" => libc::EADDRINUSE.to_string(),
"EAFNOSUPPORT" => libc::EAFNOSUPPORT.to_string(),
"EPFNOSUPPORT" => libc::EPFNOSUPPORT.to_string(),
"EOPNOTSUPP" => libc::EOPNOTSUPP.to_string(),
"ESOCKTNOSUPPORT" => libc::ESOCKTNOSUPPORT.to_string(),
"EPROTONOSUPPORT" => libc::EPROTONOSUPPORT.to_string(),
"ENOPROTOOPT" => libc::ENOPROTOOPT.to_string(),
"EPROTOTYPE" => libc::EPROTOTYPE.to_string(),
"EMSGSIZE" => libc::EMSGSIZE.to_string(),
"EDESTADDRREQ" => libc::EDESTADDRREQ.to_string(),
"ENOTSOCK" => libc::ENOTSOCK.to_string(),
"EUSERS" => libc::EUSERS.to_string(),
"ESTRPIPE" => libc::ESTRPIPE.to_string(),
"ERESTART" => libc::ERESTART.to_string(),
"EILSEQ" => libc::EILSEQ.to_string(),
"ELIBEXEC" => libc::ELIBEXEC.to_string(),
"ELIBMAX" => libc::ELIBMAX.to_string(),
"ELIBSCN" => libc::ELIBSCN.to_string(),
"ELIBBAD" => libc::ELIBBAD.to_string(),
"ELIBACC" => libc::ELIBACC.to_string(),
"EREMCHG" => libc::EREMCHG.to_string(),
"EBADMSG" => libc::EBADMSG.to_string(),
"EBADFD" => libc::EBADFD.to_string(),
"ENOTUNIQ" => libc::ENOTUNIQ.to_string(),
"EOVERFLOW" => libc::EOVERFLOW.to_string(),
"EMULTIHOP" => libc::EMULTIHOP.to_string(),
"EBADSLT" => libc::EBADSLT.to_string(),
"EBADRQC" => libc::EBADRQC.to_string(),
"ENOANO" => libc::ENOANO.to_string(),
"EXFULL" => libc::EXFULL.to_string(),
"EBADR" => libc::EBADR.to_string(),
"EBADE" => libc::EBADE.to_string(),
"EL2HLT" => libc::EL2HLT.to_string(),
"ENOCSI" => libc::ENOCSI.to_string(),
"EUNATCH" => libc::EUNATCH.to_string(),
"ELNRNG" => libc::ELNRNG.to_string(),
"EL3RST" => libc::EL3RST.to_string(),
"EL3HLT" => libc::EL3HLT.to_string(),
"EL2NSYNC" => libc::EL2NSYNC.to_string(),
"ECHRNG" => libc::ECHRNG.to_string(),
"EIDRM" => libc::EIDRM.to_string(),
"ENOMSG" => libc::ENOMSG.to_string(),
"ELOOP" => libc::ELOOP.to_string(),
"ENOTEMPTY" => libc::ENOTEMPTY.to_string(),
"ENOSYS" => libc::ENOSYS.to_string(),
"ENOLCK" => libc::ENOLCK.to_string(),
"ENAMETOOLONG" => libc::ENAMETOOLONG.to_string(),
"EDEADLK" => libc::EDEADLK.to_string(),
"MAP_GROWSDOWN" => libc::MAP_GROWSDOWN.to_string(),
"MADV_SOFT_OFFLINE" => libc::MADV_SOFT_OFFLINE.to_string(),
"O_TMPFILE" => libc::O_TMPFILE.to_string(),
"O_PATH" => libc::O_PATH.to_string(),
"O_NOATIME" => libc::O_NOATIME.to_string(),
"O_FSYNC" => libc::O_FSYNC.to_string(),
"O_DSYNC" => libc::O_DSYNC.to_string(),
"O_RSYNC" => libc::O_RSYNC.to_string(),
"O_SYNC" => libc::O_SYNC.to_string(),
"O_NONBLOCK" => libc::O_NONBLOCK.to_string(),
"O_NOCTTY" => libc::O_NOCTTY.to_string(),
"O_EXCL" => libc::O_EXCL.to_string(),
"O_CREAT" => libc::O_CREAT.to_string(),
"O_APPEND" => libc::O_APPEND.to_string(),
"RLIMIT_NPROC" => libc::RLIMIT_NPROC.to_string(),
"RLIMIT_NOFILE" => libc::RLIMIT_NOFILE.to_string(),
"RLIMIT_MEMLOCK" => libc::RLIMIT_MEMLOCK.to_string(),
"RLIMIT_AS" => libc::RLIMIT_AS.to_string(),
"RLIMIT_RSS" => libc::RLIMIT_RSS.to_string(),
"TIOCSRS485" => libc::TIOCSRS485.to_string(),
"TIOCGRS485" => libc::TIOCGRS485.to_string(),
"TIOCSSOFTCAR" => libc::TIOCSSOFTCAR.to_string(),
"TIOCGSOFTCAR" => libc::TIOCGSOFTCAR.to_string(),
"RTLD_NOLOAD" => libc::RTLD_NOLOAD.to_string(),
"RTLD_GLOBAL" => libc::RTLD_GLOBAL.to_string(),
"RTLD_DEEPBIND" => libc::RTLD_DEEPBIND.to_string(),
"VEOF" => libc::VEOF.to_string(),
"POSIX_FADV_NOREUSE" => libc::POSIX_FADV_NOREUSE.to_string(),
"POSIX_FADV_DONTNEED" => libc::POSIX_FADV_DONTNEED.to_string(),
"O_LARGEFILE" => libc::O_LARGEFILE.to_string(),
"__SIZEOF_PTHREAD_RWLOCKATTR_T" => libc::__SIZEOF_PTHREAD_RWLOCKATTR_T.to_string(),
"RLIM_INFINITY" => libc::RLIM_INFINITY.to_string(),
"REG_ERPAREN" => libc::REG_ERPAREN.to_string(),
"REG_ESIZE" => libc::REG_ESIZE.to_string(),
"REG_EEND" => libc::REG_EEND.to_string(),
"REG_STARTEND" => libc::REG_STARTEND.to_string(),
"PTHREAD_MUTEX_ADAPTIVE_NP" => libc::PTHREAD_MUTEX_ADAPTIVE_NP.to_string(),
"PTHREAD_STACK_MIN" => libc::PTHREAD_STACK_MIN.to_string(),
"MAXTC" => libc::MAXTC.to_string(),
"TIME_BAD" => libc::TIME_BAD.to_string(),
"TIME_ERROR" => libc::TIME_ERROR.to_string(),
"TIME_WAIT" => libc::TIME_WAIT.to_string(),
"TIME_OOP" => libc::TIME_OOP.to_string(),
"TIME_DEL" => libc::TIME_DEL.to_string(),
"TIME_INS" => libc::TIME_INS.to_string(),
"TIME_OK" => libc::TIME_OK.to_string(),
"NTP_API" => libc::NTP_API.to_string(),
"STA_RONLY" => libc::STA_RONLY.to_string(),
"STA_CLK" => libc::STA_CLK.to_string(),
"STA_MODE" => libc::STA_MODE.to_string(),
"STA_NANO" => libc::STA_NANO.to_string(),
"STA_CLOCKERR" => libc::STA_CLOCKERR.to_string(),
"STA_PPSERROR" => libc::STA_PPSERROR.to_string(),
"STA_PPSWANDER" => libc::STA_PPSWANDER.to_string(),
"STA_PPSJITTER" => libc::STA_PPSJITTER.to_string(),
"STA_PPSSIGNAL" => libc::STA_PPSSIGNAL.to_string(),
"STA_FREQHOLD" => libc::STA_FREQHOLD.to_string(),
"STA_UNSYNC" => libc::STA_UNSYNC.to_string(),
"STA_DEL" => libc::STA_DEL.to_string(),
"STA_INS" => libc::STA_INS.to_string(),
"STA_FLL" => libc::STA_FLL.to_string(),
"STA_PPSTIME" => libc::STA_PPSTIME.to_string(),
"STA_PPSFREQ" => libc::STA_PPSFREQ.to_string(),
"STA_PLL" => libc::STA_PLL.to_string(),
"MOD_NANO" => libc::MOD_NANO.to_string(),
"MOD_MICRO" => libc::MOD_MICRO.to_string(),
"MOD_TAI" => libc::MOD_TAI.to_string(),
"MOD_CLKA" => libc::MOD_CLKA.to_string(),
"MOD_CLKB" => libc::MOD_CLKB.to_string(),
"MOD_TIMECONST" => libc::MOD_TIMECONST.to_string(),
"MOD_STATUS" => libc::MOD_STATUS.to_string(),
"MOD_ESTERROR" => libc::MOD_ESTERROR.to_string(),
"MOD_MAXERROR" => libc::MOD_MAXERROR.to_string(),
"MOD_FREQUENCY" => libc::MOD_FREQUENCY.to_string(),
"MOD_OFFSET" => libc::MOD_OFFSET.to_string(),
"ADJ_OFFSET_SS_READ" => libc::ADJ_OFFSET_SS_READ.to_string(),
"ADJ_OFFSET_SINGLESHOT" => libc::ADJ_OFFSET_SINGLESHOT.to_string(),
"ADJ_TICK" => libc::ADJ_TICK.to_string(),
"ADJ_NANO" => libc::ADJ_NANO.to_string(),
"ADJ_MICRO" => libc::ADJ_MICRO.to_string(),
"ADJ_SETOFFSET" => libc::ADJ_SETOFFSET.to_string(),
"ADJ_TAI" => libc::ADJ_TAI.to_string(),
"ADJ_TIMECONST" => libc::ADJ_TIMECONST.to_string(),
"ADJ_STATUS" => libc::ADJ_STATUS.to_string(),
"ADJ_ESTERROR" => libc::ADJ_ESTERROR.to_string(),
"ADJ_MAXERROR" => libc::ADJ_MAXERROR.to_string(),
"ADJ_FREQUENCY" => libc::ADJ_FREQUENCY.to_string(),
"ADJ_OFFSET" => libc::ADJ_OFFSET.to_string(),
"AT_EXECFN" => libc::AT_EXECFN.to_string(),
"AT_HWCAP2" => libc::AT_HWCAP2.to_string(),
"AT_RANDOM" => libc::AT_RANDOM.to_string(),
"AT_BASE_PLATFORM" => libc::AT_BASE_PLATFORM.to_string(),
"AT_SECURE" => libc::AT_SECURE.to_string(),
"AT_CLKTCK" => libc::AT_CLKTCK.to_string(),
"AT_HWCAP" => libc::AT_HWCAP.to_string(),
"AT_PLATFORM" => libc::AT_PLATFORM.to_string(),
"AT_EGID" => libc::AT_EGID.to_string(),
"AT_GID" => libc::AT_GID.to_string(),
"AT_EUID" => libc::AT_EUID.to_string(),
"AT_UID" => libc::AT_UID.to_string(),
"AT_NOTELF" => libc::AT_NOTELF.to_string(),
"AT_ENTRY" => libc::AT_ENTRY.to_string(),
"AT_FLAGS" => libc::AT_FLAGS.to_string(),
"AT_BASE" => libc::AT_BASE.to_string(),
"AT_PAGESZ" => libc::AT_PAGESZ.to_string(),
"AT_PHNUM" => libc::AT_PHNUM.to_string(),
"AT_PHENT" => libc::AT_PHENT.to_string(),
"AT_PHDR" => libc::AT_PHDR.to_string(),
"AT_EXECFD" => libc::AT_EXECFD.to_string(),
"AT_IGNORE" => libc::AT_IGNORE.to_string(),
"AT_NULL" => libc::AT_NULL.to_string(),
"STATX_ATTR_AUTOMOUNT" => libc::STATX_ATTR_AUTOMOUNT.to_string(),
"STATX_ATTR_ENCRYPTED" => libc::STATX_ATTR_ENCRYPTED.to_string(),
"STATX_ATTR_NODUMP" => libc::STATX_ATTR_NODUMP.to_string(),
"STATX_ATTR_APPEND" => libc::STATX_ATTR_APPEND.to_string(),
"STATX_ATTR_IMMUTABLE" => libc::STATX_ATTR_IMMUTABLE.to_string(),
"STATX_ATTR_COMPRESSED" => libc::STATX_ATTR_COMPRESSED.to_string(),
"STATX__RESERVED" => libc::STATX__RESERVED.to_string(),
"STATX_ALL" => libc::STATX_ALL.to_string(),
"STATX_BTIME" => libc::STATX_BTIME.to_string(),
"STATX_BASIC_STATS" => libc::STATX_BASIC_STATS.to_string(),
"STATX_BLOCKS" => libc::STATX_BLOCKS.to_string(),
"STATX_SIZE" => libc::STATX_SIZE.to_string(),
"STATX_INO" => libc::STATX_INO.to_string(),
"STATX_CTIME" => libc::STATX_CTIME.to_string(),
"STATX_MTIME" => libc::STATX_MTIME.to_string(),
"STATX_ATIME" => libc::STATX_ATIME.to_string(),
"STATX_GID" => libc::STATX_GID.to_string(),
"STATX_UID" => libc::STATX_UID.to_string(),
"STATX_NLINK" => libc::STATX_NLINK.to_string(),
"STATX_MODE" => libc::STATX_MODE.to_string(),
"STATX_TYPE" => libc::STATX_TYPE.to_string(),
"AT_STATX_DONT_SYNC" => libc::AT_STATX_DONT_SYNC.to_string(),
"AT_STATX_FORCE_SYNC" => libc::AT_STATX_FORCE_SYNC.to_string(),
"AT_STATX_SYNC_AS_STAT" => libc::AT_STATX_SYNC_AS_STAT.to_string(),
"AT_STATX_SYNC_TYPE" => libc::AT_STATX_SYNC_TYPE.to_string(),
"M_ARENA_MAX" => libc::M_ARENA_MAX.to_string(),
"M_ARENA_TEST" => libc::M_ARENA_TEST.to_string(),
"M_PERTURB" => libc::M_PERTURB.to_string(),
"M_CHECK_ACTION" => libc::M_CHECK_ACTION.to_string(),
"M_MMAP_MAX" => libc::M_MMAP_MAX.to_string(),
"M_MMAP_THRESHOLD" => libc::M_MMAP_THRESHOLD.to_string(),
"M_TOP_PAD" => libc::M_TOP_PAD.to_string(),
"M_TRIM_THRESHOLD" => libc::M_TRIM_THRESHOLD.to_string(),
"M_KEEP" => libc::M_KEEP.to_string(),
"M_GRAIN" => libc::M_GRAIN.to_string(),
"M_NLBLKS" => libc::M_NLBLKS.to_string(),
"M_MXFAST" => libc::M_MXFAST.to_string(),
"NFT_NG_RANDOM" => libc::NFT_NG_RANDOM.to_string(),
"NFT_NG_INCREMENTAL" => libc::NFT_NG_INCREMENTAL.to_string(),
"NFT_TRACETYPE_RULE" => libc::NFT_TRACETYPE_RULE.to_string(),
"NFT_TRACETYPE_RETURN" => libc::NFT_TRACETYPE_RETURN.to_string(),
"NFT_TRACETYPE_POLICY" => libc::NFT_TRACETYPE_POLICY.to_string(),
"NFT_TRACETYPE_UNSPEC" => libc::NFT_TRACETYPE_UNSPEC.to_string(),
"NFT_NAT_DNAT" => libc::NFT_NAT_DNAT.to_string(),
"NFT_NAT_SNAT" => libc::NFT_NAT_SNAT.to_string(),
"NFT_REJECT_ICMPX_ADMIN_PROHIBITED" => libc::NFT_REJECT_ICMPX_ADMIN_PROHIBITED.to_string(),
"NFT_REJECT_ICMPX_HOST_UNREACH" => libc::NFT_REJECT_ICMPX_HOST_UNREACH.to_string(),
"NFT_REJECT_ICMPX_PORT_UNREACH" => libc::NFT_REJECT_ICMPX_PORT_UNREACH.to_string(),
"NFT_REJECT_ICMPX_NO_ROUTE" => libc::NFT_REJECT_ICMPX_NO_ROUTE.to_string(),
"NFT_REJECT_ICMPX_UNREACH" => libc::NFT_REJECT_ICMPX_UNREACH.to_string(),
"NFT_REJECT_TCP_RST" => libc::NFT_REJECT_TCP_RST.to_string(),
"NFT_REJECT_ICMP_UNREACH" => libc::NFT_REJECT_ICMP_UNREACH.to_string(),
"NFT_QUOTA_F_INV" => libc::NFT_QUOTA_F_INV.to_string(),
"NFT_QUEUE_FLAG_MASK" => libc::NFT_QUEUE_FLAG_MASK.to_string(),
"NFT_QUEUE_FLAG_CPU_FANOUT" => libc::NFT_QUEUE_FLAG_CPU_FANOUT.to_string(),
"NFT_QUEUE_FLAG_BYPASS" => libc::NFT_QUEUE_FLAG_BYPASS.to_string(),
"NFT_LIMIT_F_INV" => libc::NFT_LIMIT_F_INV.to_string(),
"NFT_LIMIT_PKT_BYTES" => libc::NFT_LIMIT_PKT_BYTES.to_string(),
"NFT_LIMIT_PKTS" => libc::NFT_LIMIT_PKTS.to_string(),
"NFT_CT_BYTES" => libc::NFT_CT_BYTES.to_string(),
"NFT_CT_PKTS" => libc::NFT_CT_PKTS.to_string(),
"NFT_CT_LABELS" => libc::NFT_CT_LABELS.to_string(),
"NFT_CT_PROTO_DST" => libc::NFT_CT_PROTO_DST.to_string(),
"NFT_CT_PROTO_SRC" => libc::NFT_CT_PROTO_SRC.to_string(),
"NFT_CT_PROTOCOL" => libc::NFT_CT_PROTOCOL.to_string(),
"NFT_CT_DST" => libc::NFT_CT_DST.to_string(),
"NFT_CT_SRC" => libc::NFT_CT_SRC.to_string(),
"NFT_CT_L3PROTOCOL" => libc::NFT_CT_L3PROTOCOL.to_string(),
"NFT_CT_HELPER" => libc::NFT_CT_HELPER.to_string(),
"NFT_CT_EXPIRATION" => libc::NFT_CT_EXPIRATION.to_string(),
"NFT_CT_SECMARK" => libc::NFT_CT_SECMARK.to_string(),
"NFT_CT_MARK" => libc::NFT_CT_MARK.to_string(),
"NFT_CT_STATUS" => libc::NFT_CT_STATUS.to_string(),
"NFT_CT_DIRECTION" => libc::NFT_CT_DIRECTION.to_string(),
"NFT_CT_STATE" => libc::NFT_CT_STATE.to_string(),
"NFT_META_PRANDOM" => libc::NFT_META_PRANDOM.to_string(),
"NFT_META_CGROUP" => libc::NFT_META_CGROUP.to_string(),
"NFT_META_OIFGROUP" => libc::NFT_META_OIFGROUP.to_string(),
"NFT_META_IIFGROUP" => libc::NFT_META_IIFGROUP.to_string(),
"NFT_META_CPU" => libc::NFT_META_CPU.to_string(),
"NFT_META_PKTTYPE" => libc::NFT_META_PKTTYPE.to_string(),
"NFT_META_BRI_OIFNAME" => libc::NFT_META_BRI_OIFNAME.to_string(),
"NFT_META_BRI_IIFNAME" => libc::NFT_META_BRI_IIFNAME.to_string(),
"NFT_META_L4PROTO" => libc::NFT_META_L4PROTO.to_string(),
"NFT_META_NFPROTO" => libc::NFT_META_NFPROTO.to_string(),
"NFT_META_SECMARK" => libc::NFT_META_SECMARK.to_string(),
"NFT_META_RTCLASSID" => libc::NFT_META_RTCLASSID.to_string(),
"NFT_META_NFTRACE" => libc::NFT_META_NFTRACE.to_string(),
"NFT_META_SKGID" => libc::NFT_META_SKGID.to_string(),
"NFT_META_SKUID" => libc::NFT_META_SKUID.to_string(),
"NFT_META_OIFTYPE" => libc::NFT_META_OIFTYPE.to_string(),
"NFT_META_IIFTYPE" => libc::NFT_META_IIFTYPE.to_string(),
"NFT_META_OIFNAME" => libc::NFT_META_OIFNAME.to_string(),
"NFT_META_IIFNAME" => libc::NFT_META_IIFNAME.to_string(),
"NFT_META_OIF" => libc::NFT_META_OIF.to_string(),
"NFT_META_IIF" => libc::NFT_META_IIF.to_string(),
"NFT_META_MARK" => libc::NFT_META_MARK.to_string(),
"NFT_META_PRIORITY" => libc::NFT_META_PRIORITY.to_string(),
"NFT_META_PROTOCOL" => libc::NFT_META_PROTOCOL.to_string(),
"NFT_META_LEN" => libc::NFT_META_LEN.to_string(),
"NFT_PAYLOAD_CSUM_INET" => libc::NFT_PAYLOAD_CSUM_INET.to_string(),
"NFT_PAYLOAD_CSUM_NONE" => libc::NFT_PAYLOAD_CSUM_NONE.to_string(),
"NFT_PAYLOAD_TRANSPORT_HEADER" => libc::NFT_PAYLOAD_TRANSPORT_HEADER.to_string(),
"NFT_PAYLOAD_NETWORK_HEADER" => libc::NFT_PAYLOAD_NETWORK_HEADER.to_string(),
"NFT_PAYLOAD_LL_HEADER" => libc::NFT_PAYLOAD_LL_HEADER.to_string(),
"NFT_DYNSET_F_INV" => libc::NFT_DYNSET_F_INV.to_string(),
"NFT_DYNSET_OP_UPDATE" => libc::NFT_DYNSET_OP_UPDATE.to_string(),
"NFT_DYNSET_OP_ADD" => libc::NFT_DYNSET_OP_ADD.to_string(),
"NFT_LOOKUP_F_INV" => libc::NFT_LOOKUP_F_INV.to_string(),
"NFT_RANGE_NEQ" => libc::NFT_RANGE_NEQ.to_string(),
"NFT_RANGE_EQ" => libc::NFT_RANGE_EQ.to_string(),
"NFT_CMP_GTE" => libc::NFT_CMP_GTE.to_string(),
"NFT_CMP_GT" => libc::NFT_CMP_GT.to_string(),
"NFT_CMP_LTE" => libc::NFT_CMP_LTE.to_string(),
"NFT_CMP_LT" => libc::NFT_CMP_LT.to_string(),
"NFT_CMP_NEQ" => libc::NFT_CMP_NEQ.to_string(),
"NFT_CMP_EQ" => libc::NFT_CMP_EQ.to_string(),
"NFT_BYTEORDER_HTON" => libc::NFT_BYTEORDER_HTON.to_string(),
"NFT_BYTEORDER_NTOH" => libc::NFT_BYTEORDER_NTOH.to_string(),
"NFT_DATA_VALUE_MAXLEN" => libc::NFT_DATA_VALUE_MAXLEN.to_string(),
"NFT_DATA_RESERVED_MASK" => libc::NFT_DATA_RESERVED_MASK.to_string(),
"NFT_DATA_VERDICT" => libc::NFT_DATA_VERDICT.to_string(),
"NFT_DATA_VALUE" => libc::NFT_DATA_VALUE.to_string(),
"NFT_SET_ELEM_INTERVAL_END" => libc::NFT_SET_ELEM_INTERVAL_END.to_string(),
"NFT_SET_POL_MEMORY" => libc::NFT_SET_POL_MEMORY.to_string(),
"NFT_SET_POL_PERFORMANCE" => libc::NFT_SET_POL_PERFORMANCE.to_string(),
"NFT_SET_EVAL" => libc::NFT_SET_EVAL.to_string(),
"NFT_SET_TIMEOUT" => libc::NFT_SET_TIMEOUT.to_string(),
"NFT_SET_MAP" => libc::NFT_SET_MAP.to_string(),
"NFT_SET_INTERVAL" => libc::NFT_SET_INTERVAL.to_string(),
"NFT_SET_CONSTANT" => libc::NFT_SET_CONSTANT.to_string(),
"NFT_SET_ANONYMOUS" => libc::NFT_SET_ANONYMOUS.to_string(),
"NFT_MSG_MAX" => libc::NFT_MSG_MAX.to_string(),
"NFT_MSG_GETOBJ_RESET" => libc::NFT_MSG_GETOBJ_RESET.to_string(),
"NFT_MSG_DELOBJ" => libc::NFT_MSG_DELOBJ.to_string(),
"NFT_MSG_GETOBJ" => libc::NFT_MSG_GETOBJ.to_string(),
"NFT_MSG_NEWOBJ" => libc::NFT_MSG_NEWOBJ.to_string(),
"NFT_MSG_TRACE" => libc::NFT_MSG_TRACE.to_string(),
"NFT_MSG_GETGEN" => libc::NFT_MSG_GETGEN.to_string(),
"NFT_MSG_NEWGEN" => libc::NFT_MSG_NEWGEN.to_string(),
"NFT_MSG_DELSETELEM" => libc::NFT_MSG_DELSETELEM.to_string(),
"NFT_MSG_GETSETELEM" => libc::NFT_MSG_GETSETELEM.to_string(),
"NFT_MSG_NEWSETELEM" => libc::NFT_MSG_NEWSETELEM.to_string(),
"NFT_MSG_DELSET" => libc::NFT_MSG_DELSET.to_string(),
"NFT_MSG_GETSET" => libc::NFT_MSG_GETSET.to_string(),
"NFT_MSG_NEWSET" => libc::NFT_MSG_NEWSET.to_string(),
"NFT_MSG_DELRULE" => libc::NFT_MSG_DELRULE.to_string(),
"NFT_MSG_GETRULE" => libc::NFT_MSG_GETRULE.to_string(),
"NFT_MSG_NEWRULE" => libc::NFT_MSG_NEWRULE.to_string(),
"NFT_MSG_DELCHAIN" => libc::NFT_MSG_DELCHAIN.to_string(),
"NFT_MSG_GETCHAIN" => libc::NFT_MSG_GETCHAIN.to_string(),
"NFT_MSG_NEWCHAIN" => libc::NFT_MSG_NEWCHAIN.to_string(),
"NFT_MSG_DELTABLE" => libc::NFT_MSG_DELTABLE.to_string(),
"NFT_MSG_GETTABLE" => libc::NFT_MSG_GETTABLE.to_string(),
"NFT_MSG_NEWTABLE" => libc::NFT_MSG_NEWTABLE.to_string(),
"NFT_RETURN" => libc::NFT_RETURN.to_string(),
"NFT_GOTO" => libc::NFT_GOTO.to_string(),
"NFT_JUMP" => libc::NFT_JUMP.to_string(),
"NFT_BREAK" => libc::NFT_BREAK.to_string(),
"NFT_CONTINUE" => libc::NFT_CONTINUE.to_string(),
"NFT_REG32_SIZE" => libc::NFT_REG32_SIZE.to_string(),
"NFT_REG_SIZE" => libc::NFT_REG_SIZE.to_string(),
"NFT_REG32_15" => libc::NFT_REG32_15.to_string(),
"NFT_REG32_14" => libc::NFT_REG32_14.to_string(),
"NFT_REG32_13" => libc::NFT_REG32_13.to_string(),
"NFT_REG32_12" => libc::NFT_REG32_12.to_string(),
"NFT_REG32_11" => libc::NFT_REG32_11.to_string(),
"NFT_REG32_10" => libc::NFT_REG32_10.to_string(),
"NFT_REG32_09" => libc::NFT_REG32_09.to_string(),
"NFT_REG32_08" => libc::NFT_REG32_08.to_string(),
"NFT_REG32_07" => libc::NFT_REG32_07.to_string(),
"NFT_REG32_06" => libc::NFT_REG32_06.to_string(),
"NFT_REG32_05" => libc::NFT_REG32_05.to_string(),
"NFT_REG32_04" => libc::NFT_REG32_04.to_string(),
"NFT_REG32_03" => libc::NFT_REG32_03.to_string(),
"NFT_REG32_02" => libc::NFT_REG32_02.to_string(),
"NFT_REG32_01" => libc::NFT_REG32_01.to_string(),
"NFT_REG32_00" => libc::NFT_REG32_00.to_string(),
"__NFT_REG_MAX" => libc::__NFT_REG_MAX.to_string(),
"NFT_REG_4" => libc::NFT_REG_4.to_string(),
"NFT_REG_3" => libc::NFT_REG_3.to_string(),
"NFT_REG_2" => libc::NFT_REG_2.to_string(),
"NFT_REG_1" => libc::NFT_REG_1.to_string(),
"NFT_REG_VERDICT" => libc::NFT_REG_VERDICT.to_string(),
"NFT_USERDATA_MAXLEN" => libc::NFT_USERDATA_MAXLEN.to_string(),
"NFT_OBJ_MAXNAMELEN" => libc::NFT_OBJ_MAXNAMELEN.to_string(),
"NFT_SET_MAXNAMELEN" => libc::NFT_SET_MAXNAMELEN.to_string(),
"NFT_CHAIN_MAXNAMELEN" => libc::NFT_CHAIN_MAXNAMELEN.to_string(),
"NFT_TABLE_MAXNAMELEN" => libc::NFT_TABLE_MAXNAMELEN.to_string(),
"KEYCTL_CAPS1_NS_KEY_TAG" => libc::KEYCTL_CAPS1_NS_KEY_TAG.to_string(),
"KEYCTL_CAPS1_NS_KEYRING_NAME" => libc::KEYCTL_CAPS1_NS_KEYRING_NAME.to_string(),
"KEYCTL_CAPS0_MOVE" => libc::KEYCTL_CAPS0_MOVE.to_string(),
"KEYCTL_CAPS0_RESTRICT_KEYRING" => libc::KEYCTL_CAPS0_RESTRICT_KEYRING.to_string(),
"KEYCTL_CAPS0_INVALIDATE" => libc::KEYCTL_CAPS0_INVALIDATE.to_string(),
"KEYCTL_CAPS0_BIG_KEY" => libc::KEYCTL_CAPS0_BIG_KEY.to_string(),
"KEYCTL_CAPS0_PUBLIC_KEY" => libc::KEYCTL_CAPS0_PUBLIC_KEY.to_string(),
"KEYCTL_CAPS0_DIFFIE_HELLMAN" => libc::KEYCTL_CAPS0_DIFFIE_HELLMAN.to_string(),
"KEYCTL_CAPS0_PERSISTENT_KEYRINGS" => libc::KEYCTL_CAPS0_PERSISTENT_KEYRINGS.to_string(),
"KEYCTL_CAPS0_CAPABILITIES" => libc::KEYCTL_CAPS0_CAPABILITIES.to_string(),
"KEYCTL_CAPABILITIES" => libc::KEYCTL_CAPABILITIES.to_string(),
"KEYCTL_MOVE" => libc::KEYCTL_MOVE.to_string(),
"KEYCTL_SUPPORTS_VERIFY" => libc::KEYCTL_SUPPORTS_VERIFY.to_string(),
"KEYCTL_SUPPORTS_SIGN" => libc::KEYCTL_SUPPORTS_SIGN.to_string(),
"KEYCTL_SUPPORTS_DECRYPT" => libc::KEYCTL_SUPPORTS_DECRYPT.to_string(),
"KEYCTL_SUPPORTS_ENCRYPT" => libc::KEYCTL_SUPPORTS_ENCRYPT.to_string(),
"KEYCTL_RESTRICT_KEYRING" => libc::KEYCTL_RESTRICT_KEYRING.to_string(),
"KEYCTL_PKEY_VERIFY" => libc::KEYCTL_PKEY_VERIFY.to_string(),
"KEYCTL_PKEY_SIGN" => libc::KEYCTL_PKEY_SIGN.to_string(),
"KEYCTL_PKEY_DECRYPT" => libc::KEYCTL_PKEY_DECRYPT.to_string(),
"KEYCTL_PKEY_ENCRYPT" => libc::KEYCTL_PKEY_ENCRYPT.to_string(),
"KEYCTL_PKEY_QUERY" => libc::KEYCTL_PKEY_QUERY.to_string(),
"KEYCTL_DH_COMPUTE" => libc::KEYCTL_DH_COMPUTE.to_string(),
"NFPROTO_NETDEV" => libc::NFPROTO_NETDEV.to_string(),
"NFPROTO_INET" => libc::NFPROTO_INET.to_string(),
"NF_NETDEV_NUMHOOKS" => libc::NF_NETDEV_NUMHOOKS.to_string(),
"NF_NETDEV_INGRESS" => libc::NF_NETDEV_INGRESS.to_string(),
"TIOCM_RI" => libc::TIOCM_RI.to_string(),
"TIOCM_CD" => libc::TIOCM_CD.to_string(),
"TIOCM_RTS" => libc::TIOCM_RTS.to_string(),
"TIOCM_DTR" => libc::TIOCM_DTR.to_string(),
"TIOCM_LE" => libc::TIOCM_LE.to_string(),
"GENL_ID_PMCRAID" => libc::GENL_ID_PMCRAID.to_string(),
"GENL_ID_VFS_DQUOT" => libc::GENL_ID_VFS_DQUOT.to_string(),
"GENL_UNS_ADMIN_PERM" => libc::GENL_UNS_ADMIN_PERM.to_string(),
"MAX_LINKS" => libc::MAX_LINKS.to_string(),
"IFA_F_STABLE_PRIVACY" => libc::IFA_F_STABLE_PRIVACY.to_string(),
"IFA_F_MCAUTOJOIN" => libc::IFA_F_MCAUTOJOIN.to_string(),
"IFA_F_NOPREFIXROUTE" => libc::IFA_F_NOPREFIXROUTE.to_string(),
"IFA_F_MANAGETEMPADDR" => libc::IFA_F_MANAGETEMPADDR.to_string(),
"IFA_FLAGS" => libc::IFA_FLAGS.to_string(),
"NDA_SRC_VNI" => libc::NDA_SRC_VNI.to_string(),
"NDA_LINK_NETNSID" => libc::NDA_LINK_NETNSID.to_string(),
"NDA_MASTER" => libc::NDA_MASTER.to_string(),
"NTF_OFFLOADED" => libc::NTF_OFFLOADED.to_string(),
"NTF_EXT_LEARNED" => libc::NTF_EXT_LEARNED.to_string(),
"RTA_TTL_PROPAGATE" => libc::RTA_TTL_PROPAGATE.to_string(),
"RTA_UID" => libc::RTA_UID.to_string(),
"RTA_PAD" => libc::RTA_PAD.to_string(),
"RTA_EXPIRES" => libc::RTA_EXPIRES.to_string(),
"RTA_ENCAP" => libc::RTA_ENCAP.to_string(),
"RTA_ENCAP_TYPE" => libc::RTA_ENCAP_TYPE.to_string(),
"RTA_PREF" => libc::RTA_PREF.to_string(),
"RTA_NEWDST" => libc::RTA_NEWDST.to_string(),
"RTA_VIA" => libc::RTA_VIA.to_string(),
"RTM_F_FIB_MATCH" => libc::RTM_F_FIB_MATCH.to_string(),
"RTM_F_LOOKUP_TABLE" => libc::RTM_F_LOOKUP_TABLE.to_string(),
"RTM_NEWCACHEREPORT" => libc::RTM_NEWCACHEREPORT.to_string(),
"RTM_GETSTATS" => libc::RTM_GETSTATS.to_string(),
"RTM_NEWSTATS" => libc::RTM_NEWSTATS.to_string(),
"RTM_DELNETCONF" => libc::RTM_DELNETCONF.to_string(),
"TCA_HW_OFFLOAD" => libc::TCA_HW_OFFLOAD.to_string(),
"TCA_CHAIN" => libc::TCA_CHAIN.to_string(),
"TCA_DUMP_INVISIBLE" => libc::TCA_DUMP_INVISIBLE.to_string(),
"TCA_PAD" => libc::TCA_PAD.to_string(),
"SEEK_HOLE" => libc::SEEK_HOLE.to_string(),
"SEEK_DATA" => libc::SEEK_DATA.to_string(),
"EPOLLWAKEUP" => libc::EPOLLWAKEUP.to_string(),
"PTRACE_PEEKSIGINFO" => libc::PTRACE_PEEKSIGINFO.to_string(),
"PTRACE_LISTEN" => libc::PTRACE_LISTEN.to_string(),
"PTRACE_INTERRUPT" => libc::PTRACE_INTERRUPT.to_string(),
"PTRACE_SEIZE" => libc::PTRACE_SEIZE.to_string(),
"PTRACE_SETREGSET" => libc::PTRACE_SETREGSET.to_string(),
"PTRACE_GETREGSET" => libc::PTRACE_GETREGSET.to_string(),
"PTRACE_SETSIGINFO" => libc::PTRACE_SETSIGINFO.to_string(),
"PTRACE_GETSIGINFO" => libc::PTRACE_GETSIGINFO.to_string(),
"PTRACE_GETEVENTMSG" => libc::PTRACE_GETEVENTMSG.to_string(),
"PTRACE_SETOPTIONS" => libc::PTRACE_SETOPTIONS.to_string(),
"PTRACE_SYSCALL" => libc::PTRACE_SYSCALL.to_string(),
"PTRACE_ATTACH" => libc::PTRACE_ATTACH.to_string(),
"PTRACE_SINGLESTEP" => libc::PTRACE_SINGLESTEP.to_string(),
"PTRACE_KILL" => libc::PTRACE_KILL.to_string(),
"PTRACE_CONT" => libc::PTRACE_CONT.to_string(),
"PTRACE_POKEUSER" => libc::PTRACE_POKEUSER.to_string(),
"PTRACE_POKEDATA" => libc::PTRACE_POKEDATA.to_string(),
"PTRACE_POKETEXT" => libc::PTRACE_POKETEXT.to_string(),
"PTRACE_PEEKUSER" => libc::PTRACE_PEEKUSER.to_string(),
"PTRACE_PEEKDATA" => libc::PTRACE_PEEKDATA.to_string(),
"PTRACE_PEEKTEXT" => libc::PTRACE_PEEKTEXT.to_string(),
"PTRACE_TRACEME" => libc::PTRACE_TRACEME.to_string(),
"CPU_SETSIZE" => libc::CPU_SETSIZE.to_string(),
"CGROUP2_SUPER_MAGIC" => libc::CGROUP2_SUPER_MAGIC.to_string(),
"CGROUP_SUPER_MAGIC" => libc::CGROUP_SUPER_MAGIC.to_string(),
"USBDEVICE_SUPER_MAGIC" => libc::USBDEVICE_SUPER_MAGIC.to_string(),
"TMPFS_MAGIC" => libc::TMPFS_MAGIC.to_string(),
"SMB_SUPER_MAGIC" => libc::SMB_SUPER_MAGIC.to_string(),
"REISERFS_SUPER_MAGIC" => libc::REISERFS_SUPER_MAGIC.to_string(),
"QNX4_SUPER_MAGIC" => libc::QNX4_SUPER_MAGIC.to_string(),
"PROC_SUPER_MAGIC" => libc::PROC_SUPER_MAGIC.to_string(),
"OPENPROM_SUPER_MAGIC" => libc::OPENPROM_SUPER_MAGIC.to_string(),
"NFS_SUPER_MAGIC" => libc::NFS_SUPER_MAGIC.to_string(),
"NCP_SUPER_MAGIC" => libc::NCP_SUPER_MAGIC.to_string(),
"MSDOS_SUPER_MAGIC" => libc::MSDOS_SUPER_MAGIC.to_string(),
"MINIX2_SUPER_MAGIC2" => libc::MINIX2_SUPER_MAGIC2.to_string(),
"MINIX2_SUPER_MAGIC" => libc::MINIX2_SUPER_MAGIC.to_string(),
"MINIX_SUPER_MAGIC2" => libc::MINIX_SUPER_MAGIC2.to_string(),
"MINIX_SUPER_MAGIC" => libc::MINIX_SUPER_MAGIC.to_string(),
"JFFS2_SUPER_MAGIC" => libc::JFFS2_SUPER_MAGIC.to_string(),
"ISOFS_SUPER_MAGIC" => libc::ISOFS_SUPER_MAGIC.to_string(),
"HUGETLBFS_MAGIC" => libc::HUGETLBFS_MAGIC.to_string(),
"HPFS_SUPER_MAGIC" => libc::HPFS_SUPER_MAGIC.to_string(),
"EXT4_SUPER_MAGIC" => libc::EXT4_SUPER_MAGIC.to_string(),
"EXT3_SUPER_MAGIC" => libc::EXT3_SUPER_MAGIC.to_string(),
"EXT2_SUPER_MAGIC" => libc::EXT2_SUPER_MAGIC.to_string(),
"EFS_SUPER_MAGIC" => libc::EFS_SUPER_MAGIC.to_string(),
"CRAMFS_MAGIC" => libc::CRAMFS_MAGIC.to_string(),
"CODA_SUPER_MAGIC" => libc::CODA_SUPER_MAGIC.to_string(),
"AFFS_SUPER_MAGIC" => libc::AFFS_SUPER_MAGIC.to_string(),
"ADFS_SUPER_MAGIC" => libc::ADFS_SUPER_MAGIC.to_string(),
"NI_MAXHOST" => libc::NI_MAXHOST.to_string(),
"ST_RELATIME" => libc::ST_RELATIME.to_string(),
"O_ACCMODE" => libc::O_ACCMODE.to_string(),
"_SC_LEVEL4_CACHE_LINESIZE" => libc::_SC_LEVEL4_CACHE_LINESIZE.to_string(),
"_SC_LEVEL4_CACHE_ASSOC" => libc::_SC_LEVEL4_CACHE_ASSOC.to_string(),
"_SC_LEVEL4_CACHE_SIZE" => libc::_SC_LEVEL4_CACHE_SIZE.to_string(),
"_SC_LEVEL3_CACHE_LINESIZE" => libc::_SC_LEVEL3_CACHE_LINESIZE.to_string(),
"_SC_LEVEL3_CACHE_ASSOC" => libc::_SC_LEVEL3_CACHE_ASSOC.to_string(),
"_SC_LEVEL3_CACHE_SIZE" => libc::_SC_LEVEL3_CACHE_SIZE.to_string(),
"_SC_LEVEL2_CACHE_LINESIZE" => libc::_SC_LEVEL2_CACHE_LINESIZE.to_string(),
"_SC_LEVEL2_CACHE_ASSOC" => libc::_SC_LEVEL2_CACHE_ASSOC.to_string(),
"_SC_LEVEL2_CACHE_SIZE" => libc::_SC_LEVEL2_CACHE_SIZE.to_string(),
"_SC_LEVEL1_DCACHE_LINESIZE" => libc::_SC_LEVEL1_DCACHE_LINESIZE.to_string(),
"_SC_LEVEL1_DCACHE_ASSOC" => libc::_SC_LEVEL1_DCACHE_ASSOC.to_string(),
"_SC_LEVEL1_DCACHE_SIZE" => libc::_SC_LEVEL1_DCACHE_SIZE.to_string(),
"_SC_LEVEL1_ICACHE_LINESIZE" => libc::_SC_LEVEL1_ICACHE_LINESIZE.to_string(),
"_SC_LEVEL1_ICACHE_ASSOC" => libc::_SC_LEVEL1_ICACHE_ASSOC.to_string(),
"_SC_LEVEL1_ICACHE_SIZE" => libc::_SC_LEVEL1_ICACHE_SIZE.to_string(),
"_SC_USER_GROUPS_R" => libc::_SC_USER_GROUPS_R.to_string(),
"_SC_USER_GROUPS" => libc::_SC_USER_GROUPS.to_string(),
"_SC_SYSTEM_DATABASE_R" => libc::_SC_SYSTEM_DATABASE_R.to_string(),
"_SC_SYSTEM_DATABASE" => libc::_SC_SYSTEM_DATABASE.to_string(),
"_SC_SIGNALS" => libc::_SC_SIGNALS.to_string(),
"_SC_REGEX_VERSION" => libc::_SC_REGEX_VERSION.to_string(),
"_SC_NETWORKING" => libc::_SC_NETWORKING.to_string(),
"_SC_SINGLE_PROCESS" => libc::_SC_SINGLE_PROCESS.to_string(),
"_SC_MULTI_PROCESS" => libc::_SC_MULTI_PROCESS.to_string(),
"_SC_FILE_SYSTEM" => libc::_SC_FILE_SYSTEM.to_string(),
"_SC_FILE_LOCKING" => libc::_SC_FILE_LOCKING.to_string(),
"_SC_FILE_ATTRIBUTES" => libc::_SC_FILE_ATTRIBUTES.to_string(),
"_SC_PIPE" => libc::_SC_PIPE.to_string(),
"_SC_FIFO" => libc::_SC_FIFO.to_string(),
"_SC_FD_MGMT" => libc::_SC_FD_MGMT.to_string(),
"_SC_DEVICE_SPECIFIC_R" => libc::_SC_DEVICE_SPECIFIC_R.to_string(),
"_SC_DEVICE_SPECIFIC" => libc::_SC_DEVICE_SPECIFIC.to_string(),
"_SC_DEVICE_IO" => libc::_SC_DEVICE_IO.to_string(),
"_SC_C_LANG_SUPPORT_R" => libc::_SC_C_LANG_SUPPORT_R.to_string(),
"_SC_C_LANG_SUPPORT" => libc::_SC_C_LANG_SUPPORT.to_string(),
"_SC_BASE" => libc::_SC_BASE.to_string(),
"_SC_NL_TEXTMAX" => libc::_SC_NL_TEXTMAX.to_string(),
"_SC_NL_SETMAX" => libc::_SC_NL_SETMAX.to_string(),
"_SC_NL_NMAX" => libc::_SC_NL_NMAX.to_string(),
"_SC_NL_MSGMAX" => libc::_SC_NL_MSGMAX.to_string(),
"_SC_NL_LANGMAX" => libc::_SC_NL_LANGMAX.to_string(),
"_SC_NL_ARGMAX" => libc::_SC_NL_ARGMAX.to_string(),
"_SC_USHRT_MAX" => libc::_SC_USHRT_MAX.to_string(),
"_SC_ULONG_MAX" => libc::_SC_ULONG_MAX.to_string(),
"_SC_UINT_MAX" => libc::_SC_UINT_MAX.to_string(),
"_SC_UCHAR_MAX" => libc::_SC_UCHAR_MAX.to_string(),
"_SC_SHRT_MIN" => libc::_SC_SHRT_MIN.to_string(),
"_SC_SHRT_MAX" => libc::_SC_SHRT_MAX.to_string(),
"_SC_SCHAR_MIN" => libc::_SC_SCHAR_MIN.to_string(),
"_SC_SCHAR_MAX" => libc::_SC_SCHAR_MAX.to_string(),
"_SC_SSIZE_MAX" => libc::_SC_SSIZE_MAX.to_string(),
"_SC_MB_LEN_MAX" => libc::_SC_MB_LEN_MAX.to_string(),
"_SC_WORD_BIT" => libc::_SC_WORD_BIT.to_string(),
"_SC_LONG_BIT" => libc::_SC_LONG_BIT.to_string(),
"_SC_INT_MIN" => libc::_SC_INT_MIN.to_string(),
"_SC_INT_MAX" => libc::_SC_INT_MAX.to_string(),
"_SC_CHAR_MIN" => libc::_SC_CHAR_MIN.to_string(),
"_SC_CHAR_MAX" => libc::_SC_CHAR_MAX.to_string(),
"_SC_CHAR_BIT" => libc::_SC_CHAR_BIT.to_string(),
"_SC_2_C_VERSION" => libc::_SC_2_C_VERSION.to_string(),
"_SC_T_IOV_MAX" => libc::_SC_T_IOV_MAX.to_string(),
"_SC_PII_OSI_M" => libc::_SC_PII_OSI_M.to_string(),
"_SC_PII_OSI_CLTS" => libc::_SC_PII_OSI_CLTS.to_string(),
"_SC_PII_OSI_COTS" => libc::_SC_PII_OSI_COTS.to_string(),
"_SC_PII_INTERNET_DGRAM" => libc::_SC_PII_INTERNET_DGRAM.to_string(),
"_SC_PII_INTERNET_STREAM" => libc::_SC_PII_INTERNET_STREAM.to_string(),
"_SC_SELECT" => libc::_SC_SELECT.to_string(),
"_SC_POLL" => libc::_SC_POLL.to_string(),
"_SC_PII_OSI" => libc::_SC_PII_OSI.to_string(),
"_SC_PII_INTERNET" => libc::_SC_PII_INTERNET.to_string(),
"_SC_PII_SOCKET" => libc::_SC_PII_SOCKET.to_string(),
"_SC_PII_XTI" => libc::_SC_PII_XTI.to_string(),
"_SC_PII" => libc::_SC_PII.to_string(),
"_SC_CHARCLASS_NAME_MAX" => libc::_SC_CHARCLASS_NAME_MAX.to_string(),
"_SC_EQUIV_CLASS_MAX" => libc::_SC_EQUIV_CLASS_MAX.to_string(),
"POSIX_MADV_DONTNEED" => libc::POSIX_MADV_DONTNEED.to_string(),
"FOPEN_MAX" => libc::FOPEN_MAX.to_string(),
"TMP_MAX" => libc::TMP_MAX.to_string(),
"BUFSIZ" => libc::BUFSIZ.to_string(),
"SIGEV_THREAD_ID" => libc::SIGEV_THREAD_ID.to_string(),
"DCCP_SERVICE_LIST_MAX_LEN" => libc::DCCP_SERVICE_LIST_MAX_LEN.to_string(),
"DCCP_SOCKOPT_CCID_TX_INFO" => libc::DCCP_SOCKOPT_CCID_TX_INFO.to_string(),
"DCCP_SOCKOPT_CCID_RX_INFO" => libc::DCCP_SOCKOPT_CCID_RX_INFO.to_string(),
"DCCP_SOCKOPT_QPOLICY_TXQLEN" => libc::DCCP_SOCKOPT_QPOLICY_TXQLEN.to_string(),
"DCCP_SOCKOPT_QPOLICY_ID" => libc::DCCP_SOCKOPT_QPOLICY_ID.to_string(),
"DCCP_SOCKOPT_RX_CCID" => libc::DCCP_SOCKOPT_RX_CCID.to_string(),
"DCCP_SOCKOPT_TX_CCID" => libc::DCCP_SOCKOPT_TX_CCID.to_string(),
"DCCP_SOCKOPT_CCID" => libc::DCCP_SOCKOPT_CCID.to_string(),
"DCCP_SOCKOPT_AVAILABLE_CCIDS" => libc::DCCP_SOCKOPT_AVAILABLE_CCIDS.to_string(),
"DCCP_SOCKOPT_RECV_CSCOV" => libc::DCCP_SOCKOPT_RECV_CSCOV.to_string(),
"DCCP_SOCKOPT_SEND_CSCOV" => libc::DCCP_SOCKOPT_SEND_CSCOV.to_string(),
"DCCP_SOCKOPT_SERVER_TIMEWAIT" => libc::DCCP_SOCKOPT_SERVER_TIMEWAIT.to_string(),
"DCCP_SOCKOPT_GET_CUR_MPS" => libc::DCCP_SOCKOPT_GET_CUR_MPS.to_string(),
"DCCP_SOCKOPT_CHANGE_R" => libc::DCCP_SOCKOPT_CHANGE_R.to_string(),
"DCCP_SOCKOPT_CHANGE_L" => libc::DCCP_SOCKOPT_CHANGE_L.to_string(),
"DCCP_SOCKOPT_SERVICE" => libc::DCCP_SOCKOPT_SERVICE.to_string(),
"DCCP_SOCKOPT_PACKET_SIZE" => libc::DCCP_SOCKOPT_PACKET_SIZE.to_string(),
"TCP_FASTOPEN_CONNECT" => libc::TCP_FASTOPEN_CONNECT.to_string(),
"TCP_TIMESTAMP" => libc::TCP_TIMESTAMP.to_string(),
"TCP_FASTOPEN" => libc::TCP_FASTOPEN.to_string(),
"TCP_REPAIR_OPTIONS" => libc::TCP_REPAIR_OPTIONS.to_string(),
"TCP_QUEUE_SEQ" => libc::TCP_QUEUE_SEQ.to_string(),
"TCP_REPAIR_QUEUE" => libc::TCP_REPAIR_QUEUE.to_string(),
"TCP_REPAIR" => libc::TCP_REPAIR.to_string(),
"TCP_USER_TIMEOUT" => libc::TCP_USER_TIMEOUT.to_string(),
"TCP_THIN_DUPACK" => libc::TCP_THIN_DUPACK.to_string(),
"TCP_THIN_LINEAR_TIMEOUTS" => libc::TCP_THIN_LINEAR_TIMEOUTS.to_string(),
"TCP_COOKIE_TRANSACTIONS" => libc::TCP_COOKIE_TRANSACTIONS.to_string(),
"SOCK_PACKET" => libc::SOCK_PACKET.to_string(),
"SOCK_DCCP" => libc::SOCK_DCCP.to_string(),
"SOCK_SEQPACKET" => libc::SOCK_SEQPACKET.to_string(),
"ENOTSUP" => libc::ENOTSUP.to_string(),
"LC_ALL_MASK" => libc::LC_ALL_MASK.to_string(),
"LC_IDENTIFICATION_MASK" => libc::LC_IDENTIFICATION_MASK.to_string(),
"LC_MEASUREMENT_MASK" => libc::LC_MEASUREMENT_MASK.to_string(),
"LC_TELEPHONE_MASK" => libc::LC_TELEPHONE_MASK.to_string(),
"LC_ADDRESS_MASK" => libc::LC_ADDRESS_MASK.to_string(),
"LC_NAME_MASK" => libc::LC_NAME_MASK.to_string(),
"LC_PAPER_MASK" => libc::LC_PAPER_MASK.to_string(),
"LC_IDENTIFICATION" => libc::LC_IDENTIFICATION.to_string(),
"LC_MEASUREMENT" => libc::LC_MEASUREMENT.to_string(),
"LC_TELEPHONE" => libc::LC_TELEPHONE.to_string(),
"LC_ADDRESS" => libc::LC_ADDRESS.to_string(),
"LC_NAME" => libc::LC_NAME.to_string(),
"LC_PAPER" => libc::LC_PAPER.to_string(),
"MSG_TRYHARD" => libc::MSG_TRYHARD.to_string(),
"SOL_XDP" => libc::SOL_XDP.to_string(),
"SOL_NFC" => libc::SOL_NFC.to_string(),
"SOL_CAIF" => libc::SOL_CAIF.to_string(),
"SOL_IUCV" => libc::SOL_IUCV.to_string(),
"SOL_RDS" => libc::SOL_RDS.to_string(),
"SOL_PNPIPE" => libc::SOL_PNPIPE.to_string(),
"SOL_PPPOL2TP" => libc::SOL_PPPOL2TP.to_string(),
"SOL_RXRPC" => libc::SOL_RXRPC.to_string(),
"SOCK_NONBLOCK" => libc::SOCK_NONBLOCK.to_string(),
"RTLD_DI_TLS_DATA" => libc::RTLD_DI_TLS_DATA.to_string(),
"RTLD_DI_TLS_MODID" => libc::RTLD_DI_TLS_MODID.to_string(),
"RTLD_DI_PROFILEOUT" => libc::RTLD_DI_PROFILEOUT.to_string(),
"RTLD_DI_PROFILENAME" => libc::RTLD_DI_PROFILENAME.to_string(),
"RTLD_DI_ORIGIN" => libc::RTLD_DI_ORIGIN.to_string(),
"RTLD_DI_SERINFOSIZE" => libc::RTLD_DI_SERINFOSIZE.to_string(),
"RTLD_DI_SERINFO" => libc::RTLD_DI_SERINFO.to_string(),
"RTLD_DI_CONFIGADDR" => libc::RTLD_DI_CONFIGADDR.to_string(),
"RTLD_DI_LINKMAP" => libc::RTLD_DI_LINKMAP.to_string(),
"RTLD_DI_LMID" => libc::RTLD_DI_LMID.to_string(),
"LM_ID_NEWLM" => libc::LM_ID_NEWLM.to_string(),
"LM_ID_BASE" => libc::LM_ID_BASE.to_string(),
"ACCOUNTING" => libc::ACCOUNTING.to_string(),
"DEAD_PROCESS" => libc::DEAD_PROCESS.to_string(),
"USER_PROCESS" => libc::USER_PROCESS.to_string(),
"LOGIN_PROCESS" => libc::LOGIN_PROCESS.to_string(),
"INIT_PROCESS" => libc::INIT_PROCESS.to_string(),
"OLD_TIME" => libc::OLD_TIME.to_string(),
"NEW_TIME" => libc::NEW_TIME.to_string(),
"BOOT_TIME" => libc::BOOT_TIME.to_string(),
"RUN_LVL" => libc::RUN_LVL.to_string(),
"EMPTY" => libc::EMPTY.to_string(),
"__UT_HOSTSIZE" => libc::__UT_HOSTSIZE.to_string(),
"__UT_NAMESIZE" => libc::__UT_NAMESIZE.to_string(),
"__UT_LINESIZE" => libc::__UT_LINESIZE.to_string(),
"MS_RMT_MASK" => libc::MS_RMT_MASK.to_string(),
"RLIMIT_NLIMITS" => libc::RLIMIT_NLIMITS.to_string(),
"RLIMIT_RTTIME" => libc::RLIMIT_RTTIME.to_string(),
"RLIMIT_RTPRIO" => libc::RLIMIT_RTPRIO.to_string(),
"RLIMIT_NICE" => libc::RLIMIT_NICE.to_string(),
"RLIMIT_MSGQUEUE" => libc::RLIMIT_MSGQUEUE.to_string(),
"RLIMIT_SIGPENDING" => libc::RLIMIT_SIGPENDING.to_string(),
"RLIMIT_LOCKS" => libc::RLIMIT_LOCKS.to_string(),
"RLIMIT_CORE" => libc::RLIMIT_CORE.to_string(),
"RLIMIT_STACK" => libc::RLIMIT_STACK.to_string(),
"RLIMIT_DATA" => libc::RLIMIT_DATA.to_string(),
"RLIMIT_FSIZE" => libc::RLIMIT_FSIZE.to_string(),
"RLIMIT_CPU" => libc::RLIMIT_CPU.to_string(),
"MAP_HUGE_16GB" => libc::MAP_HUGE_16GB.to_string(),
"MAP_HUGE_2GB" => libc::MAP_HUGE_2GB.to_string(),
"MAP_HUGE_1GB" => libc::MAP_HUGE_1GB.to_string(),
"MAP_HUGE_512MB" => libc::MAP_HUGE_512MB.to_string(),
"MAP_HUGE_256MB" => libc::MAP_HUGE_256MB.to_string(),
"MAP_HUGE_32MB" => libc::MAP_HUGE_32MB.to_string(),
"MAP_HUGE_16MB" => libc::MAP_HUGE_16MB.to_string(),
"MAP_HUGE_8MB" => libc::MAP_HUGE_8MB.to_string(),
"MAP_HUGE_2MB" => libc::MAP_HUGE_2MB.to_string(),
"MAP_HUGE_1MB" => libc::MAP_HUGE_1MB.to_string(),
"MAP_HUGE_512KB" => libc::MAP_HUGE_512KB.to_string(),
"MAP_HUGE_64KB" => libc::MAP_HUGE_64KB.to_string(),
"MAP_HUGE_MASK" => libc::MAP_HUGE_MASK.to_string(),
"MAP_HUGE_SHIFT" => libc::MAP_HUGE_SHIFT.to_string(),
"HUGETLB_FLAG_ENCODE_16GB" => libc::HUGETLB_FLAG_ENCODE_16GB.to_string(),
"HUGETLB_FLAG_ENCODE_2GB" => libc::HUGETLB_FLAG_ENCODE_2GB.to_string(),
"HUGETLB_FLAG_ENCODE_1GB" => libc::HUGETLB_FLAG_ENCODE_1GB.to_string(),
"HUGETLB_FLAG_ENCODE_512MB" => libc::HUGETLB_FLAG_ENCODE_512MB.to_string(),
"HUGETLB_FLAG_ENCODE_256MB" => libc::HUGETLB_FLAG_ENCODE_256MB.to_string(),
"HUGETLB_FLAG_ENCODE_32MB" => libc::HUGETLB_FLAG_ENCODE_32MB.to_string(),
"HUGETLB_FLAG_ENCODE_16MB" => libc::HUGETLB_FLAG_ENCODE_16MB.to_string(),
"HUGETLB_FLAG_ENCODE_8MB" => libc::HUGETLB_FLAG_ENCODE_8MB.to_string(),
"HUGETLB_FLAG_ENCODE_2MB" => libc::HUGETLB_FLAG_ENCODE_2MB.to_string(),
"HUGETLB_FLAG_ENCODE_1MB" => libc::HUGETLB_FLAG_ENCODE_1MB.to_string(),
"HUGETLB_FLAG_ENCODE_512KB" => libc::HUGETLB_FLAG_ENCODE_512KB.to_string(),
"HUGETLB_FLAG_ENCODE_64KB" => libc::HUGETLB_FLAG_ENCODE_64KB.to_string(),
"HUGETLB_FLAG_ENCODE_MASK" => libc::HUGETLB_FLAG_ENCODE_MASK.to_string(),
"HUGETLB_FLAG_ENCODE_SHIFT" => libc::HUGETLB_FLAG_ENCODE_SHIFT.to_string(),
"EWOULDBLOCK" => libc::EWOULDBLOCK.to_string(),
"ERANGE" => libc::ERANGE.to_string(),
"EDOM" => libc::EDOM.to_string(),
"EPIPE" => libc::EPIPE.to_string(),
"EMLINK" => libc::EMLINK.to_string(),
"EROFS" => libc::EROFS.to_string(),
"ESPIPE" => libc::ESPIPE.to_string(),
"ENOSPC" => libc::ENOSPC.to_string(),
"EFBIG" => libc::EFBIG.to_string(),
"ETXTBSY" => libc::ETXTBSY.to_string(),
"ENOTTY" => libc::ENOTTY.to_string(),
"EMFILE" => libc::EMFILE.to_string(),
"ENFILE" => libc::ENFILE.to_string(),
"EINVAL" => libc::EINVAL.to_string(),
"EISDIR" => libc::EISDIR.to_string(),
"ENOTDIR" => libc::ENOTDIR.to_string(),
"ENODEV" => libc::ENODEV.to_string(),
"EXDEV" => libc::EXDEV.to_string(),
"EEXIST" => libc::EEXIST.to_string(),
"EBUSY" => libc::EBUSY.to_string(),
"ENOTBLK" => libc::ENOTBLK.to_string(),
"EFAULT" => libc::EFAULT.to_string(),
"EACCES" => libc::EACCES.to_string(),
"ENOMEM" => libc::ENOMEM.to_string(),
"EAGAIN" => libc::EAGAIN.to_string(),
"ECHILD" => libc::ECHILD.to_string(),
"EBADF" => libc::EBADF.to_string(),
"ENOEXEC" => libc::ENOEXEC.to_string(),
"E2BIG" => libc::E2BIG.to_string(),
"ENXIO" => libc::ENXIO.to_string(),
"EIO" => libc::EIO.to_string(),
"EINTR" => libc::EINTR.to_string(),
"ESRCH" => libc::ESRCH.to_string(),
"ENOENT" => libc::ENOENT.to_string(),
"EPERM" => libc::EPERM.to_string(),
"SO_EE_ORIGIN_TIMESTAMPING" => libc::SO_EE_ORIGIN_TIMESTAMPING.to_string(),
"SO_EE_ORIGIN_TXSTATUS" => libc::SO_EE_ORIGIN_TXSTATUS.to_string(),
"SO_EE_ORIGIN_ICMP6" => libc::SO_EE_ORIGIN_ICMP6.to_string(),
"SO_EE_ORIGIN_ICMP" => libc::SO_EE_ORIGIN_ICMP.to_string(),
"SO_EE_ORIGIN_LOCAL" => libc::SO_EE_ORIGIN_LOCAL.to_string(),
"SO_EE_ORIGIN_NONE" => libc::SO_EE_ORIGIN_NONE.to_string(),
"REG_BADRPT" => libc::REG_BADRPT.to_string(),
"REG_ESPACE" => libc::REG_ESPACE.to_string(),
"REG_ERANGE" => libc::REG_ERANGE.to_string(),
"REG_BADBR" => libc::REG_BADBR.to_string(),
"REG_EBRACE" => libc::REG_EBRACE.to_string(),
"REG_EPAREN" => libc::REG_EPAREN.to_string(),
"REG_EBRACK" => libc::REG_EBRACK.to_string(),
"REG_ESUBREG" => libc::REG_ESUBREG.to_string(),
"REG_EESCAPE" => libc::REG_EESCAPE.to_string(),
"REG_ECTYPE" => libc::REG_ECTYPE.to_string(),
"REG_ECOLLATE" => libc::REG_ECOLLATE.to_string(),
"REG_BADPAT" => libc::REG_BADPAT.to_string(),
"REG_NOMATCH" => libc::REG_NOMATCH.to_string(),
"REG_ENOSYS" => libc::REG_ENOSYS.to_string(),
"REG_NOTEOL" => libc::REG_NOTEOL.to_string(),
"REG_NOTBOL" => libc::REG_NOTBOL.to_string(),
"REG_NOSUB" => libc::REG_NOSUB.to_string(),
"REG_NEWLINE" => libc::REG_NEWLINE.to_string(),
"REG_ICASE" => libc::REG_ICASE.to_string(),
"REG_EXTENDED" => libc::REG_EXTENDED.to_string(),
"LINUX_REBOOT_CMD_KEXEC" => libc::LINUX_REBOOT_CMD_KEXEC.to_string(),
"LINUX_REBOOT_CMD_SW_SUSPEND" => libc::LINUX_REBOOT_CMD_SW_SUSPEND.to_string(),
"LINUX_REBOOT_CMD_RESTART2" => libc::LINUX_REBOOT_CMD_RESTART2.to_string(),
"LINUX_REBOOT_CMD_POWER_OFF" => libc::LINUX_REBOOT_CMD_POWER_OFF.to_string(),
"LINUX_REBOOT_CMD_CAD_OFF" => libc::LINUX_REBOOT_CMD_CAD_OFF.to_string(),
"LINUX_REBOOT_CMD_CAD_ON" => libc::LINUX_REBOOT_CMD_CAD_ON.to_string(),
"LINUX_REBOOT_CMD_HALT" => libc::LINUX_REBOOT_CMD_HALT.to_string(),
"LINUX_REBOOT_CMD_RESTART" => libc::LINUX_REBOOT_CMD_RESTART.to_string(),
"LINUX_REBOOT_MAGIC2C" => libc::LINUX_REBOOT_MAGIC2C.to_string(),
"LINUX_REBOOT_MAGIC2B" => libc::LINUX_REBOOT_MAGIC2B.to_string(),
"LINUX_REBOOT_MAGIC2A" => libc::LINUX_REBOOT_MAGIC2A.to_string(),
"LINUX_REBOOT_MAGIC2" => libc::LINUX_REBOOT_MAGIC2.to_string(),
"LINUX_REBOOT_MAGIC1" => libc::LINUX_REBOOT_MAGIC1.to_string(),
"FUTEX_CMD_MASK" => libc::FUTEX_CMD_MASK.to_string(),
"FUTEX_CLOCK_REALTIME" => libc::FUTEX_CLOCK_REALTIME.to_string(),
"FUTEX_PRIVATE_FLAG" => libc::FUTEX_PRIVATE_FLAG.to_string(),
"FUTEX_CMP_REQUEUE_PI" => libc::FUTEX_CMP_REQUEUE_PI.to_string(),
"FUTEX_WAIT_REQUEUE_PI" => libc::FUTEX_WAIT_REQUEUE_PI.to_string(),
"FUTEX_WAKE_BITSET" => libc::FUTEX_WAKE_BITSET.to_string(),
"FUTEX_WAIT_BITSET" => libc::FUTEX_WAIT_BITSET.to_string(),
"FUTEX_TRYLOCK_PI" => libc::FUTEX_TRYLOCK_PI.to_string(),
"FUTEX_UNLOCK_PI" => libc::FUTEX_UNLOCK_PI.to_string(),
"FUTEX_LOCK_PI" => libc::FUTEX_LOCK_PI.to_string(),
"FUTEX_WAKE_OP" => libc::FUTEX_WAKE_OP.to_string(),
"FUTEX_CMP_REQUEUE" => libc::FUTEX_CMP_REQUEUE.to_string(),
"FUTEX_REQUEUE" => libc::FUTEX_REQUEUE.to_string(),
"FUTEX_FD" => libc::FUTEX_FD.to_string(),
"FUTEX_WAKE" => libc::FUTEX_WAKE.to_string(),
"FUTEX_WAIT" => libc::FUTEX_WAIT.to_string(),
"FAN_NOFD" => libc::FAN_NOFD.to_string(),
"FAN_DENY" => libc::FAN_DENY.to_string(),
"FAN_ALLOW" => libc::FAN_ALLOW.to_string(),
"FANOTIFY_METADATA_VERSION" => libc::FANOTIFY_METADATA_VERSION.to_string(),
"FAN_MARK_FLUSH" => libc::FAN_MARK_FLUSH.to_string(),
"FAN_MARK_IGNORED_SURV_MODIFY" => libc::FAN_MARK_IGNORED_SURV_MODIFY.to_string(),
"FAN_MARK_IGNORED_MASK" => libc::FAN_MARK_IGNORED_MASK.to_string(),
"FAN_MARK_FILESYSTEM" => libc::FAN_MARK_FILESYSTEM.to_string(),
"FAN_MARK_MOUNT" => libc::FAN_MARK_MOUNT.to_string(),
"FAN_MARK_INODE" => libc::FAN_MARK_INODE.to_string(),
"FAN_MARK_ONLYDIR" => libc::FAN_MARK_ONLYDIR.to_string(),
"FAN_MARK_DONT_FOLLOW" => libc::FAN_MARK_DONT_FOLLOW.to_string(),
"FAN_MARK_REMOVE" => libc::FAN_MARK_REMOVE.to_string(),
"FAN_MARK_ADD" => libc::FAN_MARK_ADD.to_string(),
"FAN_UNLIMITED_MARKS" => libc::FAN_UNLIMITED_MARKS.to_string(),
"FAN_UNLIMITED_QUEUE" => libc::FAN_UNLIMITED_QUEUE.to_string(),
"FAN_CLASS_PRE_CONTENT" => libc::FAN_CLASS_PRE_CONTENT.to_string(),
"FAN_CLASS_CONTENT" => libc::FAN_CLASS_CONTENT.to_string(),
"FAN_CLASS_NOTIF" => libc::FAN_CLASS_NOTIF.to_string(),
"FAN_NONBLOCK" => libc::FAN_NONBLOCK.to_string(),
"FAN_CLOEXEC" => libc::FAN_CLOEXEC.to_string(),
"FAN_CLOSE" => libc::FAN_CLOSE.to_string(),
"FAN_EVENT_ON_CHILD" => libc::FAN_EVENT_ON_CHILD.to_string(),
"FAN_ONDIR" => libc::FAN_ONDIR.to_string(),
"FAN_ACCESS_PERM" => libc::FAN_ACCESS_PERM.to_string(),
"FAN_OPEN_PERM" => libc::FAN_OPEN_PERM.to_string(),
"FAN_Q_OVERFLOW" => libc::FAN_Q_OVERFLOW.to_string(),
"FAN_OPEN" => libc::FAN_OPEN.to_string(),
"FAN_CLOSE_NOWRITE" => libc::FAN_CLOSE_NOWRITE.to_string(),
"FAN_CLOSE_WRITE" => libc::FAN_CLOSE_WRITE.to_string(),
"FAN_MODIFY" => libc::FAN_MODIFY.to_string(),
"FAN_ACCESS" => libc::FAN_ACCESS.to_string(),
"IN_NONBLOCK" => libc::IN_NONBLOCK.to_string(),
"IN_CLOEXEC" => libc::IN_CLOEXEC.to_string(),
"IN_ALL_EVENTS" => libc::IN_ALL_EVENTS.to_string(),
"IN_ONESHOT" => libc::IN_ONESHOT.to_string(),
"IN_ISDIR" => libc::IN_ISDIR.to_string(),
"KEYCTL_GET_PERSISTENT" => libc::KEYCTL_GET_PERSISTENT.to_string(),
"KEYCTL_INVALIDATE" => libc::KEYCTL_INVALIDATE.to_string(),
"KEYCTL_INSTANTIATE_IOV" => libc::KEYCTL_INSTANTIATE_IOV.to_string(),
"KEYCTL_REJECT" => libc::KEYCTL_REJECT.to_string(),
"KEYCTL_SESSION_TO_PARENT" => libc::KEYCTL_SESSION_TO_PARENT.to_string(),
"KEYCTL_GET_SECURITY" => libc::KEYCTL_GET_SECURITY.to_string(),
"KEYCTL_ASSUME_AUTHORITY" => libc::KEYCTL_ASSUME_AUTHORITY.to_string(),
"KEYCTL_SET_TIMEOUT" => libc::KEYCTL_SET_TIMEOUT.to_string(),
"KEYCTL_SET_REQKEY_KEYRING" => libc::KEYCTL_SET_REQKEY_KEYRING.to_string(),
"KEYCTL_NEGATE" => libc::KEYCTL_NEGATE.to_string(),
"KEYCTL_INSTANTIATE" => libc::KEYCTL_INSTANTIATE.to_string(),
"KEYCTL_READ" => libc::KEYCTL_READ.to_string(),
"KEYCTL_SEARCH" => libc::KEYCTL_SEARCH.to_string(),
"KEYCTL_UNLINK" => libc::KEYCTL_UNLINK.to_string(),
"KEYCTL_LINK" => libc::KEYCTL_LINK.to_string(),
"KEYCTL_CLEAR" => libc::KEYCTL_CLEAR.to_string(),
"KEYCTL_DESCRIBE" => libc::KEYCTL_DESCRIBE.to_string(),
"KEYCTL_SETPERM" => libc::KEYCTL_SETPERM.to_string(),
"KEYCTL_CHOWN" => libc::KEYCTL_CHOWN.to_string(),
"KEYCTL_REVOKE" => libc::KEYCTL_REVOKE.to_string(),
"KEYCTL_UPDATE" => libc::KEYCTL_UPDATE.to_string(),
"KEYCTL_JOIN_SESSION_KEYRING" => libc::KEYCTL_JOIN_SESSION_KEYRING.to_string(),
"KEYCTL_GET_KEYRING_ID" => libc::KEYCTL_GET_KEYRING_ID.to_string(),
"KEY_REQKEY_DEFL_REQUESTOR_KEYRING" => libc::KEY_REQKEY_DEFL_REQUESTOR_KEYRING.to_string(),
"KEY_REQKEY_DEFL_GROUP_KEYRING" => libc::KEY_REQKEY_DEFL_GROUP_KEYRING.to_string(),
"KEY_REQKEY_DEFL_USER_SESSION_KEYRING" => libc::KEY_REQKEY_DEFL_USER_SESSION_KEYRING.to_string(),
"KEY_REQKEY_DEFL_USER_KEYRING" => libc::KEY_REQKEY_DEFL_USER_KEYRING.to_string(),
"KEY_REQKEY_DEFL_SESSION_KEYRING" => libc::KEY_REQKEY_DEFL_SESSION_KEYRING.to_string(),
"KEY_REQKEY_DEFL_PROCESS_KEYRING" => libc::KEY_REQKEY_DEFL_PROCESS_KEYRING.to_string(),
"KEY_REQKEY_DEFL_THREAD_KEYRING" => libc::KEY_REQKEY_DEFL_THREAD_KEYRING.to_string(),
"KEY_REQKEY_DEFL_DEFAULT" => libc::KEY_REQKEY_DEFL_DEFAULT.to_string(),
"KEY_REQKEY_DEFL_NO_CHANGE" => libc::KEY_REQKEY_DEFL_NO_CHANGE.to_string(),
"KEY_SPEC_REQUESTOR_KEYRING" => libc::KEY_SPEC_REQUESTOR_KEYRING.to_string(),
"KEY_SPEC_REQKEY_AUTH_KEY" => libc::KEY_SPEC_REQKEY_AUTH_KEY.to_string(),
"KEY_SPEC_GROUP_KEYRING" => libc::KEY_SPEC_GROUP_KEYRING.to_string(),
"KEY_SPEC_USER_SESSION_KEYRING" => libc::KEY_SPEC_USER_SESSION_KEYRING.to_string(),
"KEY_SPEC_USER_KEYRING" => libc::KEY_SPEC_USER_KEYRING.to_string(),
"KEY_SPEC_SESSION_KEYRING" => libc::KEY_SPEC_SESSION_KEYRING.to_string(),
"KEY_SPEC_PROCESS_KEYRING" => libc::KEY_SPEC_PROCESS_KEYRING.to_string(),
"KEY_SPEC_THREAD_KEYRING" => libc::KEY_SPEC_THREAD_KEYRING.to_string(),
"IN_DONT_FOLLOW" => libc::IN_DONT_FOLLOW.to_string(),
"IN_ONLYDIR" => libc::IN_ONLYDIR.to_string(),
"IN_IGNORED" => libc::IN_IGNORED.to_string(),
"IN_Q_OVERFLOW" => libc::IN_Q_OVERFLOW.to_string(),
"IN_UNMOUNT" => libc::IN_UNMOUNT.to_string(),
"IN_MOVE_SELF" => libc::IN_MOVE_SELF.to_string(),
"IN_DELETE_SELF" => libc::IN_DELETE_SELF.to_string(),
"IN_DELETE" => libc::IN_DELETE.to_string(),
"IN_CREATE" => libc::IN_CREATE.to_string(),
"IN_MOVE" => libc::IN_MOVE.to_string(),
"IN_MOVED_TO" => libc::IN_MOVED_TO.to_string(),
"IN_MOVED_FROM" => libc::IN_MOVED_FROM.to_string(),
"IN_OPEN" => libc::IN_OPEN.to_string(),
"IN_CLOSE" => libc::IN_CLOSE.to_string(),
"IN_CLOSE_NOWRITE" => libc::IN_CLOSE_NOWRITE.to_string(),
"IN_CLOSE_WRITE" => libc::IN_CLOSE_WRITE.to_string(),
"IN_ATTRIB" => libc::IN_ATTRIB.to_string(),
"IN_MODIFY" => libc::IN_MODIFY.to_string(),
"IN_ACCESS" => libc::IN_ACCESS.to_string(),
"VMADDR_PORT_ANY" => libc::VMADDR_PORT_ANY.to_string(),
"VMADDR_CID_HOST" => libc::VMADDR_CID_HOST.to_string(),
"VMADDR_CID_RESERVED" => libc::VMADDR_CID_RESERVED.to_string(),
"VMADDR_CID_HYPERVISOR" => libc::VMADDR_CID_HYPERVISOR.to_string(),
"VMADDR_CID_ANY" => libc::VMADDR_CID_ANY.to_string(),
"MAP_FIXED_NOREPLACE" => libc::MAP_FIXED_NOREPLACE.to_string(),
"MAP_SHARED_VALIDATE" => libc::MAP_SHARED_VALIDATE.to_string(),
"UDP_GRO" => libc::UDP_GRO.to_string(),
"UDP_SEGMENT" => libc::UDP_SEGMENT.to_string(),
"UDP_NO_CHECK6_RX" => libc::UDP_NO_CHECK6_RX.to_string(),
"UDP_NO_CHECK6_TX" => libc::UDP_NO_CHECK6_TX.to_string(),
"UDP_ENCAP" => libc::UDP_ENCAP.to_string(),
"UDP_CORK" => libc::UDP_CORK.to_string(),
"ALG_OP_ENCRYPT" => libc::ALG_OP_ENCRYPT.to_string(),
"ALG_OP_DECRYPT" => libc::ALG_OP_DECRYPT.to_string(),
"ALG_SET_AEAD_AUTHSIZE" => libc::ALG_SET_AEAD_AUTHSIZE.to_string(),
"ALG_SET_AEAD_ASSOCLEN" => libc::ALG_SET_AEAD_ASSOCLEN.to_string(),
"ALG_SET_OP" => libc::ALG_SET_OP.to_string(),
"ALG_SET_IV" => libc::ALG_SET_IV.to_string(),
"ALG_SET_KEY" => libc::ALG_SET_KEY.to_string(),
"SOF_TIMESTAMPING_RAW_HARDWARE" => libc::SOF_TIMESTAMPING_RAW_HARDWARE.to_string(),
"SOF_TIMESTAMPING_SYS_HARDWARE" => libc::SOF_TIMESTAMPING_SYS_HARDWARE.to_string(),
"SOF_TIMESTAMPING_SOFTWARE" => libc::SOF_TIMESTAMPING_SOFTWARE.to_string(),
"SOF_TIMESTAMPING_RX_SOFTWARE" => libc::SOF_TIMESTAMPING_RX_SOFTWARE.to_string(),
"SOF_TIMESTAMPING_RX_HARDWARE" => libc::SOF_TIMESTAMPING_RX_HARDWARE.to_string(),
"SOF_TIMESTAMPING_TX_SOFTWARE" => libc::SOF_TIMESTAMPING_TX_SOFTWARE.to_string(),
"SOF_TIMESTAMPING_TX_HARDWARE" => libc::SOF_TIMESTAMPING_TX_HARDWARE.to_string(),
"MODULE_INIT_IGNORE_VERMAGIC" => libc::MODULE_INIT_IGNORE_VERMAGIC.to_string(),
"MODULE_INIT_IGNORE_MODVERSIONS" => libc::MODULE_INIT_IGNORE_MODVERSIONS.to_string(),
"SCM_TIMESTAMPING" => libc::SCM_TIMESTAMPING.to_string(),
"SO_TIMESTAMPING" => libc::SO_TIMESTAMPING.to_string(),
"ATF_MAGIC" => libc::ATF_MAGIC.to_string(),
"ARPD_FLUSH" => libc::ARPD_FLUSH.to_string(),
"ARPD_LOOKUP" => libc::ARPD_LOOKUP.to_string(),
"ARPD_UPDATE" => libc::ARPD_UPDATE.to_string(),
"MAX_ADDR_LEN" => libc::MAX_ADDR_LEN.to_string(),
"RTMSG_AR_FAILED" => libc::RTMSG_AR_FAILED.to_string(),
"RTMSG_CONTROL" => libc::RTMSG_CONTROL.to_string(),
"RTMSG_DELRULE" => libc::RTMSG_DELRULE.to_string(),
"RTMSG_NEWRULE" => libc::RTMSG_NEWRULE.to_string(),
"RTMSG_DELROUTE" => libc::RTMSG_DELROUTE.to_string(),
"RTMSG_NEWROUTE" => libc::RTMSG_NEWROUTE.to_string(),
"RTMSG_DELDEVICE" => libc::RTMSG_DELDEVICE.to_string(),
"RTMSG_NEWDEVICE" => libc::RTMSG_NEWDEVICE.to_string(),
"RTMSG_OVERRUN" => libc::RTMSG_OVERRUN.to_string(),
"RT_TABLE_LOCAL" => libc::RT_TABLE_LOCAL.to_string(),
"RT_TABLE_MAIN" => libc::RT_TABLE_MAIN.to_string(),
"RT_TABLE_DEFAULT" => libc::RT_TABLE_DEFAULT.to_string(),
"RT_TABLE_COMPAT" => libc::RT_TABLE_COMPAT.to_string(),
"RT_TABLE_UNSPEC" => libc::RT_TABLE_UNSPEC.to_string(),
"RT_SCOPE_NOWHERE" => libc::RT_SCOPE_NOWHERE.to_string(),
"RT_SCOPE_HOST" => libc::RT_SCOPE_HOST.to_string(),
"RT_SCOPE_LINK" => libc::RT_SCOPE_LINK.to_string(),
"RT_SCOPE_SITE" => libc::RT_SCOPE_SITE.to_string(),
"RT_SCOPE_UNIVERSE" => libc::RT_SCOPE_UNIVERSE.to_string(),
"RTPROT_STATIC" => libc::RTPROT_STATIC.to_string(),
"RTPROT_BOOT" => libc::RTPROT_BOOT.to_string(),
"RTPROT_KERNEL" => libc::RTPROT_KERNEL.to_string(),
"RTPROT_REDIRECT" => libc::RTPROT_REDIRECT.to_string(),
"RTPROT_UNSPEC" => libc::RTPROT_UNSPEC.to_string(),
"RTN_XRESOLVE" => libc::RTN_XRESOLVE.to_string(),
"RTN_NAT" => libc::RTN_NAT.to_string(),
"RTN_THROW" => libc::RTN_THROW.to_string(),
"RTN_PROHIBIT" => libc::RTN_PROHIBIT.to_string(),
"RTN_UNREACHABLE" => libc::RTN_UNREACHABLE.to_string(),
"RTN_BLACKHOLE" => libc::RTN_BLACKHOLE.to_string(),
"RTN_MULTICAST" => libc::RTN_MULTICAST.to_string(),
"RTN_ANYCAST" => libc::RTN_ANYCAST.to_string(),
"RTN_BROADCAST" => libc::RTN_BROADCAST.to_string(),
"RTN_LOCAL" => libc::RTN_LOCAL.to_string(),
"RTN_UNICAST" => libc::RTN_UNICAST.to_string(),
"RTN_UNSPEC" => libc::RTN_UNSPEC.to_string(),
"RTA_MFC_STATS" => libc::RTA_MFC_STATS.to_string(),
"RTA_MARK" => libc::RTA_MARK.to_string(),
"RTA_TABLE" => libc::RTA_TABLE.to_string(),
"RTA_MP_ALGO" => libc::RTA_MP_ALGO.to_string(),
"RTA_SESSION" => libc::RTA_SESSION.to_string(),
"RTA_CACHEINFO" => libc::RTA_CACHEINFO.to_string(),
"RTA_FLOW" => libc::RTA_FLOW.to_string(),
"RTA_PROTOINFO" => libc::RTA_PROTOINFO.to_string(),
"RTA_MULTIPATH" => libc::RTA_MULTIPATH.to_string(),
"RTA_METRICS" => libc::RTA_METRICS.to_string(),
"RTA_PREFSRC" => libc::RTA_PREFSRC.to_string(),
"RTA_PRIORITY" => libc::RTA_PRIORITY.to_string(),
"RTA_GATEWAY" => libc::RTA_GATEWAY.to_string(),
"RTA_OIF" => libc::RTA_OIF.to_string(),
"RTA_IIF" => libc::RTA_IIF.to_string(),
"RTA_SRC" => libc::RTA_SRC.to_string(),
"RTA_DST" => libc::RTA_DST.to_string(),
"RTA_UNSPEC" => libc::RTA_UNSPEC.to_string(),
"RTM_F_PREFIX" => libc::RTM_F_PREFIX.to_string(),
"RTM_F_EQUALIZE" => libc::RTM_F_EQUALIZE.to_string(),
"RTM_F_CLONED" => libc::RTM_F_CLONED.to_string(),
"RTM_F_NOTIFY" => libc::RTM_F_NOTIFY.to_string(),
"RTM_GETNSID" => libc::RTM_GETNSID.to_string(),
"RTM_DELNSID" => libc::RTM_DELNSID.to_string(),
"RTM_NEWNSID" => libc::RTM_NEWNSID.to_string(),
"RTM_GETMDB" => libc::RTM_GETMDB.to_string(),
"RTM_DELMDB" => libc::RTM_DELMDB.to_string(),
"RTM_NEWMDB" => libc::RTM_NEWMDB.to_string(),
"RTM_GETNETCONF" => libc::RTM_GETNETCONF.to_string(),
"RTM_NEWNETCONF" => libc::RTM_NEWNETCONF.to_string(),
"RTM_SETDCB" => libc::RTM_SETDCB.to_string(),
"RTM_GETDCB" => libc::RTM_GETDCB.to_string(),
"RTM_GETADDRLABEL" => libc::RTM_GETADDRLABEL.to_string(),
"RTM_DELADDRLABEL" => libc::RTM_DELADDRLABEL.to_string(),
"RTM_NEWADDRLABEL" => libc::RTM_NEWADDRLABEL.to_string(),
"RTM_NEWNDUSEROPT" => libc::RTM_NEWNDUSEROPT.to_string(),
"RTM_SETNEIGHTBL" => libc::RTM_SETNEIGHTBL.to_string(),
"RTM_GETNEIGHTBL" => libc::RTM_GETNEIGHTBL.to_string(),
"RTM_NEWNEIGHTBL" => libc::RTM_NEWNEIGHTBL.to_string(),
"RTM_GETANYCAST" => libc::RTM_GETANYCAST.to_string(),
"RTM_GETMULTICAST" => libc::RTM_GETMULTICAST.to_string(),
"RTM_NEWPREFIX" => libc::RTM_NEWPREFIX.to_string(),
"RTM_GETACTION" => libc::RTM_GETACTION.to_string(),
"RTM_DELACTION" => libc::RTM_DELACTION.to_string(),
"RTM_NEWACTION" => libc::RTM_NEWACTION.to_string(),
"RTM_GETTFILTER" => libc::RTM_GETTFILTER.to_string(),
"RTM_DELTFILTER" => libc::RTM_DELTFILTER.to_string(),
"RTM_NEWTFILTER" => libc::RTM_NEWTFILTER.to_string(),
"RTM_GETTCLASS" => libc::RTM_GETTCLASS.to_string(),
"RTM_DELTCLASS" => libc::RTM_DELTCLASS.to_string(),
"RTM_NEWTCLASS" => libc::RTM_NEWTCLASS.to_string(),
"RTM_GETQDISC" => libc::RTM_GETQDISC.to_string(),
"RTM_DELQDISC" => libc::RTM_DELQDISC.to_string(),
"RTM_NEWQDISC" => libc::RTM_NEWQDISC.to_string(),
"RTM_GETRULE" => libc::RTM_GETRULE.to_string(),
"RTM_DELRULE" => libc::RTM_DELRULE.to_string(),
"RTM_NEWRULE" => libc::RTM_NEWRULE.to_string(),
"RTM_GETNEIGH" => libc::RTM_GETNEIGH.to_string(),
"RTM_DELNEIGH" => libc::RTM_DELNEIGH.to_string(),
"RTM_NEWNEIGH" => libc::RTM_NEWNEIGH.to_string(),
"RTM_GETROUTE" => libc::RTM_GETROUTE.to_string(),
"RTM_DELROUTE" => libc::RTM_DELROUTE.to_string(),
"RTM_NEWROUTE" => libc::RTM_NEWROUTE.to_string(),
"RTM_GETADDR" => libc::RTM_GETADDR.to_string(),
"RTM_DELADDR" => libc::RTM_DELADDR.to_string(),
"RTM_NEWADDR" => libc::RTM_NEWADDR.to_string(),
"RTM_SETLINK" => libc::RTM_SETLINK.to_string(),
"RTM_GETLINK" => libc::RTM_GETLINK.to_string(),
"RTM_DELLINK" => libc::RTM_DELLINK.to_string(),
"RTM_NEWLINK" => libc::RTM_NEWLINK.to_string(),
"TCA_STAB" => libc::TCA_STAB.to_string(),
"TCA_STATS2" => libc::TCA_STATS2.to_string(),
"TCA_FCNT" => libc::TCA_FCNT.to_string(),
"TCA_RATE" => libc::TCA_RATE.to_string(),
"TCA_XSTATS" => libc::TCA_XSTATS.to_string(),
"TCA_STATS" => libc::TCA_STATS.to_string(),
"TCA_OPTIONS" => libc::TCA_OPTIONS.to_string(),
"TCA_KIND" => libc::TCA_KIND.to_string(),
"TCA_UNSPEC" => libc::TCA_UNSPEC.to_string(),
"NLA_TYPE_MASK" => libc::NLA_TYPE_MASK.to_string(),
"NLA_F_NET_BYTEORDER" => libc::NLA_F_NET_BYTEORDER.to_string(),
"NLA_F_NESTED" => libc::NLA_F_NESTED.to_string(),
"NETLINK_CAP_ACK" => libc::NETLINK_CAP_ACK.to_string(),
"NETLINK_LIST_MEMBERSHIPS" => libc::NETLINK_LIST_MEMBERSHIPS.to_string(),
"NETLINK_LISTEN_ALL_NSID" => libc::NETLINK_LISTEN_ALL_NSID.to_string(),
"NETLINK_TX_RING" => libc::NETLINK_TX_RING.to_string(),
"NETLINK_RX_RING" => libc::NETLINK_RX_RING.to_string(),
"NETLINK_NO_ENOBUFS" => libc::NETLINK_NO_ENOBUFS.to_string(),
"NETLINK_BROADCAST_ERROR" => libc::NETLINK_BROADCAST_ERROR.to_string(),
"NETLINK_PKTINFO" => libc::NETLINK_PKTINFO.to_string(),
"NETLINK_DROP_MEMBERSHIP" => libc::NETLINK_DROP_MEMBERSHIP.to_string(),
"NETLINK_ADD_MEMBERSHIP" => libc::NETLINK_ADD_MEMBERSHIP.to_string(),
"NLM_F_APPEND" => libc::NLM_F_APPEND.to_string(),
"NLM_F_CREATE" => libc::NLM_F_CREATE.to_string(),
"NLM_F_EXCL" => libc::NLM_F_EXCL.to_string(),
"NLM_F_REPLACE" => libc::NLM_F_REPLACE.to_string(),
"NLM_F_DUMP" => libc::NLM_F_DUMP.to_string(),
"NLM_F_ATOMIC" => libc::NLM_F_ATOMIC.to_string(),
"NLM_F_MATCH" => libc::NLM_F_MATCH.to_string(),
"NLM_F_ROOT" => libc::NLM_F_ROOT.to_string(),
"NLM_F_DUMP_FILTERED" => libc::NLM_F_DUMP_FILTERED.to_string(),
"NLM_F_DUMP_INTR" => libc::NLM_F_DUMP_INTR.to_string(),
"NLM_F_ECHO" => libc::NLM_F_ECHO.to_string(),
"NLM_F_ACK" => libc::NLM_F_ACK.to_string(),
"NLM_F_MULTI" => libc::NLM_F_MULTI.to_string(),
"NLM_F_REQUEST" => libc::NLM_F_REQUEST.to_string(),
"NETLINK_INET_DIAG" => libc::NETLINK_INET_DIAG.to_string(),
"NETLINK_CRYPTO" => libc::NETLINK_CRYPTO.to_string(),
"NETLINK_RDMA" => libc::NETLINK_RDMA.to_string(),
"NETLINK_ECRYPTFS" => libc::NETLINK_ECRYPTFS.to_string(),
"NETLINK_SCSITRANSPORT" => libc::NETLINK_SCSITRANSPORT.to_string(),
"NETLINK_GENERIC" => libc::NETLINK_GENERIC.to_string(),
"NETLINK_KOBJECT_UEVENT" => libc::NETLINK_KOBJECT_UEVENT.to_string(),
"NETLINK_DNRTMSG" => libc::NETLINK_DNRTMSG.to_string(),
"NETLINK_IP6_FW" => libc::NETLINK_IP6_FW.to_string(),
"NETLINK_NETFILTER" => libc::NETLINK_NETFILTER.to_string(),
"NETLINK_CONNECTOR" => libc::NETLINK_CONNECTOR.to_string(),
"NETLINK_FIB_LOOKUP" => libc::NETLINK_FIB_LOOKUP.to_string(),
"NETLINK_AUDIT" => libc::NETLINK_AUDIT.to_string(),
"NETLINK_ISCSI" => libc::NETLINK_ISCSI.to_string(),
"NETLINK_SELINUX" => libc::NETLINK_SELINUX.to_string(),
"NETLINK_XFRM" => libc::NETLINK_XFRM.to_string(),
"NETLINK_NFLOG" => libc::NETLINK_NFLOG.to_string(),
"NETLINK_SOCK_DIAG" => libc::NETLINK_SOCK_DIAG.to_string(),
"NETLINK_FIREWALL" => libc::NETLINK_FIREWALL.to_string(),
"NETLINK_USERSOCK" => libc::NETLINK_USERSOCK.to_string(),
"NETLINK_UNUSED" => libc::NETLINK_UNUSED.to_string(),
"NETLINK_ROUTE" => libc::NETLINK_ROUTE.to_string(),
"NLA_ALIGNTO" => libc::NLA_ALIGNTO.to_string(),
"NDA_IFINDEX" => libc::NDA_IFINDEX.to_string(),
"NDA_VNI" => libc::NDA_VNI.to_string(),
"NDA_PORT" => libc::NDA_PORT.to_string(),
"NDA_VLAN" => libc::NDA_VLAN.to_string(),
"NDA_PROBES" => libc::NDA_PROBES.to_string(),
"NDA_CACHEINFO" => libc::NDA_CACHEINFO.to_string(),
"NDA_LLADDR" => libc::NDA_LLADDR.to_string(),
"NDA_DST" => libc::NDA_DST.to_string(),
"NDA_UNSPEC" => libc::NDA_UNSPEC.to_string(),
"NTF_ROUTER" => libc::NTF_ROUTER.to_string(),
"NTF_PROXY" => libc::NTF_PROXY.to_string(),
"NTF_MASTER" => libc::NTF_MASTER.to_string(),
"NTF_SELF" => libc::NTF_SELF.to_string(),
"NTF_USE" => libc::NTF_USE.to_string(),
"NUD_PERMANENT" => libc::NUD_PERMANENT.to_string(),
"NUD_NOARP" => libc::NUD_NOARP.to_string(),
"NUD_FAILED" => libc::NUD_FAILED.to_string(),
"NUD_PROBE" => libc::NUD_PROBE.to_string(),
"NUD_DELAY" => libc::NUD_DELAY.to_string(),
"NUD_STALE" => libc::NUD_STALE.to_string(),
"NUD_REACHABLE" => libc::NUD_REACHABLE.to_string(),
"NUD_INCOMPLETE" => libc::NUD_INCOMPLETE.to_string(),
"NUD_NONE" => libc::NUD_NONE.to_string(),
"RT_CLASS_MAX" => libc::RT_CLASS_MAX.to_string(),
"RT_CLASS_LOCAL" => libc::RT_CLASS_LOCAL.to_string(),
"RT_CLASS_MAIN" => libc::RT_CLASS_MAIN.to_string(),
"RT_CLASS_DEFAULT" => libc::RT_CLASS_DEFAULT.to_string(),
"RT_CLASS_UNSPEC" => libc::RT_CLASS_UNSPEC.to_string(),
"RTF_ADDRCLASSMASK" => libc::RTF_ADDRCLASSMASK.to_string(),
"RTF_NAT" => libc::RTF_NAT.to_string(),
"RTF_BROADCAST" => libc::RTF_BROADCAST.to_string(),
"RTF_MULTICAST" => libc::RTF_MULTICAST.to_string(),
"RTF_INTERFACE" => libc::RTF_INTERFACE.to_string(),
"RTF_LOCAL" => libc::RTF_LOCAL.to_string(),
"RTCF_DIRECTSRC" => libc::RTCF_DIRECTSRC.to_string(),
"RTCF_LOG" => libc::RTCF_LOG.to_string(),
"RTCF_DOREDIRECT" => libc::RTCF_DOREDIRECT.to_string(),
"RTCF_NAT" => libc::RTCF_NAT.to_string(),
"RTCF_MASQ" => libc::RTCF_MASQ.to_string(),
"RTCF_VALVE" => libc::RTCF_VALVE.to_string(),
"RTF_POLICY" => libc::RTF_POLICY.to_string(),
"RTF_FLOW" => libc::RTF_FLOW.to_string(),
"RTF_CACHE" => libc::RTF_CACHE.to_string(),
"RTF_NONEXTHOP" => libc::RTF_NONEXTHOP.to_string(),
"RTF_LINKRT" => libc::RTF_LINKRT.to_string(),
"RTF_ADDRCONF" => libc::RTF_ADDRCONF.to_string(),
"RTF_ALLONLINK" => libc::RTF_ALLONLINK.to_string(),
"RTF_DEFAULT" => libc::RTF_DEFAULT.to_string(),
"RTF_NOPMTUDISC" => libc::RTF_NOPMTUDISC.to_string(),
"RTF_THROW" => libc::RTF_THROW.to_string(),
"RTF_NOFORWARD" => libc::RTF_NOFORWARD.to_string(),
"RTF_XRESOLVE" => libc::RTF_XRESOLVE.to_string(),
"RTF_STATIC" => libc::RTF_STATIC.to_string(),
"RTF_REJECT" => libc::RTF_REJECT.to_string(),
"RTF_IRTT" => libc::RTF_IRTT.to_string(),
"RTF_WINDOW" => libc::RTF_WINDOW.to_string(),
"RTF_MSS" => libc::RTF_MSS.to_string(),
"RTF_MTU" => libc::RTF_MTU.to_string(),
"RTF_MODIFIED" => libc::RTF_MODIFIED.to_string(),
"RTF_DYNAMIC" => libc::RTF_DYNAMIC.to_string(),
"RTF_REINSTATE" => libc::RTF_REINSTATE.to_string(),
"RTF_HOST" => libc::RTF_HOST.to_string(),
"RTF_GATEWAY" => libc::RTF_GATEWAY.to_string(),
"RTF_UP" => libc::RTF_UP.to_string(),
"IPTOS_ECN_NOT_ECT" => libc::IPTOS_ECN_NOT_ECT.to_string(),
"IPTOS_PREC_MASK" => libc::IPTOS_PREC_MASK.to_string(),
"IPTOS_TOS_MASK" => libc::IPTOS_TOS_MASK.to_string(),
"SIOCSIFMAP" => libc::SIOCSIFMAP.to_string(),
"SIOCGIFMAP" => libc::SIOCGIFMAP.to_string(),
"SIOCSRARP" => libc::SIOCSRARP.to_string(),
"SIOCGRARP" => libc::SIOCGRARP.to_string(),
"SIOCDRARP" => libc::SIOCDRARP.to_string(),
"SIOCSARP" => libc::SIOCSARP.to_string(),
"SIOCGARP" => libc::SIOCGARP.to_string(),
"SIOCDARP" => libc::SIOCDARP.to_string(),
"SIOCDELMULTI" => libc::SIOCDELMULTI.to_string(),
"SIOCADDMULTI" => libc::SIOCADDMULTI.to_string(),
"SIOCSIFSLAVE" => libc::SIOCSIFSLAVE.to_string(),
"SIOCGIFSLAVE" => libc::SIOCGIFSLAVE.to_string(),
"SIOCGIFHWADDR" => libc::SIOCGIFHWADDR.to_string(),
"SIOCSIFENCAP" => libc::SIOCSIFENCAP.to_string(),
"SIOCGIFENCAP" => libc::SIOCGIFENCAP.to_string(),
"SIOCSIFHWADDR" => libc::SIOCSIFHWADDR.to_string(),
"SIOCSIFMTU" => libc::SIOCSIFMTU.to_string(),
"SIOCGIFMTU" => libc::SIOCGIFMTU.to_string(),
"SIOCSIFMEM" => libc::SIOCSIFMEM.to_string(),
"SIOCGIFMEM" => libc::SIOCGIFMEM.to_string(),
"SIOCSIFMETRIC" => libc::SIOCSIFMETRIC.to_string(),
"SIOCGIFMETRIC" => libc::SIOCGIFMETRIC.to_string(),
"SIOCSIFNETMASK" => libc::SIOCSIFNETMASK.to_string(),
"SIOCGIFNETMASK" => libc::SIOCGIFNETMASK.to_string(),
"SIOCSIFBRDADDR" => libc::SIOCSIFBRDADDR.to_string(),
"SIOCGIFBRDADDR" => libc::SIOCGIFBRDADDR.to_string(),
"SIOCSIFDSTADDR" => libc::SIOCSIFDSTADDR.to_string(),
"SIOCGIFDSTADDR" => libc::SIOCGIFDSTADDR.to_string(),
"SIOCSIFADDR" => libc::SIOCSIFADDR.to_string(),
"SIOCGIFADDR" => libc::SIOCGIFADDR.to_string(),
"SIOCSIFFLAGS" => libc::SIOCSIFFLAGS.to_string(),
"SIOCGIFFLAGS" => libc::SIOCGIFFLAGS.to_string(),
"SIOCGIFCONF" => libc::SIOCGIFCONF.to_string(),
"SIOCSIFLINK" => libc::SIOCSIFLINK.to_string(),
"SIOCGIFNAME" => libc::SIOCGIFNAME.to_string(),
"SIOCDELRT" => libc::SIOCDELRT.to_string(),
"SIOCADDRT" => libc::SIOCADDRT.to_string(),
"IP6T_SO_ORIGINAL_DST" => libc::IP6T_SO_ORIGINAL_DST.to_string(),
"NF_IP6_PRI_LAST" => libc::NF_IP6_PRI_LAST.to_string(),
"NF_IP6_PRI_CONNTRACK_HELPER" => libc::NF_IP6_PRI_CONNTRACK_HELPER.to_string(),
"NF_IP6_PRI_SELINUX_LAST" => libc::NF_IP6_PRI_SELINUX_LAST.to_string(),
"NF_IP6_PRI_NAT_SRC" => libc::NF_IP6_PRI_NAT_SRC.to_string(),
"NF_IP6_PRI_SECURITY" => libc::NF_IP6_PRI_SECURITY.to_string(),
"NF_IP6_PRI_FILTER" => libc::NF_IP6_PRI_FILTER.to_string(),
"NF_IP6_PRI_NAT_DST" => libc::NF_IP6_PRI_NAT_DST.to_string(),
"NF_IP6_PRI_MANGLE" => libc::NF_IP6_PRI_MANGLE.to_string(),
"NF_IP6_PRI_CONNTRACK" => libc::NF_IP6_PRI_CONNTRACK.to_string(),
"NF_IP6_PRI_SELINUX_FIRST" => libc::NF_IP6_PRI_SELINUX_FIRST.to_string(),
"NF_IP6_PRI_RAW" => libc::NF_IP6_PRI_RAW.to_string(),
"NF_IP6_PRI_CONNTRACK_DEFRAG" => libc::NF_IP6_PRI_CONNTRACK_DEFRAG.to_string(),
"NF_IP6_PRI_FIRST" => libc::NF_IP6_PRI_FIRST.to_string(),
"NF_IP6_NUMHOOKS" => libc::NF_IP6_NUMHOOKS.to_string(),
"NF_IP6_POST_ROUTING" => libc::NF_IP6_POST_ROUTING.to_string(),
"NF_IP6_LOCAL_OUT" => libc::NF_IP6_LOCAL_OUT.to_string(),
"NF_IP6_FORWARD" => libc::NF_IP6_FORWARD.to_string(),
"NF_IP6_LOCAL_IN" => libc::NF_IP6_LOCAL_IN.to_string(),
"NF_IP6_PRE_ROUTING" => libc::NF_IP6_PRE_ROUTING.to_string(),
"NF_IP_PRI_LAST" => libc::NF_IP_PRI_LAST.to_string(),
"NF_IP_PRI_CONNTRACK_CONFIRM" => libc::NF_IP_PRI_CONNTRACK_CONFIRM.to_string(),
"NF_IP_PRI_CONNTRACK_HELPER" => libc::NF_IP_PRI_CONNTRACK_HELPER.to_string(),
"NF_IP_PRI_SELINUX_LAST" => libc::NF_IP_PRI_SELINUX_LAST.to_string(),
"NF_IP_PRI_NAT_SRC" => libc::NF_IP_PRI_NAT_SRC.to_string(),
"NF_IP_PRI_SECURITY" => libc::NF_IP_PRI_SECURITY.to_string(),
"NF_IP_PRI_FILTER" => libc::NF_IP_PRI_FILTER.to_string(),
"NF_IP_PRI_NAT_DST" => libc::NF_IP_PRI_NAT_DST.to_string(),
"NF_IP_PRI_MANGLE" => libc::NF_IP_PRI_MANGLE.to_string(),
"NF_IP_PRI_CONNTRACK" => libc::NF_IP_PRI_CONNTRACK.to_string(),
"NF_IP_PRI_SELINUX_FIRST" => libc::NF_IP_PRI_SELINUX_FIRST.to_string(),
"NF_IP_PRI_RAW" => libc::NF_IP_PRI_RAW.to_string(),
"NF_IP_PRI_CONNTRACK_DEFRAG" => libc::NF_IP_PRI_CONNTRACK_DEFRAG.to_string(),
"NF_IP_PRI_FIRST" => libc::NF_IP_PRI_FIRST.to_string(),
"NF_IP_NUMHOOKS" => libc::NF_IP_NUMHOOKS.to_string(),
"NF_IP_POST_ROUTING" => libc::NF_IP_POST_ROUTING.to_string(),
"NF_IP_LOCAL_OUT" => libc::NF_IP_LOCAL_OUT.to_string(),
"NF_IP_FORWARD" => libc::NF_IP_FORWARD.to_string(),
"NF_IP_LOCAL_IN" => libc::NF_IP_LOCAL_IN.to_string(),
"NF_IP_PRE_ROUTING" => libc::NF_IP_PRE_ROUTING.to_string(),
"NFPROTO_NUMPROTO" => libc::NFPROTO_NUMPROTO.to_string(),
"NFPROTO_DECNET" => libc::NFPROTO_DECNET.to_string(),
"NFPROTO_IPV6" => libc::NFPROTO_IPV6.to_string(),
"NFPROTO_BRIDGE" => libc::NFPROTO_BRIDGE.to_string(),
"NFPROTO_ARP" => libc::NFPROTO_ARP.to_string(),
"NFPROTO_IPV4" => libc::NFPROTO_IPV4.to_string(),
"NFPROTO_UNSPEC" => libc::NFPROTO_UNSPEC.to_string(),
"NF_INET_NUMHOOKS" => libc::NF_INET_NUMHOOKS.to_string(),
"NF_INET_POST_ROUTING" => libc::NF_INET_POST_ROUTING.to_string(),
"NF_INET_LOCAL_OUT" => libc::NF_INET_LOCAL_OUT.to_string(),
"NF_INET_FORWARD" => libc::NF_INET_FORWARD.to_string(),
"NF_INET_LOCAL_IN" => libc::NF_INET_LOCAL_IN.to_string(),
"NF_INET_PRE_ROUTING" => libc::NF_INET_PRE_ROUTING.to_string(),
"NF_VERDICT_BITS" => libc::NF_VERDICT_BITS.to_string(),
"NF_VERDICT_QBITS" => libc::NF_VERDICT_QBITS.to_string(),
"NF_VERDICT_QMASK" => libc::NF_VERDICT_QMASK.to_string(),
"NF_VERDICT_FLAG_QUEUE_BYPASS" => libc::NF_VERDICT_FLAG_QUEUE_BYPASS.to_string(),
"NF_VERDICT_MASK" => libc::NF_VERDICT_MASK.to_string(),
"NF_MAX_VERDICT" => libc::NF_MAX_VERDICT.to_string(),
"NF_STOP" => libc::NF_STOP.to_string(),
"NF_REPEAT" => libc::NF_REPEAT.to_string(),
"NF_QUEUE" => libc::NF_QUEUE.to_string(),
"NF_STOLEN" => libc::NF_STOLEN.to_string(),
"NF_ACCEPT" => libc::NF_ACCEPT.to_string(),
"NF_DROP" => libc::NF_DROP.to_string(),
"PACKET_MR_UNICAST" => libc::PACKET_MR_UNICAST.to_string(),
"PACKET_MR_ALLMULTI" => libc::PACKET_MR_ALLMULTI.to_string(),
"PACKET_MR_PROMISC" => libc::PACKET_MR_PROMISC.to_string(),
"PACKET_MR_MULTICAST" => libc::PACKET_MR_MULTICAST.to_string(),
"PACKET_DROP_MEMBERSHIP" => libc::PACKET_DROP_MEMBERSHIP.to_string(),
"PACKET_ADD_MEMBERSHIP" => libc::PACKET_ADD_MEMBERSHIP.to_string(),
"CTRL_ATTR_MCAST_GRP_ID" => libc::CTRL_ATTR_MCAST_GRP_ID.to_string(),
"CTRL_ATTR_MCAST_GRP_NAME" => libc::CTRL_ATTR_MCAST_GRP_NAME.to_string(),
"CTRL_ATTR_MCAST_GRP_UNSPEC" => libc::CTRL_ATTR_MCAST_GRP_UNSPEC.to_string(),
"CTRL_ATTR_OP_FLAGS" => libc::CTRL_ATTR_OP_FLAGS.to_string(),
"CTRL_ATTR_OP_ID" => libc::CTRL_ATTR_OP_ID.to_string(),
"CTRL_ATTR_OP_UNSPEC" => libc::CTRL_ATTR_OP_UNSPEC.to_string(),
"CTRL_ATTR_MCAST_GROUPS" => libc::CTRL_ATTR_MCAST_GROUPS.to_string(),
"CTRL_ATTR_OPS" => libc::CTRL_ATTR_OPS.to_string(),
"CTRL_ATTR_MAXATTR" => libc::CTRL_ATTR_MAXATTR.to_string(),
"CTRL_ATTR_HDRSIZE" => libc::CTRL_ATTR_HDRSIZE.to_string(),
"CTRL_ATTR_VERSION" => libc::CTRL_ATTR_VERSION.to_string(),
"CTRL_ATTR_FAMILY_NAME" => libc::CTRL_ATTR_FAMILY_NAME.to_string(),
"CTRL_ATTR_FAMILY_ID" => libc::CTRL_ATTR_FAMILY_ID.to_string(),
"CTRL_ATTR_UNSPEC" => libc::CTRL_ATTR_UNSPEC.to_string(),
"CTRL_CMD_GETMCAST_GRP" => libc::CTRL_CMD_GETMCAST_GRP.to_string(),
"CTRL_CMD_DELMCAST_GRP" => libc::CTRL_CMD_DELMCAST_GRP.to_string(),
"CTRL_CMD_NEWMCAST_GRP" => libc::CTRL_CMD_NEWMCAST_GRP.to_string(),
"CTRL_CMD_GETOPS" => libc::CTRL_CMD_GETOPS.to_string(),
"CTRL_CMD_DELOPS" => libc::CTRL_CMD_DELOPS.to_string(),
"CTRL_CMD_NEWOPS" => libc::CTRL_CMD_NEWOPS.to_string(),
"CTRL_CMD_GETFAMILY" => libc::CTRL_CMD_GETFAMILY.to_string(),
"CTRL_CMD_DELFAMILY" => libc::CTRL_CMD_DELFAMILY.to_string(),
"CTRL_CMD_NEWFAMILY" => libc::CTRL_CMD_NEWFAMILY.to_string(),
"CTRL_CMD_UNSPEC" => libc::CTRL_CMD_UNSPEC.to_string(),
"GENL_ID_CTRL" => libc::GENL_ID_CTRL.to_string(),
"GENL_CMD_CAP_HASPOL" => libc::GENL_CMD_CAP_HASPOL.to_string(),
"GENL_CMD_CAP_DUMP" => libc::GENL_CMD_CAP_DUMP.to_string(),
"GENL_CMD_CAP_DO" => libc::GENL_CMD_CAP_DO.to_string(),
"GENL_ADMIN_PERM" => libc::GENL_ADMIN_PERM.to_string(),
"GENL_MAX_ID" => libc::GENL_MAX_ID.to_string(),
"GENL_MIN_ID" => libc::GENL_MIN_ID.to_string(),
"GENL_NAMSIZ" => libc::GENL_NAMSIZ.to_string(),
"NFQA_SKB_CSUM_NOTVERIFIED" => libc::NFQA_SKB_CSUM_NOTVERIFIED.to_string(),
"NFQA_SKB_GSO" => libc::NFQA_SKB_GSO.to_string(),
"NFQA_SKB_CSUMNOTREADY" => libc::NFQA_SKB_CSUMNOTREADY.to_string(),
"NFQA_CFG_F_MAX" => libc::NFQA_CFG_F_MAX.to_string(),
"NFQA_CFG_F_SECCTX" => libc::NFQA_CFG_F_SECCTX.to_string(),
"NFQA_CFG_F_UID_GID" => libc::NFQA_CFG_F_UID_GID.to_string(),
"NFQA_CFG_F_GSO" => libc::NFQA_CFG_F_GSO.to_string(),
"NFQA_CFG_F_CONNTRACK" => libc::NFQA_CFG_F_CONNTRACK.to_string(),
"NFQA_CFG_F_FAIL_OPEN" => libc::NFQA_CFG_F_FAIL_OPEN.to_string(),
"NFQA_CFG_FLAGS" => libc::NFQA_CFG_FLAGS.to_string(),
"NFQA_CFG_MASK" => libc::NFQA_CFG_MASK.to_string(),
"NFQA_CFG_QUEUE_MAXLEN" => libc::NFQA_CFG_QUEUE_MAXLEN.to_string(),
"NFQA_CFG_PARAMS" => libc::NFQA_CFG_PARAMS.to_string(),
"NFQA_CFG_CMD" => libc::NFQA_CFG_CMD.to_string(),
"NFQA_CFG_UNSPEC" => libc::NFQA_CFG_UNSPEC.to_string(),
"NFQNL_COPY_PACKET" => libc::NFQNL_COPY_PACKET.to_string(),
"NFQNL_COPY_META" => libc::NFQNL_COPY_META.to_string(),
"NFQNL_COPY_NONE" => libc::NFQNL_COPY_NONE.to_string(),
"NFQNL_CFG_CMD_PF_UNBIND" => libc::NFQNL_CFG_CMD_PF_UNBIND.to_string(),
"NFQNL_CFG_CMD_PF_BIND" => libc::NFQNL_CFG_CMD_PF_BIND.to_string(),
"NFQNL_CFG_CMD_UNBIND" => libc::NFQNL_CFG_CMD_UNBIND.to_string(),
"NFQNL_CFG_CMD_BIND" => libc::NFQNL_CFG_CMD_BIND.to_string(),
"NFQNL_CFG_CMD_NONE" => libc::NFQNL_CFG_CMD_NONE.to_string(),
"NFQA_SECCTX" => libc::NFQA_SECCTX.to_string(),
"NFQA_GID" => libc::NFQA_GID.to_string(),
"NFQA_UID" => libc::NFQA_UID.to_string(),
"NFQA_EXP" => libc::NFQA_EXP.to_string(),
"NFQA_SKB_INFO" => libc::NFQA_SKB_INFO.to_string(),
"NFQA_CAP_LEN" => libc::NFQA_CAP_LEN.to_string(),
"NFQA_CT_INFO" => libc::NFQA_CT_INFO.to_string(),
"NFQA_CT" => libc::NFQA_CT.to_string(),
"NFQA_PAYLOAD" => libc::NFQA_PAYLOAD.to_string(),
"NFQA_HWADDR" => libc::NFQA_HWADDR.to_string(),
"NFQA_IFINDEX_PHYSOUTDEV" => libc::NFQA_IFINDEX_PHYSOUTDEV.to_string(),
"NFQA_IFINDEX_PHYSINDEV" => libc::NFQA_IFINDEX_PHYSINDEV.to_string(),
"NFQA_IFINDEX_OUTDEV" => libc::NFQA_IFINDEX_OUTDEV.to_string(),
"NFQA_IFINDEX_INDEV" => libc::NFQA_IFINDEX_INDEV.to_string(),
"NFQA_TIMESTAMP" => libc::NFQA_TIMESTAMP.to_string(),
"NFQA_MARK" => libc::NFQA_MARK.to_string(),
"NFQA_VERDICT_HDR" => libc::NFQA_VERDICT_HDR.to_string(),
"NFQA_PACKET_HDR" => libc::NFQA_PACKET_HDR.to_string(),
"NFQA_UNSPEC" => libc::NFQA_UNSPEC.to_string(),
"NFQNL_MSG_VERDICT_BATCH" => libc::NFQNL_MSG_VERDICT_BATCH.to_string(),
"NFQNL_MSG_CONFIG" => libc::NFQNL_MSG_CONFIG.to_string(),
"NFQNL_MSG_VERDICT" => libc::NFQNL_MSG_VERDICT.to_string(),
"NFQNL_MSG_PACKET" => libc::NFQNL_MSG_PACKET.to_string(),
"NFULNL_CFG_F_CONNTRACK" => libc::NFULNL_CFG_F_CONNTRACK.to_string(),
"NFULNL_CFG_F_SEQ_GLOBAL" => libc::NFULNL_CFG_F_SEQ_GLOBAL.to_string(),
"NFULNL_CFG_F_SEQ" => libc::NFULNL_CFG_F_SEQ.to_string(),
"NFULNL_COPY_PACKET" => libc::NFULNL_COPY_PACKET.to_string(),
"NFULNL_COPY_META" => libc::NFULNL_COPY_META.to_string(),
"NFULNL_COPY_NONE" => libc::NFULNL_COPY_NONE.to_string(),
"NFULA_CFG_FLAGS" => libc::NFULA_CFG_FLAGS.to_string(),
"NFULA_CFG_QTHRESH" => libc::NFULA_CFG_QTHRESH.to_string(),
"NFULA_CFG_TIMEOUT" => libc::NFULA_CFG_TIMEOUT.to_string(),
"NFULA_CFG_NLBUFSIZ" => libc::NFULA_CFG_NLBUFSIZ.to_string(),
"NFULA_CFG_MODE" => libc::NFULA_CFG_MODE.to_string(),
"NFULA_CFG_CMD" => libc::NFULA_CFG_CMD.to_string(),
"NFULA_CFG_UNSPEC" => libc::NFULA_CFG_UNSPEC.to_string(),
"NFULNL_CFG_CMD_PF_UNBIND" => libc::NFULNL_CFG_CMD_PF_UNBIND.to_string(),
"NFULNL_CFG_CMD_PF_BIND" => libc::NFULNL_CFG_CMD_PF_BIND.to_string(),
"NFULNL_CFG_CMD_UNBIND" => libc::NFULNL_CFG_CMD_UNBIND.to_string(),
"NFULNL_CFG_CMD_BIND" => libc::NFULNL_CFG_CMD_BIND.to_string(),
"NFULNL_CFG_CMD_NONE" => libc::NFULNL_CFG_CMD_NONE.to_string(),
"NFULA_CT_INFO" => libc::NFULA_CT_INFO.to_string(),
"NFULA_CT" => libc::NFULA_CT.to_string(),
"NFULA_HWLEN" => libc::NFULA_HWLEN.to_string(),
"NFULA_HWHEADER" => libc::NFULA_HWHEADER.to_string(),
"NFULA_HWTYPE" => libc::NFULA_HWTYPE.to_string(),
"NFULA_GID" => libc::NFULA_GID.to_string(),
"NFULA_SEQ_GLOBAL" => libc::NFULA_SEQ_GLOBAL.to_string(),
"NFULA_SEQ" => libc::NFULA_SEQ.to_string(),
"NFULA_UID" => libc::NFULA_UID.to_string(),
"NFULA_PREFIX" => libc::NFULA_PREFIX.to_string(),
"NFULA_PAYLOAD" => libc::NFULA_PAYLOAD.to_string(),
"NFULA_HWADDR" => libc::NFULA_HWADDR.to_string(),
"NFULA_IFINDEX_PHYSOUTDEV" => libc::NFULA_IFINDEX_PHYSOUTDEV.to_string(),
"NFULA_IFINDEX_PHYSINDEV" => libc::NFULA_IFINDEX_PHYSINDEV.to_string(),
"NFULA_IFINDEX_OUTDEV" => libc::NFULA_IFINDEX_OUTDEV.to_string(),
"NFULA_IFINDEX_INDEV" => libc::NFULA_IFINDEX_INDEV.to_string(),
"NFULA_TIMESTAMP" => libc::NFULA_TIMESTAMP.to_string(),
"NFULA_MARK" => libc::NFULA_MARK.to_string(),
"NFULA_PACKET_HDR" => libc::NFULA_PACKET_HDR.to_string(),
"NFULA_UNSPEC" => libc::NFULA_UNSPEC.to_string(),
"NFULNL_MSG_CONFIG" => libc::NFULNL_MSG_CONFIG.to_string(),
"NFULNL_MSG_PACKET" => libc::NFULNL_MSG_PACKET.to_string(),
"NFNL_MSG_BATCH_END" => libc::NFNL_MSG_BATCH_END.to_string(),
"NFNL_MSG_BATCH_BEGIN" => libc::NFNL_MSG_BATCH_BEGIN.to_string(),
"NFNL_SUBSYS_COUNT" => libc::NFNL_SUBSYS_COUNT.to_string(),
"NFNL_SUBSYS_NFT_COMPAT" => libc::NFNL_SUBSYS_NFT_COMPAT.to_string(),
"NFNL_SUBSYS_NFTABLES" => libc::NFNL_SUBSYS_NFTABLES.to_string(),
"NFNL_SUBSYS_CTHELPER" => libc::NFNL_SUBSYS_CTHELPER.to_string(),
"NFNL_SUBSYS_CTNETLINK_TIMEOUT" => libc::NFNL_SUBSYS_CTNETLINK_TIMEOUT.to_string(),
"NFNL_SUBSYS_ACCT" => libc::NFNL_SUBSYS_ACCT.to_string(),
"NFNL_SUBSYS_IPSET" => libc::NFNL_SUBSYS_IPSET.to_string(),
"NFNL_SUBSYS_OSF" => libc::NFNL_SUBSYS_OSF.to_string(),
"NFNL_SUBSYS_ULOG" => libc::NFNL_SUBSYS_ULOG.to_string(),
"NFNL_SUBSYS_QUEUE" => libc::NFNL_SUBSYS_QUEUE.to_string(),
"NFNL_SUBSYS_CTNETLINK_EXP" => libc::NFNL_SUBSYS_CTNETLINK_EXP.to_string(),
"NFNL_SUBSYS_CTNETLINK" => libc::NFNL_SUBSYS_CTNETLINK.to_string(),
"NFNL_SUBSYS_NONE" => libc::NFNL_SUBSYS_NONE.to_string(),
"NFNETLINK_V0" => libc::NFNETLINK_V0.to_string(),
"NFNLGRP_ACCT_QUOTA" => libc::NFNLGRP_ACCT_QUOTA.to_string(),
"NFNLGRP_NFTABLES" => libc::NFNLGRP_NFTABLES.to_string(),
"NFNLGRP_CONNTRACK_EXP_DESTROY" => libc::NFNLGRP_CONNTRACK_EXP_DESTROY.to_string(),
"NFNLGRP_CONNTRACK_EXP_UPDATE" => libc::NFNLGRP_CONNTRACK_EXP_UPDATE.to_string(),
"NFNLGRP_CONNTRACK_EXP_NEW" => libc::NFNLGRP_CONNTRACK_EXP_NEW.to_string(),
"NFNLGRP_CONNTRACK_DESTROY" => libc::NFNLGRP_CONNTRACK_DESTROY.to_string(),
"NFNLGRP_CONNTRACK_UPDATE" => libc::NFNLGRP_CONNTRACK_UPDATE.to_string(),
"NFNLGRP_CONNTRACK_NEW" => libc::NFNLGRP_CONNTRACK_NEW.to_string(),
"NFNLGRP_NONE" => libc::NFNLGRP_NONE.to_string(),
"NLMSG_MIN_TYPE" => libc::NLMSG_MIN_TYPE.to_string(),
"NLMSG_OVERRUN" => libc::NLMSG_OVERRUN.to_string(),
"NLMSG_DONE" => libc::NLMSG_DONE.to_string(),
"NLMSG_ERROR" => libc::NLMSG_ERROR.to_string(),
"NLMSG_NOOP" => libc::NLMSG_NOOP.to_string(),
"POSIX_SPAWN_SETSCHEDULER" => libc::POSIX_SPAWN_SETSCHEDULER.to_string(),
"POSIX_SPAWN_SETSCHEDPARAM" => libc::POSIX_SPAWN_SETSCHEDPARAM.to_string(),
"POSIX_SPAWN_SETSIGMASK" => libc::POSIX_SPAWN_SETSIGMASK.to_string(),
"POSIX_SPAWN_SETSIGDEF" => libc::POSIX_SPAWN_SETSIGDEF.to_string(),
"POSIX_SPAWN_SETPGROUP" => libc::POSIX_SPAWN_SETPGROUP.to_string(),
"POSIX_SPAWN_RESETIDS" => libc::POSIX_SPAWN_RESETIDS.to_string(),
"ETH_P_CAIF" => libc::ETH_P_CAIF.to_string(),
"ETH_P_IEEE802154" => libc::ETH_P_IEEE802154.to_string(),
"ETH_P_PHONET" => libc::ETH_P_PHONET.to_string(),
"ETH_P_TRAILER" => libc::ETH_P_TRAILER.to_string(),
"ETH_P_DSA" => libc::ETH_P_DSA.to_string(),
"ETH_P_ARCNET" => libc::ETH_P_ARCNET.to_string(),
"ETH_P_HDLC" => libc::ETH_P_HDLC.to_string(),
"ETH_P_ECONET" => libc::ETH_P_ECONET.to_string(),
"ETH_P_IRDA" => libc::ETH_P_IRDA.to_string(),
"ETH_P_CONTROL" => libc::ETH_P_CONTROL.to_string(),
"ETH_P_MOBITEX" => libc::ETH_P_MOBITEX.to_string(),
"ETH_P_TR_802_2" => libc::ETH_P_TR_802_2.to_string(),
"ETH_P_PPPTALK" => libc::ETH_P_PPPTALK.to_string(),
"ETH_P_CANFD" => libc::ETH_P_CANFD.to_string(),
"ETH_P_LOCALTALK" => libc::ETH_P_LOCALTALK.to_string(),
"ETH_P_PPP_MP" => libc::ETH_P_PPP_MP.to_string(),
"ETH_P_WAN_PPP" => libc::ETH_P_WAN_PPP.to_string(),
"ETH_P_DDCMP" => libc::ETH_P_DDCMP.to_string(),
"ETH_P_SNAP" => libc::ETH_P_SNAP.to_string(),
"ETH_P_802_2" => libc::ETH_P_802_2.to_string(),
"ETH_P_ALL" => libc::ETH_P_ALL.to_string(),
"ETH_P_AX25" => libc::ETH_P_AX25.to_string(),
"ETH_P_802_3" => libc::ETH_P_802_3.to_string(),
"ETH_P_802_3_MIN" => libc::ETH_P_802_3_MIN.to_string(),
"ETH_P_AF_IUCV" => libc::ETH_P_AF_IUCV.to_string(),
"ETH_P_EDSA" => libc::ETH_P_EDSA.to_string(),
"ETH_P_QINQ3" => libc::ETH_P_QINQ3.to_string(),
"ETH_P_QINQ2" => libc::ETH_P_QINQ2.to_string(),
"ETH_P_QINQ1" => libc::ETH_P_QINQ1.to_string(),
"ETH_P_LOOPBACK" => libc::ETH_P_LOOPBACK.to_string(),
"ETH_P_80221" => libc::ETH_P_80221.to_string(),
"ETH_P_FIP" => libc::ETH_P_FIP.to_string(),
"ETH_P_TDLS" => libc::ETH_P_TDLS.to_string(),
"ETH_P_FCOE" => libc::ETH_P_FCOE.to_string(),
"ETH_P_PRP" => libc::ETH_P_PRP.to_string(),
"ETH_P_1588" => libc::ETH_P_1588.to_string(),
"ETH_P_MVRP" => libc::ETH_P_MVRP.to_string(),
"ETH_P_8021AH" => libc::ETH_P_8021AH.to_string(),
"ETH_P_MACSEC" => libc::ETH_P_MACSEC.to_string(),
"ETH_P_TIPC" => libc::ETH_P_TIPC.to_string(),
"ETH_P_802_EX1" => libc::ETH_P_802_EX1.to_string(),
"ETH_P_8021AD" => libc::ETH_P_8021AD.to_string(),
"ETH_P_AOE" => libc::ETH_P_AOE.to_string(),
"ETH_P_PAE" => libc::ETH_P_PAE.to_string(),
"ETH_P_ATMFATE" => libc::ETH_P_ATMFATE.to_string(),
"ETH_P_LINK_CTL" => libc::ETH_P_LINK_CTL.to_string(),
"ETH_P_PPP_SES" => libc::ETH_P_PPP_SES.to_string(),
"ETH_P_PPP_DISC" => libc::ETH_P_PPP_DISC.to_string(),
"ETH_P_ATMMPOA" => libc::ETH_P_ATMMPOA.to_string(),
"ETH_P_MPLS_MC" => libc::ETH_P_MPLS_MC.to_string(),
"ETH_P_MPLS_UC" => libc::ETH_P_MPLS_UC.to_string(),
"ETH_P_WCCP" => libc::ETH_P_WCCP.to_string(),
"ETH_P_SLOW" => libc::ETH_P_SLOW.to_string(),
"ETH_P_PAUSE" => libc::ETH_P_PAUSE.to_string(),
"ETH_P_IPV6" => libc::ETH_P_IPV6.to_string(),
"ETH_P_IPX" => libc::ETH_P_IPX.to_string(),
"ETH_P_8021Q" => libc::ETH_P_8021Q.to_string(),
"ETH_P_AARP" => libc::ETH_P_AARP.to_string(),
"ETH_P_ATALK" => libc::ETH_P_ATALK.to_string(),
"ETH_P_RARP" => libc::ETH_P_RARP.to_string(),
"ETH_P_TEB" => libc::ETH_P_TEB.to_string(),
"ETH_P_SCA" => libc::ETH_P_SCA.to_string(),
"ETH_P_CUST" => libc::ETH_P_CUST.to_string(),
"ETH_P_DIAG" => libc::ETH_P_DIAG.to_string(),
"ETH_P_LAT" => libc::ETH_P_LAT.to_string(),
"ETH_P_DNA_RT" => libc::ETH_P_DNA_RT.to_string(),
"ETH_P_DNA_RC" => libc::ETH_P_DNA_RC.to_string(),
"ETH_P_DNA_DL" => libc::ETH_P_DNA_DL.to_string(),
"ETH_P_DEC" => libc::ETH_P_DEC.to_string(),
"ETH_P_BATMAN" => libc::ETH_P_BATMAN.to_string(),
"ETH_P_IEEEPUPAT" => libc::ETH_P_IEEEPUPAT.to_string(),
"ETH_P_IEEEPUP" => libc::ETH_P_IEEEPUP.to_string(),
"ETH_P_BPQ" => libc::ETH_P_BPQ.to_string(),
"ETH_P_ARP" => libc::ETH_P_ARP.to_string(),
"ETH_P_X25" => libc::ETH_P_X25.to_string(),
"ETH_P_IP" => libc::ETH_P_IP.to_string(),
"ETH_P_PUPAT" => libc::ETH_P_PUPAT.to_string(),
"ETH_P_PUP" => libc::ETH_P_PUP.to_string(),
"ETH_P_LOOP" => libc::ETH_P_LOOP.to_string(),
"ETH_FCS_LEN" => libc::ETH_FCS_LEN.to_string(),
"ETH_FRAME_LEN" => libc::ETH_FRAME_LEN.to_string(),
"ETH_DATA_LEN" => libc::ETH_DATA_LEN.to_string(),
"ETH_ZLEN" => libc::ETH_ZLEN.to_string(),
"ETH_HLEN" => libc::ETH_HLEN.to_string(),
"ETH_ALEN" => libc::ETH_ALEN.to_string(),
"PT_GNU_RELRO" => libc::PT_GNU_RELRO.to_string(),
"PT_GNU_STACK" => libc::PT_GNU_STACK.to_string(),
"PT_GNU_EH_FRAME" => libc::PT_GNU_EH_FRAME.to_string(),
"PT_LOOS" => libc::PT_LOOS.to_string(),
"PT_NUM" => libc::PT_NUM.to_string(),
"PT_TLS" => libc::PT_TLS.to_string(),
"PT_PHDR" => libc::PT_PHDR.to_string(),
"PT_SHLIB" => libc::PT_SHLIB.to_string(),
"PT_NOTE" => libc::PT_NOTE.to_string(),
"PT_INTERP" => libc::PT_INTERP.to_string(),
"PT_DYNAMIC" => libc::PT_DYNAMIC.to_string(),
"PT_LOAD" => libc::PT_LOAD.to_string(),
"PT_NULL" => libc::PT_NULL.to_string(),
"MFD_HUGETLB" => libc::MFD_HUGETLB.to_string(),
"MFD_ALLOW_SEALING" => libc::MFD_ALLOW_SEALING.to_string(),
"MFD_CLOEXEC" => libc::MFD_CLOEXEC.to_string(),
"CMSPAR" => libc::CMSPAR.to_string(),
"IUTF8" => libc::IUTF8.to_string(),
"IPV6_FLOWINFO_PRIORITY" => libc::IPV6_FLOWINFO_PRIORITY.to_string(),
"IPV6_FLOWINFO_FLOWLABEL" => libc::IPV6_FLOWINFO_FLOWLABEL.to_string(),
"IPV6_FLOWINFO_SEND" => libc::IPV6_FLOWINFO_SEND.to_string(),
"IPV6_FLOWLABEL_MGR" => libc::IPV6_FLOWLABEL_MGR.to_string(),
"IPV6_RECVORIGDSTADDR" => libc::IPV6_RECVORIGDSTADDR.to_string(),
"IPV6_ORIGDSTADDR" => libc::IPV6_ORIGDSTADDR.to_string(),
"IPV6_FLOWINFO" => libc::IPV6_FLOWINFO.to_string(),
"IP_RECVORIGDSTADDR" => libc::IP_RECVORIGDSTADDR.to_string(),
"IP_ORIGDSTADDR" => libc::IP_ORIGDSTADDR.to_string(),
"SO_ORIGINAL_DST" => libc::SO_ORIGINAL_DST.to_string(),
"ENOATTR" => libc::ENOATTR.to_string(),
"FALLOC_FL_UNSHARE_RANGE" => libc::FALLOC_FL_UNSHARE_RANGE.to_string(),
"FALLOC_FL_INSERT_RANGE" => libc::FALLOC_FL_INSERT_RANGE.to_string(),
"FALLOC_FL_ZERO_RANGE" => libc::FALLOC_FL_ZERO_RANGE.to_string(),
"FALLOC_FL_COLLAPSE_RANGE" => libc::FALLOC_FL_COLLAPSE_RANGE.to_string(),
"FALLOC_FL_PUNCH_HOLE" => libc::FALLOC_FL_PUNCH_HOLE.to_string(),
"FALLOC_FL_KEEP_SIZE" => libc::FALLOC_FL_KEEP_SIZE.to_string(),
"_POSIX_VDISABLE" => libc::_POSIX_VDISABLE.to_string(),
"XATTR_REPLACE" => libc::XATTR_REPLACE.to_string(),
"XATTR_CREATE" => libc::XATTR_CREATE.to_string(),
"TFD_TIMER_ABSTIME" => libc::TFD_TIMER_ABSTIME.to_string(),
"TFD_NONBLOCK" => libc::TFD_NONBLOCK.to_string(),
"TFD_CLOEXEC" => libc::TFD_CLOEXEC.to_string(),
"ITIMER_PROF" => libc::ITIMER_PROF.to_string(),
"ITIMER_VIRTUAL" => libc::ITIMER_VIRTUAL.to_string(),
"ITIMER_REAL" => libc::ITIMER_REAL.to_string(),
"SECCOMP_MODE_FILTER" => libc::SECCOMP_MODE_FILTER.to_string(),
"SECCOMP_MODE_STRICT" => libc::SECCOMP_MODE_STRICT.to_string(),
"SECCOMP_MODE_DISABLED" => libc::SECCOMP_MODE_DISABLED.to_string(),
"GRND_RANDOM" => libc::GRND_RANDOM.to_string(),
"GRND_NONBLOCK" => libc::GRND_NONBLOCK.to_string(),
"PR_CAP_AMBIENT_CLEAR_ALL" => libc::PR_CAP_AMBIENT_CLEAR_ALL.to_string(),
"PR_CAP_AMBIENT_LOWER" => libc::PR_CAP_AMBIENT_LOWER.to_string(),
"PR_CAP_AMBIENT_RAISE" => libc::PR_CAP_AMBIENT_RAISE.to_string(),
"PR_CAP_AMBIENT_IS_SET" => libc::PR_CAP_AMBIENT_IS_SET.to_string(),
"PR_CAP_AMBIENT" => libc::PR_CAP_AMBIENT.to_string(),
"PR_FP_MODE_FRE" => libc::PR_FP_MODE_FRE.to_string(),
"PR_FP_MODE_FR" => libc::PR_FP_MODE_FR.to_string(),
"PR_GET_FP_MODE" => libc::PR_GET_FP_MODE.to_string(),
"PR_SET_FP_MODE" => libc::PR_SET_FP_MODE.to_string(),
"PR_MPX_DISABLE_MANAGEMENT" => libc::PR_MPX_DISABLE_MANAGEMENT.to_string(),
"PR_MPX_ENABLE_MANAGEMENT" => libc::PR_MPX_ENABLE_MANAGEMENT.to_string(),
"PR_GET_THP_DISABLE" => libc::PR_GET_THP_DISABLE.to_string(),
"PR_SET_THP_DISABLE" => libc::PR_SET_THP_DISABLE.to_string(),
"PR_GET_TID_ADDRESS" => libc::PR_GET_TID_ADDRESS.to_string(),
"PR_GET_NO_NEW_PRIVS" => libc::PR_GET_NO_NEW_PRIVS.to_string(),
"PR_SET_NO_NEW_PRIVS" => libc::PR_SET_NO_NEW_PRIVS.to_string(),
"PR_GET_CHILD_SUBREAPER" => libc::PR_GET_CHILD_SUBREAPER.to_string(),
"PR_SET_CHILD_SUBREAPER" => libc::PR_SET_CHILD_SUBREAPER.to_string(),
"PR_SET_PTRACER" => libc::PR_SET_PTRACER.to_string(),
"PR_SET_MM_MAP_SIZE" => libc::PR_SET_MM_MAP_SIZE.to_string(),
"PR_SET_MM_MAP" => libc::PR_SET_MM_MAP.to_string(),
"PR_SET_MM_EXE_FILE" => libc::PR_SET_MM_EXE_FILE.to_string(),
"PR_SET_MM_AUXV" => libc::PR_SET_MM_AUXV.to_string(),
"PR_SET_MM_ENV_END" => libc::PR_SET_MM_ENV_END.to_string(),
"PR_SET_MM_ENV_START" => libc::PR_SET_MM_ENV_START.to_string(),
"PR_SET_MM_ARG_END" => libc::PR_SET_MM_ARG_END.to_string(),
"PR_SET_MM_ARG_START" => libc::PR_SET_MM_ARG_START.to_string(),
"PR_SET_MM_BRK" => libc::PR_SET_MM_BRK.to_string(),
"PR_SET_MM_START_BRK" => libc::PR_SET_MM_START_BRK.to_string(),
"PR_SET_MM_START_STACK" => libc::PR_SET_MM_START_STACK.to_string(),
"PR_SET_MM_END_DATA" => libc::PR_SET_MM_END_DATA.to_string(),
"PR_SET_MM_START_DATA" => libc::PR_SET_MM_START_DATA.to_string(),
"PR_SET_MM_END_CODE" => libc::PR_SET_MM_END_CODE.to_string(),
"PR_SET_MM_START_CODE" => libc::PR_SET_MM_START_CODE.to_string(),
"PR_SET_MM" => libc::PR_SET_MM.to_string(),
"PR_MCE_KILL_GET" => libc::PR_MCE_KILL_GET.to_string(),
"PR_MCE_KILL_DEFAULT" => libc::PR_MCE_KILL_DEFAULT.to_string(),
"PR_MCE_KILL_EARLY" => libc::PR_MCE_KILL_EARLY.to_string(),
"PR_MCE_KILL_LATE" => libc::PR_MCE_KILL_LATE.to_string(),
"PR_MCE_KILL_SET" => libc::PR_MCE_KILL_SET.to_string(),
"PR_MCE_KILL_CLEAR" => libc::PR_MCE_KILL_CLEAR.to_string(),
"PR_MCE_KILL" => libc::PR_MCE_KILL.to_string(),
"PR_TASK_PERF_EVENTS_ENABLE" => libc::PR_TASK_PERF_EVENTS_ENABLE.to_string(),
"PR_TASK_PERF_EVENTS_DISABLE" => libc::PR_TASK_PERF_EVENTS_DISABLE.to_string(),
"PR_GET_TIMERSLACK" => libc::PR_GET_TIMERSLACK.to_string(),
"PR_SET_TIMERSLACK" => libc::PR_SET_TIMERSLACK.to_string(),
"PR_SET_SECUREBITS" => libc::PR_SET_SECUREBITS.to_string(),
"PR_GET_SECUREBITS" => libc::PR_GET_SECUREBITS.to_string(),
"PR_TSC_SIGSEGV" => libc::PR_TSC_SIGSEGV.to_string(),
"PR_TSC_ENABLE" => libc::PR_TSC_ENABLE.to_string(),
"PR_SET_TSC" => libc::PR_SET_TSC.to_string(),
"PR_GET_TSC" => libc::PR_GET_TSC.to_string(),
"PR_CAPBSET_DROP" => libc::PR_CAPBSET_DROP.to_string(),
"PR_CAPBSET_READ" => libc::PR_CAPBSET_READ.to_string(),
"PR_SET_SECCOMP" => libc::PR_SET_SECCOMP.to_string(),
"PR_GET_SECCOMP" => libc::PR_GET_SECCOMP.to_string(),
"PR_ENDIAN_PPC_LITTLE" => libc::PR_ENDIAN_PPC_LITTLE.to_string(),
"PR_ENDIAN_LITTLE" => libc::PR_ENDIAN_LITTLE.to_string(),
"PR_ENDIAN_BIG" => libc::PR_ENDIAN_BIG.to_string(),
"PR_SET_ENDIAN" => libc::PR_SET_ENDIAN.to_string(),
"PR_GET_ENDIAN" => libc::PR_GET_ENDIAN.to_string(),
"PR_GET_NAME" => libc::PR_GET_NAME.to_string(),
"PR_SET_NAME" => libc::PR_SET_NAME.to_string(),
"PR_TIMING_TIMESTAMP" => libc::PR_TIMING_TIMESTAMP.to_string(),
"PR_TIMING_STATISTICAL" => libc::PR_TIMING_STATISTICAL.to_string(),
"PR_SET_TIMING" => libc::PR_SET_TIMING.to_string(),
"PR_GET_TIMING" => libc::PR_GET_TIMING.to_string(),
"PR_FP_EXC_PRECISE" => libc::PR_FP_EXC_PRECISE.to_string(),
"PR_FP_EXC_ASYNC" => libc::PR_FP_EXC_ASYNC.to_string(),
"PR_FP_EXC_NONRECOV" => libc::PR_FP_EXC_NONRECOV.to_string(),
"PR_FP_EXC_DISABLED" => libc::PR_FP_EXC_DISABLED.to_string(),
"PR_FP_EXC_INV" => libc::PR_FP_EXC_INV.to_string(),
"PR_FP_EXC_RES" => libc::PR_FP_EXC_RES.to_string(),
"PR_FP_EXC_UND" => libc::PR_FP_EXC_UND.to_string(),
"PR_FP_EXC_OVF" => libc::PR_FP_EXC_OVF.to_string(),
"PR_FP_EXC_DIV" => libc::PR_FP_EXC_DIV.to_string(),
"PR_FP_EXC_SW_ENABLE" => libc::PR_FP_EXC_SW_ENABLE.to_string(),
"PR_SET_FPEXC" => libc::PR_SET_FPEXC.to_string(),
"PR_GET_FPEXC" => libc::PR_GET_FPEXC.to_string(),
"PR_FPEMU_SIGFPE" => libc::PR_FPEMU_SIGFPE.to_string(),
"PR_FPEMU_NOPRINT" => libc::PR_FPEMU_NOPRINT.to_string(),
"PR_SET_FPEMU" => libc::PR_SET_FPEMU.to_string(),
"PR_GET_FPEMU" => libc::PR_GET_FPEMU.to_string(),
"PR_SET_KEEPCAPS" => libc::PR_SET_KEEPCAPS.to_string(),
"PR_GET_KEEPCAPS" => libc::PR_GET_KEEPCAPS.to_string(),
"PR_UNALIGN_SIGBUS" => libc::PR_UNALIGN_SIGBUS.to_string(),
"PR_UNALIGN_NOPRINT" => libc::PR_UNALIGN_NOPRINT.to_string(),
"PR_SET_UNALIGN" => libc::PR_SET_UNALIGN.to_string(),
"PR_GET_UNALIGN" => libc::PR_GET_UNALIGN.to_string(),
"PR_SET_DUMPABLE" => libc::PR_SET_DUMPABLE.to_string(),
"PR_GET_DUMPABLE" => libc::PR_GET_DUMPABLE.to_string(),
"PR_GET_PDEATHSIG" => libc::PR_GET_PDEATHSIG.to_string(),
"PR_SET_PDEATHSIG" => libc::PR_SET_PDEATHSIG.to_string(),
"MREMAP_FIXED" => libc::MREMAP_FIXED.to_string(),
"MREMAP_MAYMOVE" => libc::MREMAP_MAYMOVE.to_string(),
"LIO_NOWAIT" => libc::LIO_NOWAIT.to_string(),
"LIO_WAIT" => libc::LIO_WAIT.to_string(),
"LIO_NOP" => libc::LIO_NOP.to_string(),
"LIO_WRITE" => libc::LIO_WRITE.to_string(),
"LIO_READ" => libc::LIO_READ.to_string(),
"AIO_ALLDONE" => libc::AIO_ALLDONE.to_string(),
"AIO_NOTCANCELED" => libc::AIO_NOTCANCELED.to_string(),
"AIO_CANCELED" => libc::AIO_CANCELED.to_string(),
"SYNC_FILE_RANGE_WAIT_AFTER" => libc::SYNC_FILE_RANGE_WAIT_AFTER.to_string(),
"SYNC_FILE_RANGE_WRITE" => libc::SYNC_FILE_RANGE_WRITE.to_string(),
"SYNC_FILE_RANGE_WAIT_BEFORE" => libc::SYNC_FILE_RANGE_WAIT_BEFORE.to_string(),
"NI_DGRAM" => libc::NI_DGRAM.to_string(),
"NI_NAMEREQD" => libc::NI_NAMEREQD.to_string(),
"NI_NOFQDN" => libc::NI_NOFQDN.to_string(),
"NI_NUMERICSERV" => libc::NI_NUMERICSERV.to_string(),
"NI_NUMERICHOST" => libc::NI_NUMERICHOST.to_string(),
"EAI_OVERFLOW" => libc::EAI_OVERFLOW.to_string(),
"EAI_SYSTEM" => libc::EAI_SYSTEM.to_string(),
"EAI_MEMORY" => libc::EAI_MEMORY.to_string(),
"EAI_SERVICE" => libc::EAI_SERVICE.to_string(),
"EAI_SOCKTYPE" => libc::EAI_SOCKTYPE.to_string(),
"EAI_FAMILY" => libc::EAI_FAMILY.to_string(),
"EAI_NODATA" => libc::EAI_NODATA.to_string(),
"EAI_FAIL" => libc::EAI_FAIL.to_string(),
"EAI_AGAIN" => libc::EAI_AGAIN.to_string(),
"EAI_NONAME" => libc::EAI_NONAME.to_string(),
"EAI_BADFLAGS" => libc::EAI_BADFLAGS.to_string(),
"AI_NUMERICSERV" => libc::AI_NUMERICSERV.to_string(),
"AI_ADDRCONFIG" => libc::AI_ADDRCONFIG.to_string(),
"AI_ALL" => libc::AI_ALL.to_string(),
"AI_V4MAPPED" => libc::AI_V4MAPPED.to_string(),
"AI_NUMERICHOST" => libc::AI_NUMERICHOST.to_string(),
"AI_CANONNAME" => libc::AI_CANONNAME.to_string(),
"AI_PASSIVE" => libc::AI_PASSIVE.to_string(),
"RB_KEXEC" => libc::RB_KEXEC.to_string(),
"RB_SW_SUSPEND" => libc::RB_SW_SUSPEND.to_string(),
"RB_POWER_OFF" => libc::RB_POWER_OFF.to_string(),
"RB_DISABLE_CAD" => libc::RB_DISABLE_CAD.to_string(),
"RB_ENABLE_CAD" => libc::RB_ENABLE_CAD.to_string(),
"RB_HALT_SYSTEM" => libc::RB_HALT_SYSTEM.to_string(),
"RB_AUTOBOOT" => libc::RB_AUTOBOOT.to_string(),
"LOG_NFACILITIES" => libc::LOG_NFACILITIES.to_string(),
"EFD_SEMAPHORE" => libc::EFD_SEMAPHORE.to_string(),
"QFMT_VFS_V1" => libc::QFMT_VFS_V1.to_string(),
"QFMT_VFS_V0" => libc::QFMT_VFS_V0.to_string(),
"QFMT_VFS_OLD" => libc::QFMT_VFS_OLD.to_string(),
"EPOLLONESHOT" => libc::EPOLLONESHOT.to_string(),
"EPOLLEXCLUSIVE" => libc::EPOLLEXCLUSIVE.to_string(),
"EPOLLRDHUP" => libc::EPOLLRDHUP.to_string(),
"SHM_NORESERVE" => libc::SHM_NORESERVE.to_string(),
"SHM_HUGETLB" => libc::SHM_HUGETLB.to_string(),
"SHM_UNLOCK" => libc::SHM_UNLOCK.to_string(),
"SHM_LOCK" => libc::SHM_LOCK.to_string(),
"SHM_EXEC" => libc::SHM_EXEC.to_string(),
"SHM_REMAP" => libc::SHM_REMAP.to_string(),
"SHM_RND" => libc::SHM_RND.to_string(),
"SHM_RDONLY" => libc::SHM_RDONLY.to_string(),
"SHM_W" => libc::SHM_W.to_string(),
"SHM_R" => libc::SHM_R.to_string(),
"MSG_COPY" => libc::MSG_COPY.to_string(),
"MSG_EXCEPT" => libc::MSG_EXCEPT.to_string(),
"MSG_NOERROR" => libc::MSG_NOERROR.to_string(),
"MSG_INFO" => libc::MSG_INFO.to_string(),
"MSG_STAT" => libc::MSG_STAT.to_string(),
"IPC_INFO" => libc::IPC_INFO.to_string(),
"IPC_STAT" => libc::IPC_STAT.to_string(),
"IPC_SET" => libc::IPC_SET.to_string(),
"IPC_RMID" => libc::IPC_RMID.to_string(),
"IPC_NOWAIT" => libc::IPC_NOWAIT.to_string(),
"IPC_EXCL" => libc::IPC_EXCL.to_string(),
"IPC_CREAT" => libc::IPC_CREAT.to_string(),
"IPC_PRIVATE" => libc::IPC_PRIVATE.to_string(),
"PF_XDP" => libc::PF_XDP.to_string(),
"PF_VSOCK" => libc::PF_VSOCK.to_string(),
"PF_NFC" => libc::PF_NFC.to_string(),
"PF_MPLS" => libc::PF_MPLS.to_string(),
"PF_IB" => libc::PF_IB.to_string(),
"AF_XDP" => libc::AF_XDP.to_string(),
"AF_VSOCK" => libc::AF_VSOCK.to_string(),
"AF_NFC" => libc::AF_NFC.to_string(),
"AF_MPLS" => libc::AF_MPLS.to_string(),
"AF_IB" => libc::AF_IB.to_string(),
"IP_UNICAST_IF" => libc::IP_UNICAST_IF.to_string(),
"IP_MULTICAST_ALL" => libc::IP_MULTICAST_ALL.to_string(),
"MCAST_MSFILTER" => libc::MCAST_MSFILTER.to_string(),
"MCAST_LEAVE_SOURCE_GROUP" => libc::MCAST_LEAVE_SOURCE_GROUP.to_string(),
"MCAST_JOIN_SOURCE_GROUP" => libc::MCAST_JOIN_SOURCE_GROUP.to_string(),
"MCAST_LEAVE_GROUP" => libc::MCAST_LEAVE_GROUP.to_string(),
"MCAST_UNBLOCK_SOURCE" => libc::MCAST_UNBLOCK_SOURCE.to_string(),
"MCAST_BLOCK_SOURCE" => libc::MCAST_BLOCK_SOURCE.to_string(),
"MCAST_JOIN_GROUP" => libc::MCAST_JOIN_GROUP.to_string(),
"IP_MSFILTER" => libc::IP_MSFILTER.to_string(),
"IPPROTO_MAX" => libc::IPPROTO_MAX.to_string(),
"IPPROTO_RAW" => libc::IPPROTO_RAW.to_string(),
"IPPROTO_MPLS" => libc::IPPROTO_MPLS.to_string(),
"IPPROTO_UDPLITE" => libc::IPPROTO_UDPLITE.to_string(),
"IPPROTO_MH" => libc::IPPROTO_MH.to_string(),
"IPPROTO_SCTP" => libc::IPPROTO_SCTP.to_string(),
"IPPROTO_COMP" => libc::IPPROTO_COMP.to_string(),
"IPPROTO_PIM" => libc::IPPROTO_PIM.to_string(),
"IPPROTO_ENCAP" => libc::IPPROTO_ENCAP.to_string(),
"IPPROTO_BEETPH" => libc::IPPROTO_BEETPH.to_string(),
"IPPROTO_MTP" => libc::IPPROTO_MTP.to_string(),
"IPPROTO_DSTOPTS" => libc::IPPROTO_DSTOPTS.to_string(),
"IPPROTO_NONE" => libc::IPPROTO_NONE.to_string(),
"IPPROTO_AH" => libc::IPPROTO_AH.to_string(),
"IPPROTO_ESP" => libc::IPPROTO_ESP.to_string(),
"IPPROTO_GRE" => libc::IPPROTO_GRE.to_string(),
"IPPROTO_RSVP" => libc::IPPROTO_RSVP.to_string(),
"IPPROTO_FRAGMENT" => libc::IPPROTO_FRAGMENT.to_string(),
"IPPROTO_ROUTING" => libc::IPPROTO_ROUTING.to_string(),
"IPPROTO_DCCP" => libc::IPPROTO_DCCP.to_string(),
"IPPROTO_TP" => libc::IPPROTO_TP.to_string(),
"IPPROTO_IDP" => libc::IPPROTO_IDP.to_string(),
"IPPROTO_PUP" => libc::IPPROTO_PUP.to_string(),
"IPPROTO_EGP" => libc::IPPROTO_EGP.to_string(),
"IPPROTO_IPIP" => libc::IPPROTO_IPIP.to_string(),
"IPPROTO_IGMP" => libc::IPPROTO_IGMP.to_string(),
"IPPROTO_HOPOPTS" => libc::IPPROTO_HOPOPTS.to_string(),
"SCHED_RESET_ON_FORK" => libc::SCHED_RESET_ON_FORK.to_string(),
"SCHED_IDLE" => libc::SCHED_IDLE.to_string(),
"SCHED_BATCH" => libc::SCHED_BATCH.to_string(),
"SCHED_RR" => libc::SCHED_RR.to_string(),
"SCHED_FIFO" => libc::SCHED_FIFO.to_string(),
"SCHED_OTHER" => libc::SCHED_OTHER.to_string(),
"RENAME_WHITEOUT" => libc::RENAME_WHITEOUT.to_string(),
"RENAME_EXCHANGE" => libc::RENAME_EXCHANGE.to_string(),
"RENAME_NOREPLACE" => libc::RENAME_NOREPLACE.to_string(),
"__SIZEOF_PTHREAD_COND_T" => libc::__SIZEOF_PTHREAD_COND_T.to_string(),
"PTHREAD_PROCESS_SHARED" => libc::PTHREAD_PROCESS_SHARED.to_string(),
"PTHREAD_PROCESS_PRIVATE" => libc::PTHREAD_PROCESS_PRIVATE.to_string(),
"PTHREAD_MUTEX_DEFAULT" => libc::PTHREAD_MUTEX_DEFAULT.to_string(),
"PTHREAD_MUTEX_ERRORCHECK" => libc::PTHREAD_MUTEX_ERRORCHECK.to_string(),
"PTHREAD_MUTEX_RECURSIVE" => libc::PTHREAD_MUTEX_RECURSIVE.to_string(),
"PTHREAD_MUTEX_NORMAL" => libc::PTHREAD_MUTEX_NORMAL.to_string(),
"TCP_MD5SIG" => libc::TCP_MD5SIG.to_string(),
"AT_EACCESS" => libc::AT_EACCESS.to_string(),
"RTLD_NOW" => libc::RTLD_NOW.to_string(),
"RTLD_NODELETE" => libc::RTLD_NODELETE.to_string(),
"ST_NODIRATIME" => libc::ST_NODIRATIME.to_string(),
"ST_NOATIME" => libc::ST_NOATIME.to_string(),
"ST_IMMUTABLE" => libc::ST_IMMUTABLE.to_string(),
"ST_APPEND" => libc::ST_APPEND.to_string(),
"ST_WRITE" => libc::ST_WRITE.to_string(),
"ST_MANDLOCK" => libc::ST_MANDLOCK.to_string(),
"ST_SYNCHRONOUS" => libc::ST_SYNCHRONOUS.to_string(),
"ST_NOEXEC" => libc::ST_NOEXEC.to_string(),
"ST_NODEV" => libc::ST_NODEV.to_string(),
"ST_NOSUID" => libc::ST_NOSUID.to_string(),
"ST_RDONLY" => libc::ST_RDONLY.to_string(),
"IFF_NOFILTER" => libc::IFF_NOFILTER.to_string(),
"IFF_PERSIST" => libc::IFF_PERSIST.to_string(),
"IFF_DETACH_QUEUE" => libc::IFF_DETACH_QUEUE.to_string(),
"IFF_ATTACH_QUEUE" => libc::IFF_ATTACH_QUEUE.to_string(),
"IFF_MULTI_QUEUE" => libc::IFF_MULTI_QUEUE.to_string(),
"IFF_TUN_EXCL" => libc::IFF_TUN_EXCL.to_string(),
"IFF_VNET_HDR" => libc::IFF_VNET_HDR.to_string(),
"IFF_ONE_QUEUE" => libc::IFF_ONE_QUEUE.to_string(),
"TUN_TYPE_MASK" => libc::TUN_TYPE_MASK.to_string(),
"TUN_TAP_DEV" => libc::TUN_TAP_DEV.to_string(),
"TUN_TUN_DEV" => libc::TUN_TUN_DEV.to_string(),
"TUN_READQ_SIZE" => libc::TUN_READQ_SIZE.to_string(),
"IFF_NO_PI" => libc::IFF_NO_PI.to_string(),
"IFF_TAP" => libc::IFF_TAP.to_string(),
"IFF_TUN" => libc::IFF_TUN.to_string(),
"IFLA_INFO_SLAVE_DATA" => libc::IFLA_INFO_SLAVE_DATA.to_string(),
"IFLA_INFO_SLAVE_KIND" => libc::IFLA_INFO_SLAVE_KIND.to_string(),
"IFLA_INFO_XSTATS" => libc::IFLA_INFO_XSTATS.to_string(),
"IFLA_INFO_DATA" => libc::IFLA_INFO_DATA.to_string(),
"IFLA_INFO_KIND" => libc::IFLA_INFO_KIND.to_string(),
"IFLA_INFO_UNSPEC" => libc::IFLA_INFO_UNSPEC.to_string(),
"IFLA_PROTO_DOWN" => libc::IFLA_PROTO_DOWN.to_string(),
"IFLA_PHYS_PORT_NAME" => libc::IFLA_PHYS_PORT_NAME.to_string(),
"IFLA_LINK_NETNSID" => libc::IFLA_LINK_NETNSID.to_string(),
"IFLA_PHYS_SWITCH_ID" => libc::IFLA_PHYS_SWITCH_ID.to_string(),
"IFLA_CARRIER_CHANGES" => libc::IFLA_CARRIER_CHANGES.to_string(),
"IFLA_PHYS_PORT_ID" => libc::IFLA_PHYS_PORT_ID.to_string(),
"IFLA_CARRIER" => libc::IFLA_CARRIER.to_string(),
"IFLA_NUM_RX_QUEUES" => libc::IFLA_NUM_RX_QUEUES.to_string(),
"IFLA_NUM_TX_QUEUES" => libc::IFLA_NUM_TX_QUEUES.to_string(),
"IFLA_PROMISCUITY" => libc::IFLA_PROMISCUITY.to_string(),
"IFLA_EXT_MASK" => libc::IFLA_EXT_MASK.to_string(),
"IFLA_NET_NS_FD" => libc::IFLA_NET_NS_FD.to_string(),
"IFLA_GROUP" => libc::IFLA_GROUP.to_string(),
"IFLA_AF_SPEC" => libc::IFLA_AF_SPEC.to_string(),
"IFLA_PORT_SELF" => libc::IFLA_PORT_SELF.to_string(),
"IFLA_VF_PORTS" => libc::IFLA_VF_PORTS.to_string(),
"IFLA_STATS64" => libc::IFLA_STATS64.to_string(),
"IFLA_VFINFO_LIST" => libc::IFLA_VFINFO_LIST.to_string(),
"IFLA_NUM_VF" => libc::IFLA_NUM_VF.to_string(),
"IFLA_IFALIAS" => libc::IFLA_IFALIAS.to_string(),
"IFLA_NET_NS_PID" => libc::IFLA_NET_NS_PID.to_string(),
"IFLA_LINKINFO" => libc::IFLA_LINKINFO.to_string(),
"IFLA_LINKMODE" => libc::IFLA_LINKMODE.to_string(),
"IFLA_OPERSTATE" => libc::IFLA_OPERSTATE.to_string(),
"IFLA_WEIGHT" => libc::IFLA_WEIGHT.to_string(),
"IFLA_MAP" => libc::IFLA_MAP.to_string(),
"IFLA_TXQLEN" => libc::IFLA_TXQLEN.to_string(),
"IFLA_PROTINFO" => libc::IFLA_PROTINFO.to_string(),
"IFLA_WIRELESS" => libc::IFLA_WIRELESS.to_string(),
"IFLA_MASTER" => libc::IFLA_MASTER.to_string(),
"IFLA_PRIORITY" => libc::IFLA_PRIORITY.to_string(),
"IFLA_COST" => libc::IFLA_COST.to_string(),
"IFLA_STATS" => libc::IFLA_STATS.to_string(),
"IFLA_QDISC" => libc::IFLA_QDISC.to_string(),
"IFLA_LINK" => libc::IFLA_LINK.to_string(),
"IFLA_MTU" => libc::IFLA_MTU.to_string(),
"IFLA_IFNAME" => libc::IFLA_IFNAME.to_string(),
"IFLA_BROADCAST" => libc::IFLA_BROADCAST.to_string(),
"IFLA_ADDRESS" => libc::IFLA_ADDRESS.to_string(),
"IFLA_UNSPEC" => libc::IFLA_UNSPEC.to_string(),
"IFA_F_PERMANENT" => libc::IFA_F_PERMANENT.to_string(),
"IFA_F_TENTATIVE" => libc::IFA_F_TENTATIVE.to_string(),
"IFA_F_DEPRECATED" => libc::IFA_F_DEPRECATED.to_string(),
"IFA_F_HOMEADDRESS" => libc::IFA_F_HOMEADDRESS.to_string(),
"IFA_F_DADFAILED" => libc::IFA_F_DADFAILED.to_string(),
"IFA_F_OPTIMISTIC" => libc::IFA_F_OPTIMISTIC.to_string(),
"IFA_F_NODAD" => libc::IFA_F_NODAD.to_string(),
"IFA_F_TEMPORARY" => libc::IFA_F_TEMPORARY.to_string(),
"IFA_F_SECONDARY" => libc::IFA_F_SECONDARY.to_string(),
"IFA_MULTICAST" => libc::IFA_MULTICAST.to_string(),
"IFA_CACHEINFO" => libc::IFA_CACHEINFO.to_string(),
"IFA_ANYCAST" => libc::IFA_ANYCAST.to_string(),
"IFA_BROADCAST" => libc::IFA_BROADCAST.to_string(),
"IFA_LABEL" => libc::IFA_LABEL.to_string(),
"IFA_LOCAL" => libc::IFA_LOCAL.to_string(),
"IFA_ADDRESS" => libc::IFA_ADDRESS.to_string(),
"IFA_UNSPEC" => libc::IFA_UNSPEC.to_string(),
"IFF_ECHO" => libc::IFF_ECHO.to_string(),
"IFF_DORMANT" => libc::IFF_DORMANT.to_string(),
"IFF_LOWER_UP" => libc::IFF_LOWER_UP.to_string(),
"F_SEAL_FUTURE_WRITE" => libc::F_SEAL_FUTURE_WRITE.to_string(),
"F_ULOCK" => libc::F_ULOCK.to_string(),
"F_TLOCK" => libc::F_TLOCK.to_string(),
"F_TEST" => libc::F_TEST.to_string(),
"F_LOCK" => libc::F_LOCK.to_string(),
"S_IREAD" => libc::S_IREAD.to_string(),
"S_IWRITE" => libc::S_IWRITE.to_string(),
"S_IEXEC" => libc::S_IEXEC.to_string(),
"POSIX_MADV_WILLNEED" => libc::POSIX_MADV_WILLNEED.to_string(),
"POSIX_MADV_SEQUENTIAL" => libc::POSIX_MADV_SEQUENTIAL.to_string(),
"POSIX_MADV_RANDOM" => libc::POSIX_MADV_RANDOM.to_string(),
"POSIX_MADV_NORMAL" => libc::POSIX_MADV_NORMAL.to_string(),
"GLOB_NOMATCH" => libc::GLOB_NOMATCH.to_string(),
"GLOB_ABORTED" => libc::GLOB_ABORTED.to_string(),
"GLOB_NOSPACE" => libc::GLOB_NOSPACE.to_string(),
"GLOB_NOESCAPE" => libc::GLOB_NOESCAPE.to_string(),
"GLOB_APPEND" => libc::GLOB_APPEND.to_string(),
"GLOB_NOCHECK" => libc::GLOB_NOCHECK.to_string(),
"GLOB_DOOFFS" => libc::GLOB_DOOFFS.to_string(),
"GLOB_NOSORT" => libc::GLOB_NOSORT.to_string(),
"GLOB_MARK" => libc::GLOB_MARK.to_string(),
"GLOB_ERR" => libc::GLOB_ERR.to_string(),
"RLIM_SAVED_CUR" => libc::RLIM_SAVED_CUR.to_string(),
"RLIM_SAVED_MAX" => libc::RLIM_SAVED_MAX.to_string(),
"_SC_THREAD_ROBUST_PRIO_PROTECT" => libc::_SC_THREAD_ROBUST_PRIO_PROTECT.to_string(),
"_SC_THREAD_ROBUST_PRIO_INHERIT" => libc::_SC_THREAD_ROBUST_PRIO_INHERIT.to_string(),
"_SC_XOPEN_STREAMS" => libc::_SC_XOPEN_STREAMS.to_string(),
"_SC_TRACE_USER_EVENT_MAX" => libc::_SC_TRACE_USER_EVENT_MAX.to_string(),
"_SC_TRACE_SYS_MAX" => libc::_SC_TRACE_SYS_MAX.to_string(),
"_SC_TRACE_NAME_MAX" => libc::_SC_TRACE_NAME_MAX.to_string(),
"_SC_TRACE_EVENT_NAME_MAX" => libc::_SC_TRACE_EVENT_NAME_MAX.to_string(),
"_SC_SS_REPL_MAX" => libc::_SC_SS_REPL_MAX.to_string(),
"_SC_V7_LPBIG_OFFBIG" => libc::_SC_V7_LPBIG_OFFBIG.to_string(),
"_SC_V7_LP64_OFF64" => libc::_SC_V7_LP64_OFF64.to_string(),
"_SC_V7_ILP32_OFFBIG" => libc::_SC_V7_ILP32_OFFBIG.to_string(),
"_SC_V7_ILP32_OFF32" => libc::_SC_V7_ILP32_OFF32.to_string(),
"_SC_RAW_SOCKETS" => libc::_SC_RAW_SOCKETS.to_string(),
"_SC_IPV6" => libc::_SC_IPV6.to_string(),
"_SC_TRACE_LOG" => libc::_SC_TRACE_LOG.to_string(),
"_SC_TRACE_INHERIT" => libc::_SC_TRACE_INHERIT.to_string(),
"_SC_TRACE_EVENT_FILTER" => libc::_SC_TRACE_EVENT_FILTER.to_string(),
"_SC_TRACE" => libc::_SC_TRACE.to_string(),
"_SC_HOST_NAME_MAX" => libc::_SC_HOST_NAME_MAX.to_string(),
"_SC_V6_LPBIG_OFFBIG" => libc::_SC_V6_LPBIG_OFFBIG.to_string(),
"_SC_V6_LP64_OFF64" => libc::_SC_V6_LP64_OFF64.to_string(),
"_SC_V6_ILP32_OFFBIG" => libc::_SC_V6_ILP32_OFFBIG.to_string(),
"_SC_V6_ILP32_OFF32" => libc::_SC_V6_ILP32_OFF32.to_string(),
"_SC_2_PBS_CHECKPOINT" => libc::_SC_2_PBS_CHECKPOINT.to_string(),
"_SC_STREAMS" => libc::_SC_STREAMS.to_string(),
"_SC_SYMLOOP_MAX" => libc::_SC_SYMLOOP_MAX.to_string(),
"_SC_2_PBS_TRACK" => libc::_SC_2_PBS_TRACK.to_string(),
"_SC_2_PBS_MESSAGE" => libc::_SC_2_PBS_MESSAGE.to_string(),
"_SC_2_PBS_LOCATE" => libc::_SC_2_PBS_LOCATE.to_string(),
"_SC_2_PBS_ACCOUNTING" => libc::_SC_2_PBS_ACCOUNTING.to_string(),
"_SC_2_PBS" => libc::_SC_2_PBS.to_string(),
"_SC_TYPED_MEMORY_OBJECTS" => libc::_SC_TYPED_MEMORY_OBJECTS.to_string(),
"_SC_TIMEOUTS" => libc::_SC_TIMEOUTS.to_string(),
"_SC_THREAD_SPORADIC_SERVER" => libc::_SC_THREAD_SPORADIC_SERVER.to_string(),
"_SC_SPORADIC_SERVER" => libc::_SC_SPORADIC_SERVER.to_string(),
"_SC_SPAWN" => libc::_SC_SPAWN.to_string(),
"_SC_SHELL" => libc::_SC_SHELL.to_string(),
"_SC_REGEXP" => libc::_SC_REGEXP.to_string(),
"_SC_SPIN_LOCKS" => libc::_SC_SPIN_LOCKS.to_string(),
"_SC_READER_WRITER_LOCKS" => libc::_SC_READER_WRITER_LOCKS.to_string(),
"_SC_MONOTONIC_CLOCK" => libc::_SC_MONOTONIC_CLOCK.to_string(),
"_SC_THREAD_CPUTIME" => libc::_SC_THREAD_CPUTIME.to_string(),
"_SC_CPUTIME" => libc::_SC_CPUTIME.to_string(),
"_SC_CLOCK_SELECTION" => libc::_SC_CLOCK_SELECTION.to_string(),
"_SC_BARRIERS" => libc::_SC_BARRIERS.to_string(),
"_SC_ADVISORY_INFO" => libc::_SC_ADVISORY_INFO.to_string(),
"_SC_XOPEN_REALTIME_THREADS" => libc::_SC_XOPEN_REALTIME_THREADS.to_string(),
"_SC_XOPEN_REALTIME" => libc::_SC_XOPEN_REALTIME.to_string(),
"_SC_XOPEN_LEGACY" => libc::_SC_XOPEN_LEGACY.to_string(),
"_SC_XBS5_LPBIG_OFFBIG" => libc::_SC_XBS5_LPBIG_OFFBIG.to_string(),
"_SC_XBS5_LP64_OFF64" => libc::_SC_XBS5_LP64_OFF64.to_string(),
"_SC_XBS5_ILP32_OFFBIG" => libc::_SC_XBS5_ILP32_OFFBIG.to_string(),
"_SC_XBS5_ILP32_OFF32" => libc::_SC_XBS5_ILP32_OFF32.to_string(),
"_SC_NZERO" => libc::_SC_NZERO.to_string(),
"_SC_XOPEN_XPG4" => libc::_SC_XOPEN_XPG4.to_string(),
"_SC_XOPEN_XPG3" => libc::_SC_XOPEN_XPG3.to_string(),
"_SC_XOPEN_XPG2" => libc::_SC_XOPEN_XPG2.to_string(),
"_SC_2_UPE" => libc::_SC_2_UPE.to_string(),
"_SC_2_CHAR_TERM" => libc::_SC_2_CHAR_TERM.to_string(),
"_SC_XOPEN_SHM" => libc::_SC_XOPEN_SHM.to_string(),
"_SC_XOPEN_ENH_I18N" => libc::_SC_XOPEN_ENH_I18N.to_string(),
"_SC_XOPEN_CRYPT" => libc::_SC_XOPEN_CRYPT.to_string(),
"_SC_XOPEN_UNIX" => libc::_SC_XOPEN_UNIX.to_string(),
"_SC_XOPEN_XCU_VERSION" => libc::_SC_XOPEN_XCU_VERSION.to_string(),
"_SC_XOPEN_VERSION" => libc::_SC_XOPEN_VERSION.to_string(),
"_SC_PASS_MAX" => libc::_SC_PASS_MAX.to_string(),
"_SC_ATEXIT_MAX" => libc::_SC_ATEXIT_MAX.to_string(),
"_SC_AVPHYS_PAGES" => libc::_SC_AVPHYS_PAGES.to_string(),
"_SC_PHYS_PAGES" => libc::_SC_PHYS_PAGES.to_string(),
"_SC_NPROCESSORS_ONLN" => libc::_SC_NPROCESSORS_ONLN.to_string(),
"_SC_NPROCESSORS_CONF" => libc::_SC_NPROCESSORS_CONF.to_string(),
"_SC_THREAD_PROCESS_SHARED" => libc::_SC_THREAD_PROCESS_SHARED.to_string(),
"_SC_THREAD_PRIO_PROTECT" => libc::_SC_THREAD_PRIO_PROTECT.to_string(),
"_SC_THREAD_PRIO_INHERIT" => libc::_SC_THREAD_PRIO_INHERIT.to_string(),
"_SC_THREAD_PRIORITY_SCHEDULING" => libc::_SC_THREAD_PRIORITY_SCHEDULING.to_string(),
"_SC_THREAD_ATTR_STACKSIZE" => libc::_SC_THREAD_ATTR_STACKSIZE.to_string(),
"_SC_THREAD_ATTR_STACKADDR" => libc::_SC_THREAD_ATTR_STACKADDR.to_string(),
"_SC_THREAD_THREADS_MAX" => libc::_SC_THREAD_THREADS_MAX.to_string(),
"_SC_THREAD_STACK_MIN" => libc::_SC_THREAD_STACK_MIN.to_string(),
"_SC_THREAD_KEYS_MAX" => libc::_SC_THREAD_KEYS_MAX.to_string(),
"_SC_THREAD_DESTRUCTOR_ITERATIONS" => libc::_SC_THREAD_DESTRUCTOR_ITERATIONS.to_string(),
"_SC_TTY_NAME_MAX" => libc::_SC_TTY_NAME_MAX.to_string(),
"_SC_LOGIN_NAME_MAX" => libc::_SC_LOGIN_NAME_MAX.to_string(),
"_SC_GETPW_R_SIZE_MAX" => libc::_SC_GETPW_R_SIZE_MAX.to_string(),
"_SC_GETGR_R_SIZE_MAX" => libc::_SC_GETGR_R_SIZE_MAX.to_string(),
"_SC_THREAD_SAFE_FUNCTIONS" => libc::_SC_THREAD_SAFE_FUNCTIONS.to_string(),
"_SC_THREADS" => libc::_SC_THREADS.to_string(),
"_SC_IOV_MAX" => libc::_SC_IOV_MAX.to_string(),
"_SC_UIO_MAXIOV" => libc::_SC_UIO_MAXIOV.to_string(),
"_SC_2_LOCALEDEF" => libc::_SC_2_LOCALEDEF.to_string(),
"_SC_2_SW_DEV" => libc::_SC_2_SW_DEV.to_string(),
"_SC_2_FORT_RUN" => libc::_SC_2_FORT_RUN.to_string(),
"_SC_2_FORT_DEV" => libc::_SC_2_FORT_DEV.to_string(),
"_SC_2_C_DEV" => libc::_SC_2_C_DEV.to_string(),
"_SC_2_C_BIND" => libc::_SC_2_C_BIND.to_string(),
"_SC_2_VERSION" => libc::_SC_2_VERSION.to_string(),
"_SC_RE_DUP_MAX" => libc::_SC_RE_DUP_MAX.to_string(),
"_SC_LINE_MAX" => libc::_SC_LINE_MAX.to_string(),
"_SC_EXPR_NEST_MAX" => libc::_SC_EXPR_NEST_MAX.to_string(),
"_SC_COLL_WEIGHTS_MAX" => libc::_SC_COLL_WEIGHTS_MAX.to_string(),
"_SC_BC_STRING_MAX" => libc::_SC_BC_STRING_MAX.to_string(),
"_SC_BC_SCALE_MAX" => libc::_SC_BC_SCALE_MAX.to_string(),
"_SC_BC_DIM_MAX" => libc::_SC_BC_DIM_MAX.to_string(),
"_SC_BC_BASE_MAX" => libc::_SC_BC_BASE_MAX.to_string(),
"_SC_TIMER_MAX" => libc::_SC_TIMER_MAX.to_string(),
"_SC_SIGQUEUE_MAX" => libc::_SC_SIGQUEUE_MAX.to_string(),
"_SC_SEM_VALUE_MAX" => libc::_SC_SEM_VALUE_MAX.to_string(),
"_SC_SEM_NSEMS_MAX" => libc::_SC_SEM_NSEMS_MAX.to_string(),
"_SC_RTSIG_MAX" => libc::_SC_RTSIG_MAX.to_string(),
"_SC_PAGE_SIZE" => libc::_SC_PAGE_SIZE.to_string(),
"_SC_PAGESIZE" => libc::_SC_PAGESIZE.to_string(),
"_SC_VERSION" => libc::_SC_VERSION.to_string(),
"_SC_MQ_PRIO_MAX" => libc::_SC_MQ_PRIO_MAX.to_string(),
"_SC_MQ_OPEN_MAX" => libc::_SC_MQ_OPEN_MAX.to_string(),
"_SC_DELAYTIMER_MAX" => libc::_SC_DELAYTIMER_MAX.to_string(),
"_SC_AIO_PRIO_DELTA_MAX" => libc::_SC_AIO_PRIO_DELTA_MAX.to_string(),
"_SC_AIO_MAX" => libc::_SC_AIO_MAX.to_string(),
"_SC_AIO_LISTIO_MAX" => libc::_SC_AIO_LISTIO_MAX.to_string(),
"_SC_SHARED_MEMORY_OBJECTS" => libc::_SC_SHARED_MEMORY_OBJECTS.to_string(),
"_SC_SEMAPHORES" => libc::_SC_SEMAPHORES.to_string(),
"_SC_MESSAGE_PASSING" => libc::_SC_MESSAGE_PASSING.to_string(),
"_SC_MEMORY_PROTECTION" => libc::_SC_MEMORY_PROTECTION.to_string(),
"_SC_MEMLOCK_RANGE" => libc::_SC_MEMLOCK_RANGE.to_string(),
"_SC_MEMLOCK" => libc::_SC_MEMLOCK.to_string(),
"_SC_MAPPED_FILES" => libc::_SC_MAPPED_FILES.to_string(),
"_SC_FSYNC" => libc::_SC_FSYNC.to_string(),
"_SC_SYNCHRONIZED_IO" => libc::_SC_SYNCHRONIZED_IO.to_string(),
"_SC_PRIORITIZED_IO" => libc::_SC_PRIORITIZED_IO.to_string(),
"_SC_ASYNCHRONOUS_IO" => libc::_SC_ASYNCHRONOUS_IO.to_string(),
"_SC_TIMERS" => libc::_SC_TIMERS.to_string(),
"_SC_PRIORITY_SCHEDULING" => libc::_SC_PRIORITY_SCHEDULING.to_string(),
"_SC_REALTIME_SIGNALS" => libc::_SC_REALTIME_SIGNALS.to_string(),
"_SC_SAVED_IDS" => libc::_SC_SAVED_IDS.to_string(),
"_SC_JOB_CONTROL" => libc::_SC_JOB_CONTROL.to_string(),
"_SC_TZNAME_MAX" => libc::_SC_TZNAME_MAX.to_string(),
"_SC_STREAM_MAX" => libc::_SC_STREAM_MAX.to_string(),
"_SC_OPEN_MAX" => libc::_SC_OPEN_MAX.to_string(),
"_SC_NGROUPS_MAX" => libc::_SC_NGROUPS_MAX.to_string(),
"_SC_CLK_TCK" => libc::_SC_CLK_TCK.to_string(),
"_SC_CHILD_MAX" => libc::_SC_CHILD_MAX.to_string(),
"_SC_ARG_MAX" => libc::_SC_ARG_MAX.to_string(),
"MS_NOUSER" => libc::MS_NOUSER.to_string(),
"_PC_2_SYMLINKS" => libc::_PC_2_SYMLINKS.to_string(),
"_PC_SYMLINK_MAX" => libc::_PC_SYMLINK_MAX.to_string(),
"_PC_ALLOC_SIZE_MIN" => libc::_PC_ALLOC_SIZE_MIN.to_string(),
"_PC_REC_XFER_ALIGN" => libc::_PC_REC_XFER_ALIGN.to_string(),
"_PC_REC_MIN_XFER_SIZE" => libc::_PC_REC_MIN_XFER_SIZE.to_string(),
"_PC_REC_MAX_XFER_SIZE" => libc::_PC_REC_MAX_XFER_SIZE.to_string(),
"_PC_REC_INCR_XFER_SIZE" => libc::_PC_REC_INCR_XFER_SIZE.to_string(),
"_PC_FILESIZEBITS" => libc::_PC_FILESIZEBITS.to_string(),
"_PC_SOCK_MAXBUF" => libc::_PC_SOCK_MAXBUF.to_string(),
"_PC_PRIO_IO" => libc::_PC_PRIO_IO.to_string(),
"_PC_ASYNC_IO" => libc::_PC_ASYNC_IO.to_string(),
"_PC_SYNC_IO" => libc::_PC_SYNC_IO.to_string(),
"_PC_VDISABLE" => libc::_PC_VDISABLE.to_string(),
"_PC_NO_TRUNC" => libc::_PC_NO_TRUNC.to_string(),
"_PC_CHOWN_RESTRICTED" => libc::_PC_CHOWN_RESTRICTED.to_string(),
"_PC_PIPE_BUF" => libc::_PC_PIPE_BUF.to_string(),
"_PC_PATH_MAX" => libc::_PC_PATH_MAX.to_string(),
"_PC_NAME_MAX" => libc::_PC_NAME_MAX.to_string(),
"_PC_MAX_INPUT" => libc::_PC_MAX_INPUT.to_string(),
"_PC_MAX_CANON" => libc::_PC_MAX_CANON.to_string(),
"_PC_LINK_MAX" => libc::_PC_LINK_MAX.to_string(),
"L_tmpnam" => libc::L_tmpnam.to_string(),
"FILENAME_MAX" => libc::FILENAME_MAX.to_string(),
"NOSTR" => libc::NOSTR.to_string(),
"YESSTR" => libc::YESSTR.to_string(),
"NOEXPR" => libc::NOEXPR.to_string(),
"YESEXPR" => libc::YESEXPR.to_string(),
"THOUSEP" => libc::THOUSEP.to_string(),
"RADIXCHAR" => libc::RADIXCHAR.to_string(),
"RUSAGE_CHILDREN" => libc::RUSAGE_CHILDREN.to_string(),
"RUSAGE_THREAD" => libc::RUSAGE_THREAD.to_string(),
"CRNCYSTR" => libc::CRNCYSTR.to_string(),
"CODESET" => libc::CODESET.to_string(),
"ERA_T_FMT" => libc::ERA_T_FMT.to_string(),
"ERA_D_T_FMT" => libc::ERA_D_T_FMT.to_string(),
"ALT_DIGITS" => libc::ALT_DIGITS.to_string(),
"ERA_D_FMT" => libc::ERA_D_FMT.to_string(),
"ERA" => libc::ERA.to_string(),
"T_FMT_AMPM" => libc::T_FMT_AMPM.to_string(),
"T_FMT" => libc::T_FMT.to_string(),
"D_FMT" => libc::D_FMT.to_string(),
"D_T_FMT" => libc::D_T_FMT.to_string(),
"PM_STR" => libc::PM_STR.to_string(),
"AM_STR" => libc::AM_STR.to_string(),
"MON_12" => libc::MON_12.to_string(),
"MON_11" => libc::MON_11.to_string(),
"MON_10" => libc::MON_10.to_string(),
"MON_9" => libc::MON_9.to_string(),
"MON_8" => libc::MON_8.to_string(),
"MON_7" => libc::MON_7.to_string(),
"MON_6" => libc::MON_6.to_string(),
"MON_5" => libc::MON_5.to_string(),
"MON_4" => libc::MON_4.to_string(),
"MON_3" => libc::MON_3.to_string(),
"MON_2" => libc::MON_2.to_string(),
"MON_1" => libc::MON_1.to_string(),
"ABMON_12" => libc::ABMON_12.to_string(),
"ABMON_11" => libc::ABMON_11.to_string(),
"ABMON_10" => libc::ABMON_10.to_string(),
"ABMON_9" => libc::ABMON_9.to_string(),
"ABMON_8" => libc::ABMON_8.to_string(),
"ABMON_7" => libc::ABMON_7.to_string(),
"ABMON_6" => libc::ABMON_6.to_string(),
"ABMON_5" => libc::ABMON_5.to_string(),
"ABMON_4" => libc::ABMON_4.to_string(),
"ABMON_3" => libc::ABMON_3.to_string(),
"ABMON_2" => libc::ABMON_2.to_string(),
"ABMON_1" => libc::ABMON_1.to_string(),
"DAY_7" => libc::DAY_7.to_string(),
"DAY_6" => libc::DAY_6.to_string(),
"DAY_5" => libc::DAY_5.to_string(),
"DAY_4" => libc::DAY_4.to_string(),
"DAY_3" => libc::DAY_3.to_string(),
"DAY_2" => libc::DAY_2.to_string(),
"DAY_1" => libc::DAY_1.to_string(),
"ABDAY_7" => libc::ABDAY_7.to_string(),
"ABDAY_6" => libc::ABDAY_6.to_string(),
"ABDAY_5" => libc::ABDAY_5.to_string(),
"ABDAY_4" => libc::ABDAY_4.to_string(),
"ABDAY_3" => libc::ABDAY_3.to_string(),
"ABDAY_2" => libc::ABDAY_2.to_string(),
"ABDAY_1" => libc::ABDAY_1.to_string(),
"ARPHRD_NONE" => libc::ARPHRD_NONE.to_string(),
"ARPHRD_VOID" => libc::ARPHRD_VOID.to_string(),
"ARPHRD_IEEE802154" => libc::ARPHRD_IEEE802154.to_string(),
"ARPHRD_IEEE80211_RADIOTAP" => libc::ARPHRD_IEEE80211_RADIOTAP.to_string(),
"ARPHRD_IEEE80211_PRISM" => libc::ARPHRD_IEEE80211_PRISM.to_string(),
"ARPHRD_IEEE80211" => libc::ARPHRD_IEEE80211.to_string(),
"ARPHRD_IEEE802_TR" => libc::ARPHRD_IEEE802_TR.to_string(),
"ARPHRD_FCFABRIC" => libc::ARPHRD_FCFABRIC.to_string(),
"ARPHRD_FCPL" => libc::ARPHRD_FCPL.to_string(),
"ARPHRD_FCAL" => libc::ARPHRD_FCAL.to_string(),
"ARPHRD_FCPP" => libc::ARPHRD_FCPP.to_string(),
"ARPHRD_IRDA" => libc::ARPHRD_IRDA.to_string(),
"ARPHRD_ECONET" => libc::ARPHRD_ECONET.to_string(),
"ARPHRD_ASH" => libc::ARPHRD_ASH.to_string(),
"ARPHRD_HIPPI" => libc::ARPHRD_HIPPI.to_string(),
"ARPHRD_PIMREG" => libc::ARPHRD_PIMREG.to_string(),
"ARPHRD_IPGRE" => libc::ARPHRD_IPGRE.to_string(),
"ARPHRD_IPDDP" => libc::ARPHRD_IPDDP.to_string(),
"ARPHRD_SIT" => libc::ARPHRD_SIT.to_string(),
"ARPHRD_BIF" => libc::ARPHRD_BIF.to_string(),
"ARPHRD_FDDI" => libc::ARPHRD_FDDI.to_string(),
"ARPHRD_LOCALTLK" => libc::ARPHRD_LOCALTLK.to_string(),
"ARPHRD_LOOPBACK" => libc::ARPHRD_LOOPBACK.to_string(),
"ARPHRD_SKIP" => libc::ARPHRD_SKIP.to_string(),
"ARPHRD_FRAD" => libc::ARPHRD_FRAD.to_string(),
"ARPHRD_TUNNEL6" => libc::ARPHRD_TUNNEL6.to_string(),
"ARPHRD_TUNNEL" => libc::ARPHRD_TUNNEL.to_string(),
"ARPHRD_RAWHDLC" => libc::ARPHRD_RAWHDLC.to_string(),
"ARPHRD_DDCMP" => libc::ARPHRD_DDCMP.to_string(),
"ARPHRD_LAPB" => libc::ARPHRD_LAPB.to_string(),
"ARPHRD_HDLC" => libc::ARPHRD_HDLC.to_string(),
"ARPHRD_CISCO" => libc::ARPHRD_CISCO.to_string(),
"ARPHRD_PPP" => libc::ARPHRD_PPP.to_string(),
"ARPHRD_HWX25" => libc::ARPHRD_HWX25.to_string(),
"ARPHRD_X25" => libc::ARPHRD_X25.to_string(),
"ARPHRD_ROSE" => libc::ARPHRD_ROSE.to_string(),
"ARPHRD_ADAPT" => libc::ARPHRD_ADAPT.to_string(),
"ARPHRD_RSRVD" => libc::ARPHRD_RSRVD.to_string(),
"ARPHRD_CSLIP6" => libc::ARPHRD_CSLIP6.to_string(),
"ARPHRD_SLIP6" => libc::ARPHRD_SLIP6.to_string(),
"ARPHRD_CSLIP" => libc::ARPHRD_CSLIP.to_string(),
"ARPHRD_SLIP" => libc::ARPHRD_SLIP.to_string(),
"ARPHRD_INFINIBAND" => libc::ARPHRD_INFINIBAND.to_string(),
"ARPHRD_EUI64" => libc::ARPHRD_EUI64.to_string(),
"ARPHRD_IEEE1394" => libc::ARPHRD_IEEE1394.to_string(),
"ARPHRD_METRICOM" => libc::ARPHRD_METRICOM.to_string(),
"ARPHRD_ATM" => libc::ARPHRD_ATM.to_string(),
"ARPHRD_DLCI" => libc::ARPHRD_DLCI.to_string(),
"ARPHRD_APPLETLK" => libc::ARPHRD_APPLETLK.to_string(),
"ARPHRD_ARCNET" => libc::ARPHRD_ARCNET.to_string(),
"ARPHRD_IEEE802" => libc::ARPHRD_IEEE802.to_string(),
"ARPHRD_CHAOS" => libc::ARPHRD_CHAOS.to_string(),
"ARPHRD_PRONET" => libc::ARPHRD_PRONET.to_string(),
"ARPHRD_AX25" => libc::ARPHRD_AX25.to_string(),
"ARPHRD_EETHER" => libc::ARPHRD_EETHER.to_string(),
"ARPHRD_ETHER" => libc::ARPHRD_ETHER.to_string(),
"ARPHRD_NETROM" => libc::ARPHRD_NETROM.to_string(),
"ATF_DONTPUB" => libc::ATF_DONTPUB.to_string(),
"ATF_NETMASK" => libc::ATF_NETMASK.to_string(),
"ARPOP_NAK" => libc::ARPOP_NAK.to_string(),
"ARPOP_InREPLY" => libc::ARPOP_InREPLY.to_string(),
"ARPOP_InREQUEST" => libc::ARPOP_InREQUEST.to_string(),
"ARPOP_RREPLY" => libc::ARPOP_RREPLY.to_string(),
"ARPOP_RREQUEST" => libc::ARPOP_RREQUEST.to_string(),
"IPOPT_TS_PRESPEC" => libc::IPOPT_TS_PRESPEC.to_string(),
"IPOPT_TS_TSANDADDR" => libc::IPOPT_TS_TSANDADDR.to_string(),
"IPOPT_TS_TSONLY" => libc::IPOPT_TS_TSONLY.to_string(),
"IPOPT_TS" => libc::IPOPT_TS.to_string(),
"IPOPT_EOL" => libc::IPOPT_EOL.to_string(),
"IPOPT_NOP" => libc::IPOPT_NOP.to_string(),
"MAX_IPOPTLEN" => libc::MAX_IPOPTLEN.to_string(),
"IPOPT_MINOFF" => libc::IPOPT_MINOFF.to_string(),
"IPOPT_OFFSET" => libc::IPOPT_OFFSET.to_string(),
"IPOPT_OLEN" => libc::IPOPT_OLEN.to_string(),
"IPOPT_OPTVAL" => libc::IPOPT_OPTVAL.to_string(),
"IPDEFTTL" => libc::IPDEFTTL.to_string(),
"MAXTTL" => libc::MAXTTL.to_string(),
"IPVERSION" => libc::IPVERSION.to_string(),
"IPOPT_RA" => libc::IPOPT_RA.to_string(),
"IPOPT_SSRR" => libc::IPOPT_SSRR.to_string(),
"IPOPT_SID" => libc::IPOPT_SID.to_string(),
"IPOPT_RR" => libc::IPOPT_RR.to_string(),
"IPOPT_TIMESTAMP" => libc::IPOPT_TIMESTAMP.to_string(),
"IPOPT_LSRR" => libc::IPOPT_LSRR.to_string(),
"IPOPT_SEC" => libc::IPOPT_SEC.to_string(),
"IPOPT_NOOP" => libc::IPOPT_NOOP.to_string(),
"IPOPT_END" => libc::IPOPT_END.to_string(),
"IPOPT_RESERVED2" => libc::IPOPT_RESERVED2.to_string(),
"IPOPT_MEASUREMENT" => libc::IPOPT_MEASUREMENT.to_string(),
"IPOPT_RESERVED1" => libc::IPOPT_RESERVED1.to_string(),
"IPOPT_CONTROL" => libc::IPOPT_CONTROL.to_string(),
"IPOPT_NUMBER_MASK" => libc::IPOPT_NUMBER_MASK.to_string(),
"IPOPT_CLASS_MASK" => libc::IPOPT_CLASS_MASK.to_string(),
"IPOPT_COPY" => libc::IPOPT_COPY.to_string(),
"IPTOS_ECN_CE" => libc::IPTOS_ECN_CE.to_string(),
"IPTOS_ECN_ECT0" => libc::IPTOS_ECN_ECT0.to_string(),
"IPTOS_ECN_ECT1" => libc::IPTOS_ECN_ECT1.to_string(),
"IPTOS_ECN_MASK" => libc::IPTOS_ECN_MASK.to_string(),
"IPTOS_PREC_ROUTINE" => libc::IPTOS_PREC_ROUTINE.to_string(),
"IPTOS_PREC_PRIORITY" => libc::IPTOS_PREC_PRIORITY.to_string(),
"IPTOS_PREC_IMMEDIATE" => libc::IPTOS_PREC_IMMEDIATE.to_string(),
"IPTOS_PREC_FLASH" => libc::IPTOS_PREC_FLASH.to_string(),
"IPTOS_PREC_FLASHOVERRIDE" => libc::IPTOS_PREC_FLASHOVERRIDE.to_string(),
"IPTOS_PREC_CRITIC_ECP" => libc::IPTOS_PREC_CRITIC_ECP.to_string(),
"IPTOS_PREC_INTERNETCONTROL" => libc::IPTOS_PREC_INTERNETCONTROL.to_string(),
"IPTOS_PREC_NETCONTROL" => libc::IPTOS_PREC_NETCONTROL.to_string(),
"IPTOS_MINCOST" => libc::IPTOS_MINCOST.to_string(),
"IPTOS_RELIABILITY" => libc::IPTOS_RELIABILITY.to_string(),
"IPTOS_THROUGHPUT" => libc::IPTOS_THROUGHPUT.to_string(),
"IPTOS_LOWDELAY" => libc::IPTOS_LOWDELAY.to_string(),
"POLLRDBAND" => libc::POLLRDBAND.to_string(),
"POLLRDNORM" => libc::POLLRDNORM.to_string(),
"POLLNVAL" => libc::POLLNVAL.to_string(),
"POLLHUP" => libc::POLLHUP.to_string(),
"POLLERR" => libc::POLLERR.to_string(),
"POLLOUT" => libc::POLLOUT.to_string(),
"POLLPRI" => libc::POLLPRI.to_string(),
"POLLIN" => libc::POLLIN.to_string(),
"UTIME_NOW" => libc::UTIME_NOW.to_string(),
"UTIME_OMIT" => libc::UTIME_OMIT.to_string(),
"P_PGID" => libc::P_PGID.to_string(),
"P_PID" => libc::P_PID.to_string(),
"P_ALL" => libc::P_ALL.to_string(),
"SIGEV_THREAD" => libc::SIGEV_THREAD.to_string(),
"SIGEV_NONE" => libc::SIGEV_NONE.to_string(),
"SIGEV_SIGNAL" => libc::SIGEV_SIGNAL.to_string(),
"SI_LOAD_SHIFT" => libc::SI_LOAD_SHIFT.to_string(),
"PIPE_BUF" => libc::PIPE_BUF.to_string(),
"LOG_PERROR" => libc::LOG_PERROR.to_string(),
"LOG_FTP" => libc::LOG_FTP.to_string(),
"LOG_AUTHPRIV" => libc::LOG_AUTHPRIV.to_string(),
"LOG_CRON" => libc::LOG_CRON.to_string(),
"AT_EMPTY_PATH" => libc::AT_EMPTY_PATH.to_string(),
"AT_NO_AUTOMOUNT" => libc::AT_NO_AUTOMOUNT.to_string(),
"AT_SYMLINK_FOLLOW" => libc::AT_SYMLINK_FOLLOW.to_string(),
"AT_REMOVEDIR" => libc::AT_REMOVEDIR.to_string(),
"AT_SYMLINK_NOFOLLOW" => libc::AT_SYMLINK_NOFOLLOW.to_string(),
"AT_FDCWD" => libc::AT_FDCWD.to_string(),
"POSIX_FADV_WILLNEED" => libc::POSIX_FADV_WILLNEED.to_string(),
"POSIX_FADV_SEQUENTIAL" => libc::POSIX_FADV_SEQUENTIAL.to_string(),
"POSIX_FADV_RANDOM" => libc::POSIX_FADV_RANDOM.to_string(),
"POSIX_FADV_NORMAL" => libc::POSIX_FADV_NORMAL.to_string(),
"RTLD_LAZY" => libc::RTLD_LAZY.to_string(),
"RTLD_LOCAL" => libc::RTLD_LOCAL.to_string(),
"SPLICE_F_GIFT" => libc::SPLICE_F_GIFT.to_string(),
"SPLICE_F_MORE" => libc::SPLICE_F_MORE.to_string(),
"SPLICE_F_NONBLOCK" => libc::SPLICE_F_NONBLOCK.to_string(),
"SPLICE_F_MOVE" => libc::SPLICE_F_MOVE.to_string(),
"__WCLONE" => libc::__WCLONE.to_string(),
"__WALL" => libc::__WALL.to_string(),
"__WNOTHREAD" => libc::__WNOTHREAD.to_string(),
"PTRACE_EVENT_SECCOMP" => libc::PTRACE_EVENT_SECCOMP.to_string(),
"PTRACE_EVENT_EXIT" => libc::PTRACE_EVENT_EXIT.to_string(),
"PTRACE_EVENT_VFORK_DONE" => libc::PTRACE_EVENT_VFORK_DONE.to_string(),
"PTRACE_EVENT_EXEC" => libc::PTRACE_EVENT_EXEC.to_string(),
"PTRACE_EVENT_CLONE" => libc::PTRACE_EVENT_CLONE.to_string(),
"PTRACE_EVENT_VFORK" => libc::PTRACE_EVENT_VFORK.to_string(),
"PTRACE_EVENT_FORK" => libc::PTRACE_EVENT_FORK.to_string(),
"PTRACE_O_MASK" => libc::PTRACE_O_MASK.to_string(),
"PTRACE_O_SUSPEND_SECCOMP" => libc::PTRACE_O_SUSPEND_SECCOMP.to_string(),
"PTRACE_O_EXITKILL" => libc::PTRACE_O_EXITKILL.to_string(),
"PTRACE_O_TRACESECCOMP" => libc::PTRACE_O_TRACESECCOMP.to_string(),
"PTRACE_O_TRACEEXIT" => libc::PTRACE_O_TRACEEXIT.to_string(),
"PTRACE_O_TRACEVFORKDONE" => libc::PTRACE_O_TRACEVFORKDONE.to_string(),
"PTRACE_O_TRACEEXEC" => libc::PTRACE_O_TRACEEXEC.to_string(),
"PTRACE_O_TRACECLONE" => libc::PTRACE_O_TRACECLONE.to_string(),
"PTRACE_O_TRACEVFORK" => libc::PTRACE_O_TRACEVFORK.to_string(),
"PTRACE_O_TRACEFORK" => libc::PTRACE_O_TRACEFORK.to_string(),
"PTRACE_O_TRACESYSGOOD" => libc::PTRACE_O_TRACESYSGOOD.to_string(),
"WNOWAIT" => libc::WNOWAIT.to_string(),
"WCONTINUED" => libc::WCONTINUED.to_string(),
"WEXITED" => libc::WEXITED.to_string(),
"WSTOPPED" => libc::WSTOPPED.to_string(),
"WUNTRACED" => libc::WUNTRACED.to_string(),
"WNOHANG" => libc::WNOHANG.to_string(),
"CLONE_NEWCGROUP" => libc::CLONE_NEWCGROUP.to_string(),
"CLONE_IO" => libc::CLONE_IO.to_string(),
"CLONE_NEWNET" => libc::CLONE_NEWNET.to_string(),
"CLONE_NEWPID" => libc::CLONE_NEWPID.to_string(),
"CLONE_NEWUSER" => libc::CLONE_NEWUSER.to_string(),
"CLONE_NEWIPC" => libc::CLONE_NEWIPC.to_string(),
"CLONE_NEWUTS" => libc::CLONE_NEWUTS.to_string(),
"CLONE_CHILD_SETTID" => libc::CLONE_CHILD_SETTID.to_string(),
"CLONE_UNTRACED" => libc::CLONE_UNTRACED.to_string(),
"CLONE_DETACHED" => libc::CLONE_DETACHED.to_string(),
"CLONE_CHILD_CLEARTID" => libc::CLONE_CHILD_CLEARTID.to_string(),
"CLONE_PARENT_SETTID" => libc::CLONE_PARENT_SETTID.to_string(),
"CLONE_SETTLS" => libc::CLONE_SETTLS.to_string(),
"CLONE_SYSVSEM" => libc::CLONE_SYSVSEM.to_string(),
"CLONE_NEWNS" => libc::CLONE_NEWNS.to_string(),
"CLONE_THREAD" => libc::CLONE_THREAD.to_string(),
"CLONE_PARENT" => libc::CLONE_PARENT.to_string(),
"CLONE_VFORK" => libc::CLONE_VFORK.to_string(),
"CLONE_PTRACE" => libc::CLONE_PTRACE.to_string(),
"CLONE_SIGHAND" => libc::CLONE_SIGHAND.to_string(),
"CLONE_FILES" => libc::CLONE_FILES.to_string(),
"CLONE_FS" => libc::CLONE_FS.to_string(),
"CLONE_VM" => libc::CLONE_VM.to_string(),
"OFDEL" => libc::OFDEL.to_string(),
"OFILL" => libc::OFILL.to_string(),
"ONLRET" => libc::ONLRET.to_string(),
"ONOCR" => libc::ONOCR.to_string(),
"OCRNL" => libc::OCRNL.to_string(),
"ECHO" => libc::ECHO.to_string(),
"CRTSCTS" => libc::CRTSCTS.to_string(),
"CS5" => libc::CS5.to_string(),
"OPOST" => libc::OPOST.to_string(),
"IMAXBEL" => libc::IMAXBEL.to_string(),
"IXANY" => libc::IXANY.to_string(),
"ICRNL" => libc::ICRNL.to_string(),
"IGNCR" => libc::IGNCR.to_string(),
"INLCR" => libc::INLCR.to_string(),
"ISTRIP" => libc::ISTRIP.to_string(),
"INPCK" => libc::INPCK.to_string(),
"PARMRK" => libc::PARMRK.to_string(),
"IGNPAR" => libc::IGNPAR.to_string(),
"BRKINT" => libc::BRKINT.to_string(),
"IGNBRK" => libc::IGNBRK.to_string(),
"VLNEXT" => libc::VLNEXT.to_string(),
"VQUIT" => libc::VQUIT.to_string(),
"VINTR" => libc::VINTR.to_string(),
"VKILL" => libc::VKILL.to_string(),
"VERASE" => libc::VERASE.to_string(),
"VT0" => libc::VT0.to_string(),
"BS0" => libc::BS0.to_string(),
"FF0" => libc::FF0.to_string(),
"CR0" => libc::CR0.to_string(),
"TAB0" => libc::TAB0.to_string(),
"NL1" => libc::NL1.to_string(),
"NL0" => libc::NL0.to_string(),
"TCIOFLUSH" => libc::TCIOFLUSH.to_string(),
"TCOFLUSH" => libc::TCOFLUSH.to_string(),
"TCIFLUSH" => libc::TCIFLUSH.to_string(),
"TCOON" => libc::TCOON.to_string(),
"TCOOFF" => libc::TCOOFF.to_string(),
"TCION" => libc::TCION.to_string(),
"TCIOFF" => libc::TCIOFF.to_string(),
"Q_SETQUOTA" => libc::Q_SETQUOTA.to_string(),
"Q_GETQUOTA" => libc::Q_GETQUOTA.to_string(),
"Q_QUOTAOFF" => libc::Q_QUOTAOFF.to_string(),
"Q_QUOTAON" => libc::Q_QUOTAON.to_string(),
"Q_SYNC" => libc::Q_SYNC.to_string(),
"MNT_FORCE" => libc::MNT_FORCE.to_string(),
"QIF_ALL" => libc::QIF_ALL.to_string(),
"QIF_TIMES" => libc::QIF_TIMES.to_string(),
"QIF_USAGE" => libc::QIF_USAGE.to_string(),
"QIF_LIMITS" => libc::QIF_LIMITS.to_string(),
"QIF_ITIME" => libc::QIF_ITIME.to_string(),
"QIF_BTIME" => libc::QIF_BTIME.to_string(),
"QIF_INODES" => libc::QIF_INODES.to_string(),
"QIF_ILIMITS" => libc::QIF_ILIMITS.to_string(),
"QIF_SPACE" => libc::QIF_SPACE.to_string(),
"QIF_BLIMITS" => libc::QIF_BLIMITS.to_string(),
"Q_SETINFO" => libc::Q_SETINFO.to_string(),
"Q_GETINFO" => libc::Q_GETINFO.to_string(),
"Q_GETFMT" => libc::Q_GETFMT.to_string(),
"MNT_EXPIRE" => libc::MNT_EXPIRE.to_string(),
"MNT_DETACH" => libc::MNT_DETACH.to_string(),
"EPOLL_CTL_DEL" => libc::EPOLL_CTL_DEL.to_string(),
"EPOLL_CTL_MOD" => libc::EPOLL_CTL_MOD.to_string(),
"EPOLL_CTL_ADD" => libc::EPOLL_CTL_ADD.to_string(),
"EPOLLET" => libc::EPOLLET.to_string(),
"EPOLLHUP" => libc::EPOLLHUP.to_string(),
"EPOLLERR" => libc::EPOLLERR.to_string(),
"EPOLLMSG" => libc::EPOLLMSG.to_string(),
"EPOLLWRBAND" => libc::EPOLLWRBAND.to_string(),
"EPOLLWRNORM" => libc::EPOLLWRNORM.to_string(),
"EPOLLRDBAND" => libc::EPOLLRDBAND.to_string(),
"EPOLLRDNORM" => libc::EPOLLRDNORM.to_string(),
"EPOLLOUT" => libc::EPOLLOUT.to_string(),
"EPOLLPRI" => libc::EPOLLPRI.to_string(),
"EPOLLIN" => libc::EPOLLIN.to_string(),
"FD_SETSIZE" => libc::FD_SETSIZE.to_string(),
"PATH_MAX" => libc::PATH_MAX.to_string(),
"SS_DISABLE" => libc::SS_DISABLE.to_string(),
"SS_ONSTACK" => libc::SS_ONSTACK.to_string(),
"LOCK_UN" => libc::LOCK_UN.to_string(),
"LOCK_NB" => libc::LOCK_NB.to_string(),
"LOCK_EX" => libc::LOCK_EX.to_string(),
"LOCK_SH" => libc::LOCK_SH.to_string(),
"SHUT_RDWR" => libc::SHUT_RDWR.to_string(),
"SHUT_WR" => libc::SHUT_WR.to_string(),
"SHUT_RD" => libc::SHUT_RD.to_string(),
"SO_DEBUG" => libc::SO_DEBUG.to_string(),
"TCP_CONGESTION" => libc::TCP_CONGESTION.to_string(),
"TCP_QUICKACK" => libc::TCP_QUICKACK.to_string(),
"TCP_INFO" => libc::TCP_INFO.to_string(),
"TCP_WINDOW_CLAMP" => libc::TCP_WINDOW_CLAMP.to_string(),
"TCP_DEFER_ACCEPT" => libc::TCP_DEFER_ACCEPT.to_string(),
"TCP_LINGER2" => libc::TCP_LINGER2.to_string(),
"TCP_SYNCNT" => libc::TCP_SYNCNT.to_string(),
"TCP_KEEPCNT" => libc::TCP_KEEPCNT.to_string(),
"TCP_KEEPINTVL" => libc::TCP_KEEPINTVL.to_string(),
"TCP_KEEPIDLE" => libc::TCP_KEEPIDLE.to_string(),
"TCP_CORK" => libc::TCP_CORK.to_string(),
"TCP_MAXSEG" => libc::TCP_MAXSEG.to_string(),
"TCP_NODELAY" => libc::TCP_NODELAY.to_string(),
"IP_PMTUDISC_PROBE" => libc::IP_PMTUDISC_PROBE.to_string(),
"IP_PMTUDISC_DO" => libc::IP_PMTUDISC_DO.to_string(),
"IP_PMTUDISC_WANT" => libc::IP_PMTUDISC_WANT.to_string(),
"IP_PMTUDISC_DONT" => libc::IP_PMTUDISC_DONT.to_string(),
"IPV6_TCLASS" => libc::IPV6_TCLASS.to_string(),
"IPV6_RECVTCLASS" => libc::IPV6_RECVTCLASS.to_string(),
"IPV6_PKTINFO" => libc::IPV6_PKTINFO.to_string(),
"IPV6_RECVPKTINFO" => libc::IPV6_RECVPKTINFO.to_string(),
"IPV6_LEAVE_ANYCAST" => libc::IPV6_LEAVE_ANYCAST.to_string(),
"IPV6_JOIN_ANYCAST" => libc::IPV6_JOIN_ANYCAST.to_string(),
"IPV6_V6ONLY" => libc::IPV6_V6ONLY.to_string(),
"IPV6_RECVERR" => libc::IPV6_RECVERR.to_string(),
"IPV6_MTU" => libc::IPV6_MTU.to_string(),
"IPV6_MTU_DISCOVER" => libc::IPV6_MTU_DISCOVER.to_string(),
"IPV6_ROUTER_ALERT" => libc::IPV6_ROUTER_ALERT.to_string(),
"IPV6_DROP_MEMBERSHIP" => libc::IPV6_DROP_MEMBERSHIP.to_string(),
"IPV6_ADD_MEMBERSHIP" => libc::IPV6_ADD_MEMBERSHIP.to_string(),
"IPV6_MULTICAST_LOOP" => libc::IPV6_MULTICAST_LOOP.to_string(),
"IPV6_MULTICAST_HOPS" => libc::IPV6_MULTICAST_HOPS.to_string(),
"IPV6_MULTICAST_IF" => libc::IPV6_MULTICAST_IF.to_string(),
"IPV6_UNICAST_HOPS" => libc::IPV6_UNICAST_HOPS.to_string(),
"IPV6_NEXTHOP" => libc::IPV6_NEXTHOP.to_string(),
"IPV6_2292HOPLIMIT" => libc::IPV6_2292HOPLIMIT.to_string(),
"IPV6_CHECKSUM" => libc::IPV6_CHECKSUM.to_string(),
"IPV6_2292PKTOPTIONS" => libc::IPV6_2292PKTOPTIONS.to_string(),
"IPV6_2292RTHDR" => libc::IPV6_2292RTHDR.to_string(),
"IPV6_2292DSTOPTS" => libc::IPV6_2292DSTOPTS.to_string(),
"IPV6_2292HOPOPTS" => libc::IPV6_2292HOPOPTS.to_string(),
"IPV6_2292PKTINFO" => libc::IPV6_2292PKTINFO.to_string(),
"IPV6_ADDRFORM" => libc::IPV6_ADDRFORM.to_string(),
"IP_TRANSPARENT" => libc::IP_TRANSPARENT.to_string(),
"IP_DROP_SOURCE_MEMBERSHIP" => libc::IP_DROP_SOURCE_MEMBERSHIP.to_string(),
"IP_ADD_SOURCE_MEMBERSHIP" => libc::IP_ADD_SOURCE_MEMBERSHIP.to_string(),
"IP_DROP_MEMBERSHIP" => libc::IP_DROP_MEMBERSHIP.to_string(),
"IP_ADD_MEMBERSHIP" => libc::IP_ADD_MEMBERSHIP.to_string(),
"IP_RECVERR" => libc::IP_RECVERR.to_string(),
"IP_RECVTOS" => libc::IP_RECVTOS.to_string(),
"IP_MTU_DISCOVER" => libc::IP_MTU_DISCOVER.to_string(),
"IP_PKTINFO" => libc::IP_PKTINFO.to_string(),
"IP_HDRINCL" => libc::IP_HDRINCL.to_string(),
"IP_TTL" => libc::IP_TTL.to_string(),
"IP_TOS" => libc::IP_TOS.to_string(),
"IP_MULTICAST_LOOP" => libc::IP_MULTICAST_LOOP.to_string(),
"IP_MULTICAST_TTL" => libc::IP_MULTICAST_TTL.to_string(),
"IP_MULTICAST_IF" => libc::IP_MULTICAST_IF.to_string(),
"SOCK_RDM" => libc::SOCK_RDM.to_string(),
"SOCK_RAW" => libc::SOCK_RAW.to_string(),
"SCM_TIMESTAMP" => libc::SCM_TIMESTAMP.to_string(),
"MSG_CMSG_CLOEXEC" => libc::MSG_CMSG_CLOEXEC.to_string(),
"MSG_FASTOPEN" => libc::MSG_FASTOPEN.to_string(),
"MSG_WAITFORONE" => libc::MSG_WAITFORONE.to_string(),
"MSG_MORE" => libc::MSG_MORE.to_string(),
"MSG_NOSIGNAL" => libc::MSG_NOSIGNAL.to_string(),
"MSG_ERRQUEUE" => libc::MSG_ERRQUEUE.to_string(),
"MSG_RST" => libc::MSG_RST.to_string(),
"MSG_CONFIRM" => libc::MSG_CONFIRM.to_string(),
"MSG_SYN" => libc::MSG_SYN.to_string(),
"MSG_FIN" => libc::MSG_FIN.to_string(),
"MSG_WAITALL" => libc::MSG_WAITALL.to_string(),
"MSG_EOR" => libc::MSG_EOR.to_string(),
"MSG_DONTWAIT" => libc::MSG_DONTWAIT.to_string(),
"MSG_TRUNC" => libc::MSG_TRUNC.to_string(),
"MSG_CTRUNC" => libc::MSG_CTRUNC.to_string(),
"MSG_DONTROUTE" => libc::MSG_DONTROUTE.to_string(),
"MSG_PEEK" => libc::MSG_PEEK.to_string(),
"MSG_OOB" => libc::MSG_OOB.to_string(),
"SOMAXCONN" => libc::SOMAXCONN.to_string(),
"PF_ALG" => libc::PF_ALG.to_string(),
"PF_CAIF" => libc::PF_CAIF.to_string(),
"PF_IEEE802154" => libc::PF_IEEE802154.to_string(),
"PF_PHONET" => libc::PF_PHONET.to_string(),
"PF_ISDN" => libc::PF_ISDN.to_string(),
"PF_RXRPC" => libc::PF_RXRPC.to_string(),
"PF_IUCV" => libc::PF_IUCV.to_string(),
"PF_BLUETOOTH" => libc::PF_BLUETOOTH.to_string(),
"PF_TIPC" => libc::PF_TIPC.to_string(),
"PF_CAN" => libc::PF_CAN.to_string(),
"PF_LLC" => libc::PF_LLC.to_string(),
"PF_WANPIPE" => libc::PF_WANPIPE.to_string(),
"PF_PPPOX" => libc::PF_PPPOX.to_string(),
"PF_IRDA" => libc::PF_IRDA.to_string(),
"PF_SNA" => libc::PF_SNA.to_string(),
"PF_RDS" => libc::PF_RDS.to_string(),
"PF_ATMSVC" => libc::PF_ATMSVC.to_string(),
"PF_ECONET" => libc::PF_ECONET.to_string(),
"PF_ASH" => libc::PF_ASH.to_string(),
"PF_PACKET" => libc::PF_PACKET.to_string(),
"PF_ROUTE" => libc::PF_ROUTE.to_string(),
"PF_NETLINK" => libc::PF_NETLINK.to_string(),
"PF_KEY" => libc::PF_KEY.to_string(),
"PF_SECURITY" => libc::PF_SECURITY.to_string(),
"PF_NETBEUI" => libc::PF_NETBEUI.to_string(),
"PF_DECnet" => libc::PF_DECnet.to_string(),
"PF_ROSE" => libc::PF_ROSE.to_string(),
"PF_INET6" => libc::PF_INET6.to_string(),
"PF_X25" => libc::PF_X25.to_string(),
"PF_ATMPVC" => libc::PF_ATMPVC.to_string(),
"PF_BRIDGE" => libc::PF_BRIDGE.to_string(),
"PF_NETROM" => libc::PF_NETROM.to_string(),
"PF_APPLETALK" => libc::PF_APPLETALK.to_string(),
"PF_IPX" => libc::PF_IPX.to_string(),
"PF_AX25" => libc::PF_AX25.to_string(),
"PF_INET" => libc::PF_INET.to_string(),
"PF_LOCAL" => libc::PF_LOCAL.to_string(),
"PF_UNIX" => libc::PF_UNIX.to_string(),
"PF_UNSPEC" => libc::PF_UNSPEC.to_string(),
"AF_ALG" => libc::AF_ALG.to_string(),
"AF_CAIF" => libc::AF_CAIF.to_string(),
"AF_IEEE802154" => libc::AF_IEEE802154.to_string(),
"AF_PHONET" => libc::AF_PHONET.to_string(),
"AF_ISDN" => libc::AF_ISDN.to_string(),
"AF_RXRPC" => libc::AF_RXRPC.to_string(),
"AF_IUCV" => libc::AF_IUCV.to_string(),
"AF_BLUETOOTH" => libc::AF_BLUETOOTH.to_string(),
"AF_TIPC" => libc::AF_TIPC.to_string(),
"AF_CAN" => libc::AF_CAN.to_string(),
"AF_LLC" => libc::AF_LLC.to_string(),
"AF_WANPIPE" => libc::AF_WANPIPE.to_string(),
"AF_PPPOX" => libc::AF_PPPOX.to_string(),
"AF_IRDA" => libc::AF_IRDA.to_string(),
"AF_SNA" => libc::AF_SNA.to_string(),
"AF_RDS" => libc::AF_RDS.to_string(),
"AF_ATMSVC" => libc::AF_ATMSVC.to_string(),
"AF_ECONET" => libc::AF_ECONET.to_string(),
"AF_ASH" => libc::AF_ASH.to_string(),
"AF_PACKET" => libc::AF_PACKET.to_string(),
"AF_ROUTE" => libc::AF_ROUTE.to_string(),
"AF_NETLINK" => libc::AF_NETLINK.to_string(),
"AF_KEY" => libc::AF_KEY.to_string(),
"AF_SECURITY" => libc::AF_SECURITY.to_string(),
"AF_NETBEUI" => libc::AF_NETBEUI.to_string(),
"AF_DECnet" => libc::AF_DECnet.to_string(),
"AF_ROSE" => libc::AF_ROSE.to_string(),
"AF_INET6" => libc::AF_INET6.to_string(),
"AF_X25" => libc::AF_X25.to_string(),
"AF_ATMPVC" => libc::AF_ATMPVC.to_string(),
"AF_BRIDGE" => libc::AF_BRIDGE.to_string(),
"AF_NETROM" => libc::AF_NETROM.to_string(),
"AF_APPLETALK" => libc::AF_APPLETALK.to_string(),
"AF_IPX" => libc::AF_IPX.to_string(),
"AF_AX25" => libc::AF_AX25.to_string(),
"AF_INET" => libc::AF_INET.to_string(),
"AF_LOCAL" => libc::AF_LOCAL.to_string(),
"AF_UNIX" => libc::AF_UNIX.to_string(),
"AF_UNSPEC" => libc::AF_UNSPEC.to_string(),
"SOL_ALG" => libc::SOL_ALG.to_string(),
"SOL_BLUETOOTH" => libc::SOL_BLUETOOTH.to_string(),
"SOL_TIPC" => libc::SOL_TIPC.to_string(),
"SOL_NETLINK" => libc::SOL_NETLINK.to_string(),
"SOL_DCCP" => libc::SOL_DCCP.to_string(),
"SOL_LLC" => libc::SOL_LLC.to_string(),
"SOL_NETBEUI" => libc::SOL_NETBEUI.to_string(),
"SOL_IRDA" => libc::SOL_IRDA.to_string(),
"SOL_AAL" => libc::SOL_AAL.to_string(),
"SOL_ATM" => libc::SOL_ATM.to_string(),
"SOL_PACKET" => libc::SOL_PACKET.to_string(),
"SOL_X25" => libc::SOL_X25.to_string(),
"SOL_DECNET" => libc::SOL_DECNET.to_string(),
"SOL_RAW" => libc::SOL_RAW.to_string(),
"SOL_ICMPV6" => libc::SOL_ICMPV6.to_string(),
"SOL_IPV6" => libc::SOL_IPV6.to_string(),
"SOL_UDP" => libc::SOL_UDP.to_string(),
"SOL_TCP" => libc::SOL_TCP.to_string(),
"SOL_IP" => libc::SOL_IP.to_string(),
"IFF_DYNAMIC" => libc::IFF_DYNAMIC.to_string(),
"IFF_AUTOMEDIA" => libc::IFF_AUTOMEDIA.to_string(),
"IFF_PORTSEL" => libc::IFF_PORTSEL.to_string(),
"IFF_MULTICAST" => libc::IFF_MULTICAST.to_string(),
"IFF_SLAVE" => libc::IFF_SLAVE.to_string(),
"IFF_MASTER" => libc::IFF_MASTER.to_string(),
"IFF_ALLMULTI" => libc::IFF_ALLMULTI.to_string(),
"IFF_PROMISC" => libc::IFF_PROMISC.to_string(),
"IFF_NOARP" => libc::IFF_NOARP.to_string(),
"IFF_RUNNING" => libc::IFF_RUNNING.to_string(),
"IFF_NOTRAILERS" => libc::IFF_NOTRAILERS.to_string(),
"IFF_POINTOPOINT" => libc::IFF_POINTOPOINT.to_string(),
"IFF_LOOPBACK" => libc::IFF_LOOPBACK.to_string(),
"IFF_DEBUG" => libc::IFF_DEBUG.to_string(),
"IFF_BROADCAST" => libc::IFF_BROADCAST.to_string(),
"IFF_UP" => libc::IFF_UP.to_string(),
"MADV_HWPOISON" => libc::MADV_HWPOISON.to_string(),
"MADV_DODUMP" => libc::MADV_DODUMP.to_string(),
"MADV_DONTDUMP" => libc::MADV_DONTDUMP.to_string(),
"MADV_NOHUGEPAGE" => libc::MADV_NOHUGEPAGE.to_string(),
"MADV_HUGEPAGE" => libc::MADV_HUGEPAGE.to_string(),
"MADV_UNMERGEABLE" => libc::MADV_UNMERGEABLE.to_string(),
"MADV_MERGEABLE" => libc::MADV_MERGEABLE.to_string(),
"MADV_DOFORK" => libc::MADV_DOFORK.to_string(),
"MADV_DONTFORK" => libc::MADV_DONTFORK.to_string(),
"MADV_REMOVE" => libc::MADV_REMOVE.to_string(),
"MADV_FREE" => libc::MADV_FREE.to_string(),
"MADV_DONTNEED" => libc::MADV_DONTNEED.to_string(),
"MADV_WILLNEED" => libc::MADV_WILLNEED.to_string(),
"MADV_SEQUENTIAL" => libc::MADV_SEQUENTIAL.to_string(),
"MADV_RANDOM" => libc::MADV_RANDOM.to_string(),
"MADV_NORMAL" => libc::MADV_NORMAL.to_string(),
"MAP_TYPE" => libc::MAP_TYPE.to_string(),
"PROT_GROWSUP" => libc::PROT_GROWSUP.to_string(),
"PROT_GROWSDOWN" => libc::PROT_GROWSDOWN.to_string(),
"SCM_CREDENTIALS" => libc::SCM_CREDENTIALS.to_string(),
"SCM_RIGHTS" => libc::SCM_RIGHTS.to_string(),
"MS_MGC_MSK" => libc::MS_MGC_MSK.to_string(),
"MS_MGC_VAL" => libc::MS_MGC_VAL.to_string(),
"MS_ACTIVE" => libc::MS_ACTIVE.to_string(),
"MS_STRICTATIME" => libc::MS_STRICTATIME.to_string(),
"MS_I_VERSION" => libc::MS_I_VERSION.to_string(),
"MS_KERNMOUNT" => libc::MS_KERNMOUNT.to_string(),
"MS_RELATIME" => libc::MS_RELATIME.to_string(),
"MS_SHARED" => libc::MS_SHARED.to_string(),
"MS_SLAVE" => libc::MS_SLAVE.to_string(),
"MS_PRIVATE" => libc::MS_PRIVATE.to_string(),
"MS_UNBINDABLE" => libc::MS_UNBINDABLE.to_string(),
"MS_POSIXACL" => libc::MS_POSIXACL.to_string(),
"MS_SILENT" => libc::MS_SILENT.to_string(),
"MS_REC" => libc::MS_REC.to_string(),
"MS_MOVE" => libc::MS_MOVE.to_string(),
"MS_BIND" => libc::MS_BIND.to_string(),
"MS_NODIRATIME" => libc::MS_NODIRATIME.to_string(),
"MS_NOATIME" => libc::MS_NOATIME.to_string(),
"MS_DIRSYNC" => libc::MS_DIRSYNC.to_string(),
"MS_MANDLOCK" => libc::MS_MANDLOCK.to_string(),
"MS_REMOUNT" => libc::MS_REMOUNT.to_string(),
"MS_SYNCHRONOUS" => libc::MS_SYNCHRONOUS.to_string(),
"MS_NOEXEC" => libc::MS_NOEXEC.to_string(),
"MS_NODEV" => libc::MS_NODEV.to_string(),
"MS_NOSUID" => libc::MS_NOSUID.to_string(),
"MS_RDONLY" => libc::MS_RDONLY.to_string(),
"MS_SYNC" => libc::MS_SYNC.to_string(),
"MS_INVALIDATE" => libc::MS_INVALIDATE.to_string(),
"MS_ASYNC" => libc::MS_ASYNC.to_string(),
"MAP_FIXED" => libc::MAP_FIXED.to_string(),
"MAP_PRIVATE" => libc::MAP_PRIVATE.to_string(),
"MAP_SHARED" => libc::MAP_SHARED.to_string(),
"MAP_FILE" => libc::MAP_FILE.to_string(),
"LC_MESSAGES_MASK" => libc::LC_MESSAGES_MASK.to_string(),
"LC_MONETARY_MASK" => libc::LC_MONETARY_MASK.to_string(),
"LC_COLLATE_MASK" => libc::LC_COLLATE_MASK.to_string(),
"LC_TIME_MASK" => libc::LC_TIME_MASK.to_string(),
"LC_NUMERIC_MASK" => libc::LC_NUMERIC_MASK.to_string(),
"LC_CTYPE_MASK" => libc::LC_CTYPE_MASK.to_string(),
"LC_ALL" => libc::LC_ALL.to_string(),
"LC_MESSAGES" => libc::LC_MESSAGES.to_string(),
"LC_MONETARY" => libc::LC_MONETARY.to_string(),
"LC_COLLATE" => libc::LC_COLLATE.to_string(),
"LC_TIME" => libc::LC_TIME.to_string(),
"LC_NUMERIC" => libc::LC_NUMERIC.to_string(),
"LC_CTYPE" => libc::LC_CTYPE.to_string(),
"PROT_EXEC" => libc::PROT_EXEC.to_string(),
"PROT_WRITE" => libc::PROT_WRITE.to_string(),
"PROT_READ" => libc::PROT_READ.to_string(),
"PROT_NONE" => libc::PROT_NONE.to_string(),
"SIGTERM" => libc::SIGTERM.to_string(),
"SIGALRM" => libc::SIGALRM.to_string(),
"SIGPIPE" => libc::SIGPIPE.to_string(),
"SIGSEGV" => libc::SIGSEGV.to_string(),
"SIGKILL" => libc::SIGKILL.to_string(),
"SIGFPE" => libc::SIGFPE.to_string(),
"SIGABRT" => libc::SIGABRT.to_string(),
"SIGILL" => libc::SIGILL.to_string(),
"SIGQUIT" => libc::SIGQUIT.to_string(),
"SIGINT" => libc::SIGINT.to_string(),
"SIGHUP" => libc::SIGHUP.to_string(),
"STDERR_FILENO" => libc::STDERR_FILENO.to_string(),
"STDOUT_FILENO" => libc::STDOUT_FILENO.to_string(),
"STDIN_FILENO" => libc::STDIN_FILENO.to_string(),
"X_OK" => libc::X_OK.to_string(),
"W_OK" => libc::W_OK.to_string(),
"R_OK" => libc::R_OK.to_string(),
"F_OK" => libc::F_OK.to_string(),
"S_IROTH" => libc::S_IROTH.to_string(),
"S_IWOTH" => libc::S_IWOTH.to_string(),
"S_IXOTH" => libc::S_IXOTH.to_string(),
"S_IRWXO" => libc::S_IRWXO.to_string(),
"S_IRGRP" => libc::S_IRGRP.to_string(),
"S_IWGRP" => libc::S_IWGRP.to_string(),
"S_IXGRP" => libc::S_IXGRP.to_string(),
"S_IRWXG" => libc::S_IRWXG.to_string(),
"S_IRUSR" => libc::S_IRUSR.to_string(),
"S_IWUSR" => libc::S_IWUSR.to_string(),
"S_IXUSR" => libc::S_IXUSR.to_string(),
"S_IRWXU" => libc::S_IRWXU.to_string(),
"S_IFMT" => libc::S_IFMT.to_string(),
"S_IFSOCK" => libc::S_IFSOCK.to_string(),
"S_IFLNK" => libc::S_IFLNK.to_string(),
"S_IFREG" => libc::S_IFREG.to_string(),
"S_IFDIR" => libc::S_IFDIR.to_string(),
"S_IFBLK" => libc::S_IFBLK.to_string(),
"S_IFCHR" => libc::S_IFCHR.to_string(),
"S_IFIFO" => libc::S_IFIFO.to_string(),
"SOCK_CLOEXEC" => libc::SOCK_CLOEXEC.to_string(),
"O_RDWR" => libc::O_RDWR.to_string(),
"O_WRONLY" => libc::O_WRONLY.to_string(),
"O_RDONLY" => libc::O_RDONLY.to_string(),
"RUSAGE_SELF" => libc::RUSAGE_SELF.to_string(),
"TIMER_ABSTIME" => libc::TIMER_ABSTIME.to_string(),
"CLOCK_TAI" => libc::CLOCK_TAI.to_string(),
"CLOCK_BOOTTIME_ALARM" => libc::CLOCK_BOOTTIME_ALARM.to_string(),
"CLOCK_REALTIME_ALARM" => libc::CLOCK_REALTIME_ALARM.to_string(),
"CLOCK_BOOTTIME" => libc::CLOCK_BOOTTIME.to_string(),
"CLOCK_MONOTONIC_COARSE" => libc::CLOCK_MONOTONIC_COARSE.to_string(),
"CLOCK_REALTIME_COARSE" => libc::CLOCK_REALTIME_COARSE.to_string(),
"CLOCK_MONOTONIC_RAW" => libc::CLOCK_MONOTONIC_RAW.to_string(),
"CLOCK_THREAD_CPUTIME_ID" => libc::CLOCK_THREAD_CPUTIME_ID.to_string(),
"CLOCK_PROCESS_CPUTIME_ID" => libc::CLOCK_PROCESS_CPUTIME_ID.to_string(),
"CLOCK_MONOTONIC" => libc::CLOCK_MONOTONIC.to_string(),
"CLOCK_REALTIME" => libc::CLOCK_REALTIME.to_string(),
"PTHREAD_CREATE_DETACHED" => libc::PTHREAD_CREATE_DETACHED.to_string(),
"PTHREAD_CREATE_JOINABLE" => libc::PTHREAD_CREATE_JOINABLE.to_string(),
"SIGTRAP" => libc::SIGTRAP.to_string(),
"F_SEAL_WRITE" => libc::F_SEAL_WRITE.to_string(),
"F_SEAL_GROW" => libc::F_SEAL_GROW.to_string(),
"F_SEAL_SHRINK" => libc::F_SEAL_SHRINK.to_string(),
"F_SEAL_SEAL" => libc::F_SEAL_SEAL.to_string(),
"F_GET_SEALS" => libc::F_GET_SEALS.to_string(),
"F_ADD_SEALS" => libc::F_ADD_SEALS.to_string(),
"F_GETPIPE_SZ" => libc::F_GETPIPE_SZ.to_string(),
"F_SETPIPE_SZ" => libc::F_SETPIPE_SZ.to_string(),
"F_DUPFD_CLOEXEC" => libc::F_DUPFD_CLOEXEC.to_string(),
"F_CANCELLK" => libc::F_CANCELLK.to_string(),
"F_NOTIFY" => libc::F_NOTIFY.to_string(),
"F_GETLEASE" => libc::F_GETLEASE.to_string(),
"F_SETLEASE" => libc::F_SETLEASE.to_string(),
"F_SETFL" => libc::F_SETFL.to_string(),
"F_GETFL" => libc::F_GETFL.to_string(),
"F_SETFD" => libc::F_SETFD.to_string(),
"F_GETFD" => libc::F_GETFD.to_string(),
"F_DUPFD" => libc::F_DUPFD.to_string(),
"_IOLBF" => libc::_IOLBF.to_string(),
"_IONBF" => libc::_IONBF.to_string(),
"_IOFBF" => libc::_IOFBF.to_string(),
"SEEK_END" => libc::SEEK_END.to_string(),
"SEEK_CUR" => libc::SEEK_CUR.to_string(),
"SEEK_SET" => libc::SEEK_SET.to_string(),
"EOF" => libc::EOF.to_string(),
"RAND_MAX" => libc::RAND_MAX.to_string(),
"EXIT_SUCCESS" => libc::EXIT_SUCCESS.to_string(),
"EXIT_FAILURE" => libc::EXIT_FAILURE.to_string(),
"ATF_USETRAILERS" => libc::ATF_USETRAILERS.to_string(),
"ATF_PUBL" => libc::ATF_PUBL.to_string(),
"ATF_PERM" => libc::ATF_PERM.to_string(),
"ATF_COM" => libc::ATF_COM.to_string(),
"ARPOP_REPLY" => libc::ARPOP_REPLY.to_string(),
"ARPOP_REQUEST" => libc::ARPOP_REQUEST.to_string(),
"INADDR_NONE" => libc::INADDR_NONE.to_string(),
"INADDR_BROADCAST" => libc::INADDR_BROADCAST.to_string(),
"INADDR_ANY" => libc::INADDR_ANY.to_string(),
"INADDR_LOOPBACK" => libc::INADDR_LOOPBACK.to_string(),
"IPPROTO_IPV6" => libc::IPPROTO_IPV6.to_string(),
"IPPROTO_IP" => libc::IPPROTO_IP.to_string(),
"IPPROTO_UDP" => libc::IPPROTO_UDP.to_string(),
"IPPROTO_TCP" => libc::IPPROTO_TCP.to_string(),
"IPPROTO_ICMPV6" => libc::IPPROTO_ICMPV6.to_string(),
"IPPROTO_ICMP" => libc::IPPROTO_ICMP.to_string(),
"PRIO_MAX" => libc::PRIO_MAX.to_string(),
"PRIO_MIN" => libc::PRIO_MIN.to_string(),
"PRIO_USER" => libc::PRIO_USER.to_string(),
"PRIO_PGRP" => libc::PRIO_PGRP.to_string(),
"PRIO_PROCESS" => libc::PRIO_PROCESS.to_string(),
"LOG_FACMASK" => libc::LOG_FACMASK.to_string(),
"LOG_PRIMASK" => libc::LOG_PRIMASK.to_string(),
"LOG_NOWAIT" => libc::LOG_NOWAIT.to_string(),
"LOG_NDELAY" => libc::LOG_NDELAY.to_string(),
"LOG_ODELAY" => libc::LOG_ODELAY.to_string(),
"LOG_CONS" => libc::LOG_CONS.to_string(),
"LOG_PID" => libc::LOG_PID.to_string(),
"LOG_LOCAL7" => libc::LOG_LOCAL7.to_string(),
"LOG_LOCAL6" => libc::LOG_LOCAL6.to_string(),
"LOG_LOCAL5" => libc::LOG_LOCAL5.to_string(),
"LOG_LOCAL4" => libc::LOG_LOCAL4.to_string(),
"LOG_LOCAL3" => libc::LOG_LOCAL3.to_string(),
"LOG_LOCAL2" => libc::LOG_LOCAL2.to_string(),
"LOG_LOCAL1" => libc::LOG_LOCAL1.to_string(),
"LOG_LOCAL0" => libc::LOG_LOCAL0.to_string(),
"LOG_UUCP" => libc::LOG_UUCP.to_string(),
"LOG_NEWS" => libc::LOG_NEWS.to_string(),
"LOG_LPR" => libc::LOG_LPR.to_string(),
"LOG_SYSLOG" => libc::LOG_SYSLOG.to_string(),
"LOG_AUTH" => libc::LOG_AUTH.to_string(),
"LOG_DAEMON" => libc::LOG_DAEMON.to_string(),
"LOG_MAIL" => libc::LOG_MAIL.to_string(),
"LOG_USER" => libc::LOG_USER.to_string(),
"LOG_KERN" => libc::LOG_KERN.to_string(),
"LOG_DEBUG" => libc::LOG_DEBUG.to_string(),
"LOG_INFO" => libc::LOG_INFO.to_string(),
"LOG_NOTICE" => libc::LOG_NOTICE.to_string(),
"LOG_WARNING" => libc::LOG_WARNING.to_string(),
"LOG_ERR" => libc::LOG_ERR.to_string(),
"LOG_CRIT" => libc::LOG_CRIT.to_string(),
"LOG_ALERT" => libc::LOG_ALERT.to_string(),
"LOG_EMERG" => libc::LOG_EMERG.to_string(),
"IFNAMSIZ" => libc::IFNAMSIZ.to_string(),
"IF_NAMESIZE" => libc::IF_NAMESIZE.to_string(),
"S_ISVTX" => libc::S_ISVTX.to_string(),
"S_ISGID" => libc::S_ISGID.to_string(),
"S_ISUID" => libc::S_ISUID.to_string(),
"SIGIOT" => libc::SIGIOT.to_string(),
"GRPQUOTA" => libc::GRPQUOTA.to_string(),
"USRQUOTA" => libc::USRQUOTA.to_string(),
"FD_CLOEXEC" => libc::FD_CLOEXEC.to_string(),
"DT_SOCK" => libc::DT_SOCK.to_string(),
"DT_LNK" => libc::DT_LNK.to_string(),
"DT_REG" => libc::DT_REG.to_string(),
"DT_BLK" => libc::DT_BLK.to_string(),
"DT_DIR" => libc::DT_DIR.to_string(),
"DT_CHR" => libc::DT_CHR.to_string(),
"DT_FIFO" => libc::DT_FIFO.to_string(),
"DT_UNKNOWN" => libc::DT_UNKNOWN.to_string(),
"SIG_ERR" => libc::SIG_ERR.to_string(),
"SIG_IGN" => libc::SIG_IGN.to_string(),
"SIG_DFL" => libc::SIG_DFL.to_string(),
"INT_MAX" => libc::INT_MAX.to_string(),
"INT_MIN" => libc::INT_MIN.to_string(),
"TIOCCBRK" => libc::TIOCCBRK.to_string(),
"TIOCSBRK" => libc::TIOCSBRK.to_string(),
"IPV6_HOPLIMIT" => libc::IPV6_HOPLIMIT.to_string(),

				_ => unreachable!("unknown command")
			});
		}
