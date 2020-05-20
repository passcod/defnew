
			#[rustfmt::skip]
			#[allow(deprecated)]
			fn main() {
				let args = clap::App::new("defnew")
					.author(&*format!(
						"CC BY-SA-NC 4.0 - {}",
						env!("CARGO_PKG_HOMEPAGE")
					))
					.about("libc-const: provides values for libc constants")
					.after_help("Values are hard-coded at compile and are not guaranteed to be correct for your system.")
					.version(clap::crate_version!())
					.setting(clap::AppSettings::SubcommandRequired)
			
.subcommand(clap::SubCommand::with_name("SYS_statx"))
.subcommand(clap::SubCommand::with_name("SYS_pkey_free"))
.subcommand(clap::SubCommand::with_name("SYS_pkey_alloc"))
.subcommand(clap::SubCommand::with_name("SYS_pkey_mprotect"))
.subcommand(clap::SubCommand::with_name("SYS_pwritev2"))
.subcommand(clap::SubCommand::with_name("SYS_preadv2"))
.subcommand(clap::SubCommand::with_name("SYS_copy_file_range"))
.subcommand(clap::SubCommand::with_name("SYS_mlock2"))
.subcommand(clap::SubCommand::with_name("SYS_membarrier"))
.subcommand(clap::SubCommand::with_name("SYS_userfaultfd"))
.subcommand(clap::SubCommand::with_name("SYS_execveat"))
.subcommand(clap::SubCommand::with_name("SYS_bpf"))
.subcommand(clap::SubCommand::with_name("SYS_kexec_file_load"))
.subcommand(clap::SubCommand::with_name("SYS_memfd_create"))
.subcommand(clap::SubCommand::with_name("SYS_getrandom"))
.subcommand(clap::SubCommand::with_name("SYS_seccomp"))
.subcommand(clap::SubCommand::with_name("SYS_renameat2"))
.subcommand(clap::SubCommand::with_name("SYS_sched_getattr"))
.subcommand(clap::SubCommand::with_name("SYS_sched_setattr"))
.subcommand(clap::SubCommand::with_name("SYS_finit_module"))
.subcommand(clap::SubCommand::with_name("SYS_kcmp"))
.subcommand(clap::SubCommand::with_name("SYS_process_vm_writev"))
.subcommand(clap::SubCommand::with_name("SYS_process_vm_readv"))
.subcommand(clap::SubCommand::with_name("SYS_getcpu"))
.subcommand(clap::SubCommand::with_name("SYS_setns"))
.subcommand(clap::SubCommand::with_name("SYS_sendmmsg"))
.subcommand(clap::SubCommand::with_name("SYS_syncfs"))
.subcommand(clap::SubCommand::with_name("SYS_clock_adjtime"))
.subcommand(clap::SubCommand::with_name("SYS_open_by_handle_at"))
.subcommand(clap::SubCommand::with_name("SYS_name_to_handle_at"))
.subcommand(clap::SubCommand::with_name("SYS_prlimit64"))
.subcommand(clap::SubCommand::with_name("SYS_fanotify_mark"))
.subcommand(clap::SubCommand::with_name("SYS_fanotify_init"))
.subcommand(clap::SubCommand::with_name("SYS_recvmmsg"))
.subcommand(clap::SubCommand::with_name("SYS_perf_event_open"))
.subcommand(clap::SubCommand::with_name("SYS_rt_tgsigqueueinfo"))
.subcommand(clap::SubCommand::with_name("SYS_pwritev"))
.subcommand(clap::SubCommand::with_name("SYS_preadv"))
.subcommand(clap::SubCommand::with_name("SYS_inotify_init1"))
.subcommand(clap::SubCommand::with_name("SYS_pipe2"))
.subcommand(clap::SubCommand::with_name("SYS_dup3"))
.subcommand(clap::SubCommand::with_name("SYS_epoll_create1"))
.subcommand(clap::SubCommand::with_name("SYS_eventfd2"))
.subcommand(clap::SubCommand::with_name("SYS_signalfd4"))
.subcommand(clap::SubCommand::with_name("SYS_accept4"))
.subcommand(clap::SubCommand::with_name("SYS_timerfd_gettime"))
.subcommand(clap::SubCommand::with_name("SYS_timerfd_settime"))
.subcommand(clap::SubCommand::with_name("SYS_fallocate"))
.subcommand(clap::SubCommand::with_name("SYS_eventfd"))
.subcommand(clap::SubCommand::with_name("SYS_timerfd_create"))
.subcommand(clap::SubCommand::with_name("SYS_signalfd"))
.subcommand(clap::SubCommand::with_name("SYS_epoll_pwait"))
.subcommand(clap::SubCommand::with_name("SYS_utimensat"))
.subcommand(clap::SubCommand::with_name("SYS_move_pages"))
.subcommand(clap::SubCommand::with_name("SYS_vmsplice"))
.subcommand(clap::SubCommand::with_name("SYS_sync_file_range"))
.subcommand(clap::SubCommand::with_name("SYS_tee"))
.subcommand(clap::SubCommand::with_name("SYS_splice"))
.subcommand(clap::SubCommand::with_name("SYS_get_robust_list"))
.subcommand(clap::SubCommand::with_name("SYS_set_robust_list"))
.subcommand(clap::SubCommand::with_name("SYS_unshare"))
.subcommand(clap::SubCommand::with_name("SYS_ppoll"))
.subcommand(clap::SubCommand::with_name("SYS_pselect6"))
.subcommand(clap::SubCommand::with_name("SYS_faccessat"))
.subcommand(clap::SubCommand::with_name("SYS_fchmodat"))
.subcommand(clap::SubCommand::with_name("SYS_readlinkat"))
.subcommand(clap::SubCommand::with_name("SYS_symlinkat"))
.subcommand(clap::SubCommand::with_name("SYS_linkat"))
.subcommand(clap::SubCommand::with_name("SYS_renameat"))
.subcommand(clap::SubCommand::with_name("SYS_unlinkat"))
.subcommand(clap::SubCommand::with_name("SYS_newfstatat"))
.subcommand(clap::SubCommand::with_name("SYS_futimesat"))
.subcommand(clap::SubCommand::with_name("SYS_fchownat"))
.subcommand(clap::SubCommand::with_name("SYS_mknodat"))
.subcommand(clap::SubCommand::with_name("SYS_mkdirat"))
.subcommand(clap::SubCommand::with_name("SYS_openat"))
.subcommand(clap::SubCommand::with_name("SYS_migrate_pages"))
.subcommand(clap::SubCommand::with_name("SYS_inotify_rm_watch"))
.subcommand(clap::SubCommand::with_name("SYS_inotify_add_watch"))
.subcommand(clap::SubCommand::with_name("SYS_inotify_init"))
.subcommand(clap::SubCommand::with_name("SYS_ioprio_get"))
.subcommand(clap::SubCommand::with_name("SYS_ioprio_set"))
.subcommand(clap::SubCommand::with_name("SYS_keyctl"))
.subcommand(clap::SubCommand::with_name("SYS_request_key"))
.subcommand(clap::SubCommand::with_name("SYS_add_key"))
.subcommand(clap::SubCommand::with_name("SYS_waitid"))
.subcommand(clap::SubCommand::with_name("SYS_kexec_load"))
.subcommand(clap::SubCommand::with_name("SYS_mq_getsetattr"))
.subcommand(clap::SubCommand::with_name("SYS_mq_notify"))
.subcommand(clap::SubCommand::with_name("SYS_mq_timedreceive"))
.subcommand(clap::SubCommand::with_name("SYS_mq_timedsend"))
.subcommand(clap::SubCommand::with_name("SYS_mq_unlink"))
.subcommand(clap::SubCommand::with_name("SYS_mq_open"))
.subcommand(clap::SubCommand::with_name("SYS_get_mempolicy"))
.subcommand(clap::SubCommand::with_name("SYS_set_mempolicy"))
.subcommand(clap::SubCommand::with_name("SYS_mbind"))
.subcommand(clap::SubCommand::with_name("SYS_vserver"))
.subcommand(clap::SubCommand::with_name("SYS_utimes"))
.subcommand(clap::SubCommand::with_name("SYS_tgkill"))
.subcommand(clap::SubCommand::with_name("SYS_epoll_ctl"))
.subcommand(clap::SubCommand::with_name("SYS_epoll_wait"))
.subcommand(clap::SubCommand::with_name("SYS_exit_group"))
.subcommand(clap::SubCommand::with_name("SYS_clock_nanosleep"))
.subcommand(clap::SubCommand::with_name("SYS_clock_getres"))
.subcommand(clap::SubCommand::with_name("SYS_clock_gettime"))
.subcommand(clap::SubCommand::with_name("SYS_clock_settime"))
.subcommand(clap::SubCommand::with_name("SYS_timer_delete"))
.subcommand(clap::SubCommand::with_name("SYS_timer_getoverrun"))
.subcommand(clap::SubCommand::with_name("SYS_timer_gettime"))
.subcommand(clap::SubCommand::with_name("SYS_timer_settime"))
.subcommand(clap::SubCommand::with_name("SYS_timer_create"))
.subcommand(clap::SubCommand::with_name("SYS_fadvise64"))
.subcommand(clap::SubCommand::with_name("SYS_semtimedop"))
.subcommand(clap::SubCommand::with_name("SYS_restart_syscall"))
.subcommand(clap::SubCommand::with_name("SYS_set_tid_address"))
.subcommand(clap::SubCommand::with_name("SYS_getdents64"))
.subcommand(clap::SubCommand::with_name("SYS_remap_file_pages"))
.subcommand(clap::SubCommand::with_name("SYS_epoll_wait_old"))
.subcommand(clap::SubCommand::with_name("SYS_epoll_ctl_old"))
.subcommand(clap::SubCommand::with_name("SYS_epoll_create"))
.subcommand(clap::SubCommand::with_name("SYS_lookup_dcookie"))
.subcommand(clap::SubCommand::with_name("SYS_get_thread_area"))
.subcommand(clap::SubCommand::with_name("SYS_io_cancel"))
.subcommand(clap::SubCommand::with_name("SYS_io_submit"))
.subcommand(clap::SubCommand::with_name("SYS_io_getevents"))
.subcommand(clap::SubCommand::with_name("SYS_io_destroy"))
.subcommand(clap::SubCommand::with_name("SYS_io_setup"))
.subcommand(clap::SubCommand::with_name("SYS_set_thread_area"))
.subcommand(clap::SubCommand::with_name("SYS_sched_getaffinity"))
.subcommand(clap::SubCommand::with_name("SYS_sched_setaffinity"))
.subcommand(clap::SubCommand::with_name("SYS_futex"))
.subcommand(clap::SubCommand::with_name("SYS_time"))
.subcommand(clap::SubCommand::with_name("SYS_tkill"))
.subcommand(clap::SubCommand::with_name("SYS_fremovexattr"))
.subcommand(clap::SubCommand::with_name("SYS_lremovexattr"))
.subcommand(clap::SubCommand::with_name("SYS_removexattr"))
.subcommand(clap::SubCommand::with_name("SYS_flistxattr"))
.subcommand(clap::SubCommand::with_name("SYS_llistxattr"))
.subcommand(clap::SubCommand::with_name("SYS_listxattr"))
.subcommand(clap::SubCommand::with_name("SYS_fgetxattr"))
.subcommand(clap::SubCommand::with_name("SYS_lgetxattr"))
.subcommand(clap::SubCommand::with_name("SYS_getxattr"))
.subcommand(clap::SubCommand::with_name("SYS_fsetxattr"))
.subcommand(clap::SubCommand::with_name("SYS_lsetxattr"))
.subcommand(clap::SubCommand::with_name("SYS_setxattr"))
.subcommand(clap::SubCommand::with_name("SYS_readahead"))
.subcommand(clap::SubCommand::with_name("SYS_gettid"))
.subcommand(clap::SubCommand::with_name("SYS_security"))
.subcommand(clap::SubCommand::with_name("SYS_tuxcall"))
.subcommand(clap::SubCommand::with_name("SYS_afs_syscall"))
.subcommand(clap::SubCommand::with_name("SYS_putpmsg"))
.subcommand(clap::SubCommand::with_name("SYS_getpmsg"))
.subcommand(clap::SubCommand::with_name("SYS_nfsservctl"))
.subcommand(clap::SubCommand::with_name("SYS_quotactl"))
.subcommand(clap::SubCommand::with_name("SYS_query_module"))
.subcommand(clap::SubCommand::with_name("SYS_get_kernel_syms"))
.subcommand(clap::SubCommand::with_name("SYS_delete_module"))
.subcommand(clap::SubCommand::with_name("SYS_init_module"))
.subcommand(clap::SubCommand::with_name("SYS_create_module"))
.subcommand(clap::SubCommand::with_name("SYS_ioperm"))
.subcommand(clap::SubCommand::with_name("SYS_iopl"))
.subcommand(clap::SubCommand::with_name("SYS_setdomainname"))
.subcommand(clap::SubCommand::with_name("SYS_sethostname"))
.subcommand(clap::SubCommand::with_name("SYS_reboot"))
.subcommand(clap::SubCommand::with_name("SYS_swapoff"))
.subcommand(clap::SubCommand::with_name("SYS_swapon"))
.subcommand(clap::SubCommand::with_name("SYS_umount2"))
.subcommand(clap::SubCommand::with_name("SYS_mount"))
.subcommand(clap::SubCommand::with_name("SYS_settimeofday"))
.subcommand(clap::SubCommand::with_name("SYS_acct"))
.subcommand(clap::SubCommand::with_name("SYS_sync"))
.subcommand(clap::SubCommand::with_name("SYS_chroot"))
.subcommand(clap::SubCommand::with_name("SYS_setrlimit"))
.subcommand(clap::SubCommand::with_name("SYS_adjtimex"))
.subcommand(clap::SubCommand::with_name("SYS_arch_prctl"))
.subcommand(clap::SubCommand::with_name("SYS_prctl"))
.subcommand(clap::SubCommand::with_name("SYS__sysctl"))
.subcommand(clap::SubCommand::with_name("SYS_pivot_root"))
.subcommand(clap::SubCommand::with_name("SYS_modify_ldt"))
.subcommand(clap::SubCommand::with_name("SYS_vhangup"))
.subcommand(clap::SubCommand::with_name("SYS_munlockall"))
.subcommand(clap::SubCommand::with_name("SYS_mlockall"))
.subcommand(clap::SubCommand::with_name("SYS_munlock"))
.subcommand(clap::SubCommand::with_name("SYS_mlock"))
.subcommand(clap::SubCommand::with_name("SYS_sched_rr_get_interval"))
.subcommand(clap::SubCommand::with_name("SYS_sched_get_priority_min"))
.subcommand(clap::SubCommand::with_name("SYS_sched_get_priority_max"))
.subcommand(clap::SubCommand::with_name("SYS_sched_getscheduler"))
.subcommand(clap::SubCommand::with_name("SYS_sched_setscheduler"))
.subcommand(clap::SubCommand::with_name("SYS_sched_getparam"))
.subcommand(clap::SubCommand::with_name("SYS_sched_setparam"))
.subcommand(clap::SubCommand::with_name("SYS_setpriority"))
.subcommand(clap::SubCommand::with_name("SYS_getpriority"))
.subcommand(clap::SubCommand::with_name("SYS_sysfs"))
.subcommand(clap::SubCommand::with_name("SYS_fstatfs"))
.subcommand(clap::SubCommand::with_name("SYS_statfs"))
.subcommand(clap::SubCommand::with_name("SYS_ustat"))
.subcommand(clap::SubCommand::with_name("SYS_personality"))
.subcommand(clap::SubCommand::with_name("SYS_uselib"))
.subcommand(clap::SubCommand::with_name("SYS_mknod"))
.subcommand(clap::SubCommand::with_name("SYS_utime"))
.subcommand(clap::SubCommand::with_name("SYS_sigaltstack"))
.subcommand(clap::SubCommand::with_name("SYS_rt_sigsuspend"))
.subcommand(clap::SubCommand::with_name("SYS_rt_sigqueueinfo"))
.subcommand(clap::SubCommand::with_name("SYS_rt_sigtimedwait"))
.subcommand(clap::SubCommand::with_name("SYS_rt_sigpending"))
.subcommand(clap::SubCommand::with_name("SYS_capset"))
.subcommand(clap::SubCommand::with_name("SYS_capget"))
.subcommand(clap::SubCommand::with_name("SYS_getsid"))
.subcommand(clap::SubCommand::with_name("SYS_setfsgid"))
.subcommand(clap::SubCommand::with_name("SYS_setfsuid"))
.subcommand(clap::SubCommand::with_name("SYS_getpgid"))
.subcommand(clap::SubCommand::with_name("SYS_getresgid"))
.subcommand(clap::SubCommand::with_name("SYS_setresgid"))
.subcommand(clap::SubCommand::with_name("SYS_getresuid"))
.subcommand(clap::SubCommand::with_name("SYS_setresuid"))
.subcommand(clap::SubCommand::with_name("SYS_setgroups"))
.subcommand(clap::SubCommand::with_name("SYS_getgroups"))
.subcommand(clap::SubCommand::with_name("SYS_setregid"))
.subcommand(clap::SubCommand::with_name("SYS_setreuid"))
.subcommand(clap::SubCommand::with_name("SYS_setsid"))
.subcommand(clap::SubCommand::with_name("SYS_getpgrp"))
.subcommand(clap::SubCommand::with_name("SYS_getppid"))
.subcommand(clap::SubCommand::with_name("SYS_setpgid"))
.subcommand(clap::SubCommand::with_name("SYS_getegid"))
.subcommand(clap::SubCommand::with_name("SYS_geteuid"))
.subcommand(clap::SubCommand::with_name("SYS_setgid"))
.subcommand(clap::SubCommand::with_name("SYS_setuid"))
.subcommand(clap::SubCommand::with_name("SYS_getgid"))
.subcommand(clap::SubCommand::with_name("SYS_syslog"))
.subcommand(clap::SubCommand::with_name("SYS_getuid"))
.subcommand(clap::SubCommand::with_name("SYS_ptrace"))
.subcommand(clap::SubCommand::with_name("SYS_times"))
.subcommand(clap::SubCommand::with_name("SYS_sysinfo"))
.subcommand(clap::SubCommand::with_name("SYS_getrusage"))
.subcommand(clap::SubCommand::with_name("SYS_getrlimit"))
.subcommand(clap::SubCommand::with_name("SYS_gettimeofday"))
.subcommand(clap::SubCommand::with_name("SYS_umask"))
.subcommand(clap::SubCommand::with_name("SYS_lchown"))
.subcommand(clap::SubCommand::with_name("SYS_fchown"))
.subcommand(clap::SubCommand::with_name("SYS_chown"))
.subcommand(clap::SubCommand::with_name("SYS_fchmod"))
.subcommand(clap::SubCommand::with_name("SYS_chmod"))
.subcommand(clap::SubCommand::with_name("SYS_readlink"))
.subcommand(clap::SubCommand::with_name("SYS_symlink"))
.subcommand(clap::SubCommand::with_name("SYS_unlink"))
.subcommand(clap::SubCommand::with_name("SYS_link"))
.subcommand(clap::SubCommand::with_name("SYS_creat"))
.subcommand(clap::SubCommand::with_name("SYS_rmdir"))
.subcommand(clap::SubCommand::with_name("SYS_mkdir"))
.subcommand(clap::SubCommand::with_name("SYS_rename"))
.subcommand(clap::SubCommand::with_name("SYS_fchdir"))
.subcommand(clap::SubCommand::with_name("SYS_chdir"))
.subcommand(clap::SubCommand::with_name("SYS_getcwd"))
.subcommand(clap::SubCommand::with_name("SYS_getdents"))
.subcommand(clap::SubCommand::with_name("SYS_ftruncate"))
.subcommand(clap::SubCommand::with_name("SYS_truncate"))
.subcommand(clap::SubCommand::with_name("SYS_fdatasync"))
.subcommand(clap::SubCommand::with_name("SYS_fsync"))
.subcommand(clap::SubCommand::with_name("SYS_flock"))
.subcommand(clap::SubCommand::with_name("SYS_fcntl"))
.subcommand(clap::SubCommand::with_name("SYS_msgctl"))
.subcommand(clap::SubCommand::with_name("SYS_msgrcv"))
.subcommand(clap::SubCommand::with_name("SYS_msgsnd"))
.subcommand(clap::SubCommand::with_name("SYS_msgget"))
.subcommand(clap::SubCommand::with_name("SYS_shmdt"))
.subcommand(clap::SubCommand::with_name("SYS_semctl"))
.subcommand(clap::SubCommand::with_name("SYS_semop"))
.subcommand(clap::SubCommand::with_name("SYS_semget"))
.subcommand(clap::SubCommand::with_name("SYS_uname"))
.subcommand(clap::SubCommand::with_name("SYS_kill"))
.subcommand(clap::SubCommand::with_name("SYS_wait4"))
.subcommand(clap::SubCommand::with_name("SYS_exit"))
.subcommand(clap::SubCommand::with_name("SYS_execve"))
.subcommand(clap::SubCommand::with_name("SYS_vfork"))
.subcommand(clap::SubCommand::with_name("SYS_fork"))
.subcommand(clap::SubCommand::with_name("SYS_clone"))
.subcommand(clap::SubCommand::with_name("SYS_getsockopt"))
.subcommand(clap::SubCommand::with_name("SYS_setsockopt"))
.subcommand(clap::SubCommand::with_name("SYS_socketpair"))
.subcommand(clap::SubCommand::with_name("SYS_getpeername"))
.subcommand(clap::SubCommand::with_name("SYS_getsockname"))
.subcommand(clap::SubCommand::with_name("SYS_listen"))
.subcommand(clap::SubCommand::with_name("SYS_bind"))
.subcommand(clap::SubCommand::with_name("SYS_shutdown"))
.subcommand(clap::SubCommand::with_name("SYS_recvmsg"))
.subcommand(clap::SubCommand::with_name("SYS_sendmsg"))
.subcommand(clap::SubCommand::with_name("SYS_recvfrom"))
.subcommand(clap::SubCommand::with_name("SYS_sendto"))
.subcommand(clap::SubCommand::with_name("SYS_accept"))
.subcommand(clap::SubCommand::with_name("SYS_connect"))
.subcommand(clap::SubCommand::with_name("SYS_socket"))
.subcommand(clap::SubCommand::with_name("SYS_sendfile"))
.subcommand(clap::SubCommand::with_name("SYS_getpid"))
.subcommand(clap::SubCommand::with_name("SYS_setitimer"))
.subcommand(clap::SubCommand::with_name("SYS_alarm"))
.subcommand(clap::SubCommand::with_name("SYS_getitimer"))
.subcommand(clap::SubCommand::with_name("SYS_nanosleep"))
.subcommand(clap::SubCommand::with_name("SYS_pause"))
.subcommand(clap::SubCommand::with_name("SYS_dup2"))
.subcommand(clap::SubCommand::with_name("SYS_dup"))
.subcommand(clap::SubCommand::with_name("SYS_shmctl"))
.subcommand(clap::SubCommand::with_name("SYS_shmat"))
.subcommand(clap::SubCommand::with_name("SYS_shmget"))
.subcommand(clap::SubCommand::with_name("SYS_madvise"))
.subcommand(clap::SubCommand::with_name("SYS_mincore"))
.subcommand(clap::SubCommand::with_name("SYS_msync"))
.subcommand(clap::SubCommand::with_name("SYS_mremap"))
.subcommand(clap::SubCommand::with_name("SYS_sched_yield"))
.subcommand(clap::SubCommand::with_name("SYS_select"))
.subcommand(clap::SubCommand::with_name("SYS_pipe"))
.subcommand(clap::SubCommand::with_name("SYS_access"))
.subcommand(clap::SubCommand::with_name("SYS_writev"))
.subcommand(clap::SubCommand::with_name("SYS_readv"))
.subcommand(clap::SubCommand::with_name("SYS_pwrite64"))
.subcommand(clap::SubCommand::with_name("SYS_pread64"))
.subcommand(clap::SubCommand::with_name("SYS_ioctl"))
.subcommand(clap::SubCommand::with_name("SYS_rt_sigreturn"))
.subcommand(clap::SubCommand::with_name("SYS_rt_sigprocmask"))
.subcommand(clap::SubCommand::with_name("SYS_rt_sigaction"))
.subcommand(clap::SubCommand::with_name("SYS_brk"))
.subcommand(clap::SubCommand::with_name("SYS_munmap"))
.subcommand(clap::SubCommand::with_name("SYS_mprotect"))
.subcommand(clap::SubCommand::with_name("SYS_mmap"))
.subcommand(clap::SubCommand::with_name("SYS_lseek"))
.subcommand(clap::SubCommand::with_name("SYS_poll"))
.subcommand(clap::SubCommand::with_name("SYS_lstat"))
.subcommand(clap::SubCommand::with_name("SYS_fstat"))
.subcommand(clap::SubCommand::with_name("SYS_stat"))
.subcommand(clap::SubCommand::with_name("SYS_close"))
.subcommand(clap::SubCommand::with_name("SYS_open"))
.subcommand(clap::SubCommand::with_name("SYS_write"))
.subcommand(clap::SubCommand::with_name("SYS_read"))
.subcommand(clap::SubCommand::with_name("__SIZEOF_PTHREAD_RWLOCK_T"))
.subcommand(clap::SubCommand::with_name("__SIZEOF_PTHREAD_MUTEX_T"))
.subcommand(clap::SubCommand::with_name("REG_CR2"))
.subcommand(clap::SubCommand::with_name("REG_OLDMASK"))
.subcommand(clap::SubCommand::with_name("REG_TRAPNO"))
.subcommand(clap::SubCommand::with_name("REG_ERR"))
.subcommand(clap::SubCommand::with_name("REG_CSGSFS"))
.subcommand(clap::SubCommand::with_name("REG_EFL"))
.subcommand(clap::SubCommand::with_name("REG_RIP"))
.subcommand(clap::SubCommand::with_name("REG_RSP"))
.subcommand(clap::SubCommand::with_name("REG_RCX"))
.subcommand(clap::SubCommand::with_name("REG_RAX"))
.subcommand(clap::SubCommand::with_name("REG_RDX"))
.subcommand(clap::SubCommand::with_name("REG_RBX"))
.subcommand(clap::SubCommand::with_name("REG_RBP"))
.subcommand(clap::SubCommand::with_name("REG_RSI"))
.subcommand(clap::SubCommand::with_name("REG_RDI"))
.subcommand(clap::SubCommand::with_name("REG_R15"))
.subcommand(clap::SubCommand::with_name("REG_R14"))
.subcommand(clap::SubCommand::with_name("REG_R13"))
.subcommand(clap::SubCommand::with_name("REG_R12"))
.subcommand(clap::SubCommand::with_name("REG_R11"))
.subcommand(clap::SubCommand::with_name("REG_R10"))
.subcommand(clap::SubCommand::with_name("REG_R9"))
.subcommand(clap::SubCommand::with_name("REG_R8"))
.subcommand(clap::SubCommand::with_name("GS"))
.subcommand(clap::SubCommand::with_name("FS"))
.subcommand(clap::SubCommand::with_name("ES"))
.subcommand(clap::SubCommand::with_name("DS"))
.subcommand(clap::SubCommand::with_name("GS_BASE"))
.subcommand(clap::SubCommand::with_name("FS_BASE"))
.subcommand(clap::SubCommand::with_name("SS"))
.subcommand(clap::SubCommand::with_name("RSP"))
.subcommand(clap::SubCommand::with_name("EFLAGS"))
.subcommand(clap::SubCommand::with_name("CS"))
.subcommand(clap::SubCommand::with_name("RIP"))
.subcommand(clap::SubCommand::with_name("ORIG_RAX"))
.subcommand(clap::SubCommand::with_name("RDI"))
.subcommand(clap::SubCommand::with_name("RSI"))
.subcommand(clap::SubCommand::with_name("RDX"))
.subcommand(clap::SubCommand::with_name("RCX"))
.subcommand(clap::SubCommand::with_name("RAX"))
.subcommand(clap::SubCommand::with_name("R8"))
.subcommand(clap::SubCommand::with_name("R9"))
.subcommand(clap::SubCommand::with_name("R10"))
.subcommand(clap::SubCommand::with_name("R11"))
.subcommand(clap::SubCommand::with_name("RBX"))
.subcommand(clap::SubCommand::with_name("RBP"))
.subcommand(clap::SubCommand::with_name("R12"))
.subcommand(clap::SubCommand::with_name("R13"))
.subcommand(clap::SubCommand::with_name("R14"))
.subcommand(clap::SubCommand::with_name("R15"))
.subcommand(clap::SubCommand::with_name("FIONREAD"))
.subcommand(clap::SubCommand::with_name("TIOCSWINSZ"))
.subcommand(clap::SubCommand::with_name("TIOCGWINSZ"))
.subcommand(clap::SubCommand::with_name("TIOCOUTQ"))
.subcommand(clap::SubCommand::with_name("TIOCSPGRP"))
.subcommand(clap::SubCommand::with_name("TIOCGPGRP"))
.subcommand(clap::SubCommand::with_name("TIOCINQ"))
.subcommand(clap::SubCommand::with_name("TCFLSH"))
.subcommand(clap::SubCommand::with_name("TCXONC"))
.subcommand(clap::SubCommand::with_name("TCSBRK"))
.subcommand(clap::SubCommand::with_name("TCSETAF"))
.subcommand(clap::SubCommand::with_name("TCSETAW"))
.subcommand(clap::SubCommand::with_name("TCSETA"))
.subcommand(clap::SubCommand::with_name("TCGETA"))
.subcommand(clap::SubCommand::with_name("TCSETSF"))
.subcommand(clap::SubCommand::with_name("TCSETSW"))
.subcommand(clap::SubCommand::with_name("TCSETS"))
.subcommand(clap::SubCommand::with_name("TCGETS"))
.subcommand(clap::SubCommand::with_name("EXTPROC"))
.subcommand(clap::SubCommand::with_name("FLUSHO"))
.subcommand(clap::SubCommand::with_name("TOSTOP"))
.subcommand(clap::SubCommand::with_name("IEXTEN"))
.subcommand(clap::SubCommand::with_name("VMIN"))
.subcommand(clap::SubCommand::with_name("VEOL2"))
.subcommand(clap::SubCommand::with_name("VEOL"))
.subcommand(clap::SubCommand::with_name("B4000000"))
.subcommand(clap::SubCommand::with_name("B3500000"))
.subcommand(clap::SubCommand::with_name("B3000000"))
.subcommand(clap::SubCommand::with_name("B2500000"))
.subcommand(clap::SubCommand::with_name("B2000000"))
.subcommand(clap::SubCommand::with_name("B1500000"))
.subcommand(clap::SubCommand::with_name("B1152000"))
.subcommand(clap::SubCommand::with_name("B1000000"))
.subcommand(clap::SubCommand::with_name("B921600"))
.subcommand(clap::SubCommand::with_name("B576000"))
.subcommand(clap::SubCommand::with_name("B500000"))
.subcommand(clap::SubCommand::with_name("B460800"))
.subcommand(clap::SubCommand::with_name("B230400"))
.subcommand(clap::SubCommand::with_name("B115200"))
.subcommand(clap::SubCommand::with_name("B57600"))
.subcommand(clap::SubCommand::with_name("BOTHER"))
.subcommand(clap::SubCommand::with_name("EXTB"))
.subcommand(clap::SubCommand::with_name("EXTA"))
.subcommand(clap::SubCommand::with_name("B38400"))
.subcommand(clap::SubCommand::with_name("B19200"))
.subcommand(clap::SubCommand::with_name("B9600"))
.subcommand(clap::SubCommand::with_name("B4800"))
.subcommand(clap::SubCommand::with_name("B2400"))
.subcommand(clap::SubCommand::with_name("B1800"))
.subcommand(clap::SubCommand::with_name("B1200"))
.subcommand(clap::SubCommand::with_name("B600"))
.subcommand(clap::SubCommand::with_name("B300"))
.subcommand(clap::SubCommand::with_name("B200"))
.subcommand(clap::SubCommand::with_name("B150"))
.subcommand(clap::SubCommand::with_name("B134"))
.subcommand(clap::SubCommand::with_name("B110"))
.subcommand(clap::SubCommand::with_name("B75"))
.subcommand(clap::SubCommand::with_name("B50"))
.subcommand(clap::SubCommand::with_name("B0"))
.subcommand(clap::SubCommand::with_name("XTABS"))
.subcommand(clap::SubCommand::with_name("VTDLY"))
.subcommand(clap::SubCommand::with_name("FFDLY"))
.subcommand(clap::SubCommand::with_name("BSDLY"))
.subcommand(clap::SubCommand::with_name("TABDLY"))
.subcommand(clap::SubCommand::with_name("CRDLY"))
.subcommand(clap::SubCommand::with_name("NLDLY"))
.subcommand(clap::SubCommand::with_name("OLCUC"))
.subcommand(clap::SubCommand::with_name("VSWTC"))
.subcommand(clap::SubCommand::with_name("CBAUDEX"))
.subcommand(clap::SubCommand::with_name("CIBAUD"))
.subcommand(clap::SubCommand::with_name("NOFLSH"))
.subcommand(clap::SubCommand::with_name("PENDIN"))
.subcommand(clap::SubCommand::with_name("ICANON"))
.subcommand(clap::SubCommand::with_name("ISIG"))
.subcommand(clap::SubCommand::with_name("ECHOCTL"))
.subcommand(clap::SubCommand::with_name("ECHOPRT"))
.subcommand(clap::SubCommand::with_name("ECHONL"))
.subcommand(clap::SubCommand::with_name("ECHOK"))
.subcommand(clap::SubCommand::with_name("ECHOE"))
.subcommand(clap::SubCommand::with_name("ECHOKE"))
.subcommand(clap::SubCommand::with_name("CLOCAL"))
.subcommand(clap::SubCommand::with_name("HUPCL"))
.subcommand(clap::SubCommand::with_name("PARODD"))
.subcommand(clap::SubCommand::with_name("PARENB"))
.subcommand(clap::SubCommand::with_name("CREAD"))
.subcommand(clap::SubCommand::with_name("CSTOPB"))
.subcommand(clap::SubCommand::with_name("CS8"))
.subcommand(clap::SubCommand::with_name("CS7"))
.subcommand(clap::SubCommand::with_name("CS6"))
.subcommand(clap::SubCommand::with_name("CSIZE"))
.subcommand(clap::SubCommand::with_name("ONLCR"))
.subcommand(clap::SubCommand::with_name("IXOFF"))
.subcommand(clap::SubCommand::with_name("IXON"))
.subcommand(clap::SubCommand::with_name("VTIME"))
.subcommand(clap::SubCommand::with_name("VDISCARD"))
.subcommand(clap::SubCommand::with_name("VSTOP"))
.subcommand(clap::SubCommand::with_name("VSTART"))
.subcommand(clap::SubCommand::with_name("VSUSP"))
.subcommand(clap::SubCommand::with_name("VREPRINT"))
.subcommand(clap::SubCommand::with_name("VWERASE"))
.subcommand(clap::SubCommand::with_name("VT1"))
.subcommand(clap::SubCommand::with_name("BS1"))
.subcommand(clap::SubCommand::with_name("FF1"))
.subcommand(clap::SubCommand::with_name("CR3"))
.subcommand(clap::SubCommand::with_name("CR2"))
.subcommand(clap::SubCommand::with_name("CR1"))
.subcommand(clap::SubCommand::with_name("TAB3"))
.subcommand(clap::SubCommand::with_name("TAB2"))
.subcommand(clap::SubCommand::with_name("TAB1"))
.subcommand(clap::SubCommand::with_name("CBAUD"))
.subcommand(clap::SubCommand::with_name("MINSIGSTKSZ"))
.subcommand(clap::SubCommand::with_name("SIGSTKSZ"))
.subcommand(clap::SubCommand::with_name("MCL_FUTURE"))
.subcommand(clap::SubCommand::with_name("MCL_CURRENT"))
.subcommand(clap::SubCommand::with_name("PTRACE_PEEKSIGINFO_SHARED"))
.subcommand(clap::SubCommand::with_name("PTRACE_SETREGS"))
.subcommand(clap::SubCommand::with_name("PTRACE_GETREGS"))
.subcommand(clap::SubCommand::with_name("PTRACE_SETFPXREGS"))
.subcommand(clap::SubCommand::with_name("PTRACE_GETFPXREGS"))
.subcommand(clap::SubCommand::with_name("PTRACE_SETFPREGS"))
.subcommand(clap::SubCommand::with_name("PTRACE_GETFPREGS"))
.subcommand(clap::SubCommand::with_name("FIONBIO"))
.subcommand(clap::SubCommand::with_name("FIONCLEX"))
.subcommand(clap::SubCommand::with_name("FIOCLEX"))
.subcommand(clap::SubCommand::with_name("EREMOTEIO"))
.subcommand(clap::SubCommand::with_name("EISNAM"))
.subcommand(clap::SubCommand::with_name("ENAVAIL"))
.subcommand(clap::SubCommand::with_name("ENOTNAM"))
.subcommand(clap::SubCommand::with_name("EUCLEAN"))
.subcommand(clap::SubCommand::with_name("EDEADLOCK"))
.subcommand(clap::SubCommand::with_name("MAP_SYNC"))
.subcommand(clap::SubCommand::with_name("MAP_STACK"))
.subcommand(clap::SubCommand::with_name("MAP_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("MAP_POPULATE"))
.subcommand(clap::SubCommand::with_name("MAP_EXECUTABLE"))
.subcommand(clap::SubCommand::with_name("MAP_DENYWRITE"))
.subcommand(clap::SubCommand::with_name("MAP_ANONYMOUS"))
.subcommand(clap::SubCommand::with_name("MAP_ANON"))
.subcommand(clap::SubCommand::with_name("MAP_32BIT"))
.subcommand(clap::SubCommand::with_name("MAP_NORESERVE"))
.subcommand(clap::SubCommand::with_name("MAP_LOCKED"))
.subcommand(clap::SubCommand::with_name("MAP_HUGETLB"))
.subcommand(clap::SubCommand::with_name("O_NOFOLLOW"))
.subcommand(clap::SubCommand::with_name("O_DIRECTORY"))
.subcommand(clap::SubCommand::with_name("O_DIRECT"))
.subcommand(clap::SubCommand::with_name("__SIZEOF_PTHREAD_MUTEXATTR_T"))
.subcommand(clap::SubCommand::with_name("__SIZEOF_PTHREAD_CONDATTR_T"))
.subcommand(clap::SubCommand::with_name("EFD_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("EPOLL_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("SA_NOCLDSTOP"))
.subcommand(clap::SubCommand::with_name("SA_RESTART"))
.subcommand(clap::SubCommand::with_name("SA_RESETHAND"))
.subcommand(clap::SubCommand::with_name("SA_NODEFER"))
.subcommand(clap::SubCommand::with_name("EDOTDOT"))
.subcommand(clap::SubCommand::with_name("EPROTO"))
.subcommand(clap::SubCommand::with_name("ECOMM"))
.subcommand(clap::SubCommand::with_name("ESRMNT"))
.subcommand(clap::SubCommand::with_name("EADV"))
.subcommand(clap::SubCommand::with_name("ENOLINK"))
.subcommand(clap::SubCommand::with_name("EREMOTE"))
.subcommand(clap::SubCommand::with_name("ENOPKG"))
.subcommand(clap::SubCommand::with_name("ENONET"))
.subcommand(clap::SubCommand::with_name("ENOSR"))
.subcommand(clap::SubCommand::with_name("ETIME"))
.subcommand(clap::SubCommand::with_name("ENODATA"))
.subcommand(clap::SubCommand::with_name("ENOSTR"))
.subcommand(clap::SubCommand::with_name("EBFONT"))
.subcommand(clap::SubCommand::with_name("O_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("O_TRUNC"))
.subcommand(clap::SubCommand::with_name("NCCS"))
.subcommand(clap::SubCommand::with_name("SFD_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("TIOCM_DSR"))
.subcommand(clap::SubCommand::with_name("TIOCM_RNG"))
.subcommand(clap::SubCommand::with_name("TIOCM_CAR"))
.subcommand(clap::SubCommand::with_name("TIOCM_CTS"))
.subcommand(clap::SubCommand::with_name("TIOCM_SR"))
.subcommand(clap::SubCommand::with_name("TIOCM_ST"))
.subcommand(clap::SubCommand::with_name("TIOCCONS"))
.subcommand(clap::SubCommand::with_name("TIOCMSET"))
.subcommand(clap::SubCommand::with_name("TIOCMBIC"))
.subcommand(clap::SubCommand::with_name("TIOCMBIS"))
.subcommand(clap::SubCommand::with_name("TIOCMGET"))
.subcommand(clap::SubCommand::with_name("TIOCSTI"))
.subcommand(clap::SubCommand::with_name("TIOCSCTTY"))
.subcommand(clap::SubCommand::with_name("TIOCNXCL"))
.subcommand(clap::SubCommand::with_name("TIOCEXCL"))
.subcommand(clap::SubCommand::with_name("TIOCGSERIAL"))
.subcommand(clap::SubCommand::with_name("TIOCLINUX"))
.subcommand(clap::SubCommand::with_name("TCSAFLUSH"))
.subcommand(clap::SubCommand::with_name("TCSADRAIN"))
.subcommand(clap::SubCommand::with_name("TCSANOW"))
.subcommand(clap::SubCommand::with_name("SFD_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("F_UNLCK"))
.subcommand(clap::SubCommand::with_name("F_WRLCK"))
.subcommand(clap::SubCommand::with_name("F_RDLCK"))
.subcommand(clap::SubCommand::with_name("F_OFD_SETLKW"))
.subcommand(clap::SubCommand::with_name("F_OFD_SETLK"))
.subcommand(clap::SubCommand::with_name("F_OFD_GETLK"))
.subcommand(clap::SubCommand::with_name("F_SETLKW"))
.subcommand(clap::SubCommand::with_name("F_SETLK"))
.subcommand(clap::SubCommand::with_name("F_SETOWN"))
.subcommand(clap::SubCommand::with_name("F_GETOWN"))
.subcommand(clap::SubCommand::with_name("F_GETLK"))
.subcommand(clap::SubCommand::with_name("EFD_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("PTRACE_DETACH"))
.subcommand(clap::SubCommand::with_name("O_NDELAY"))
.subcommand(clap::SubCommand::with_name("O_ASYNC"))
.subcommand(clap::SubCommand::with_name("POLLWRBAND"))
.subcommand(clap::SubCommand::with_name("POLLWRNORM"))
.subcommand(clap::SubCommand::with_name("SIG_UNBLOCK"))
.subcommand(clap::SubCommand::with_name("SIG_BLOCK"))
.subcommand(clap::SubCommand::with_name("SIG_SETMASK"))
.subcommand(clap::SubCommand::with_name("SIGPWR"))
.subcommand(clap::SubCommand::with_name("SIGPOLL"))
.subcommand(clap::SubCommand::with_name("SIGUNUSED"))
.subcommand(clap::SubCommand::with_name("SIGSTKFLT"))
.subcommand(clap::SubCommand::with_name("SIGSYS"))
.subcommand(clap::SubCommand::with_name("SIGIO"))
.subcommand(clap::SubCommand::with_name("SIGURG"))
.subcommand(clap::SubCommand::with_name("SIGTSTP"))
.subcommand(clap::SubCommand::with_name("SIGSTOP"))
.subcommand(clap::SubCommand::with_name("SIGCONT"))
.subcommand(clap::SubCommand::with_name("SIGUSR2"))
.subcommand(clap::SubCommand::with_name("SIGUSR1"))
.subcommand(clap::SubCommand::with_name("SIGBUS"))
.subcommand(clap::SubCommand::with_name("SIGCHLD"))
.subcommand(clap::SubCommand::with_name("SIGWINCH"))
.subcommand(clap::SubCommand::with_name("SIGPROF"))
.subcommand(clap::SubCommand::with_name("SIGVTALRM"))
.subcommand(clap::SubCommand::with_name("SIGXFSZ"))
.subcommand(clap::SubCommand::with_name("SIGXCPU"))
.subcommand(clap::SubCommand::with_name("SIGTTOU"))
.subcommand(clap::SubCommand::with_name("SIGTTIN"))
.subcommand(clap::SubCommand::with_name("SA_NOCLDWAIT"))
.subcommand(clap::SubCommand::with_name("SA_SIGINFO"))
.subcommand(clap::SubCommand::with_name("SA_ONSTACK"))
.subcommand(clap::SubCommand::with_name("SOCK_DGRAM"))
.subcommand(clap::SubCommand::with_name("SOCK_STREAM"))
.subcommand(clap::SubCommand::with_name("SO_DETACH_BPF"))
.subcommand(clap::SubCommand::with_name("SO_ATTACH_BPF"))
.subcommand(clap::SubCommand::with_name("SO_INCOMING_CPU"))
.subcommand(clap::SubCommand::with_name("SO_BPF_EXTENSIONS"))
.subcommand(clap::SubCommand::with_name("SO_MAX_PACING_RATE"))
.subcommand(clap::SubCommand::with_name("SO_BUSY_POLL"))
.subcommand(clap::SubCommand::with_name("SO_SELECT_ERR_QUEUE"))
.subcommand(clap::SubCommand::with_name("SO_LOCK_FILTER"))
.subcommand(clap::SubCommand::with_name("SO_NOFCS"))
.subcommand(clap::SubCommand::with_name("SO_PEEK_OFF"))
.subcommand(clap::SubCommand::with_name("SCM_WIFI_STATUS"))
.subcommand(clap::SubCommand::with_name("SO_WIFI_STATUS"))
.subcommand(clap::SubCommand::with_name("SO_RXQ_OVFL"))
.subcommand(clap::SubCommand::with_name("SO_DOMAIN"))
.subcommand(clap::SubCommand::with_name("SO_PROTOCOL"))
.subcommand(clap::SubCommand::with_name("SO_MARK"))
.subcommand(clap::SubCommand::with_name("SCM_TIMESTAMPNS"))
.subcommand(clap::SubCommand::with_name("SO_TIMESTAMPNS"))
.subcommand(clap::SubCommand::with_name("SO_PASSSEC"))
.subcommand(clap::SubCommand::with_name("SO_PEERSEC"))
.subcommand(clap::SubCommand::with_name("SO_ACCEPTCONN"))
.subcommand(clap::SubCommand::with_name("SO_TIMESTAMP"))
.subcommand(clap::SubCommand::with_name("SO_PEERNAME"))
.subcommand(clap::SubCommand::with_name("SO_GET_FILTER"))
.subcommand(clap::SubCommand::with_name("SO_DETACH_FILTER"))
.subcommand(clap::SubCommand::with_name("SO_ATTACH_FILTER"))
.subcommand(clap::SubCommand::with_name("SO_BINDTODEVICE"))
.subcommand(clap::SubCommand::with_name("SO_SECURITY_ENCRYPTION_NETWORK"))
.subcommand(clap::SubCommand::with_name("SO_SECURITY_ENCRYPTION_TRANSPORT"))
.subcommand(clap::SubCommand::with_name("SO_SECURITY_AUTHENTICATION"))
.subcommand(clap::SubCommand::with_name("SO_SNDTIMEO"))
.subcommand(clap::SubCommand::with_name("SO_RCVTIMEO"))
.subcommand(clap::SubCommand::with_name("SO_SNDLOWAT"))
.subcommand(clap::SubCommand::with_name("SO_RCVLOWAT"))
.subcommand(clap::SubCommand::with_name("SO_PEERCRED"))
.subcommand(clap::SubCommand::with_name("SO_PASSCRED"))
.subcommand(clap::SubCommand::with_name("SO_REUSEPORT"))
.subcommand(clap::SubCommand::with_name("SO_BSDCOMPAT"))
.subcommand(clap::SubCommand::with_name("SO_LINGER"))
.subcommand(clap::SubCommand::with_name("SO_PRIORITY"))
.subcommand(clap::SubCommand::with_name("SO_NO_CHECK"))
.subcommand(clap::SubCommand::with_name("SO_OOBINLINE"))
.subcommand(clap::SubCommand::with_name("SO_KEEPALIVE"))
.subcommand(clap::SubCommand::with_name("SO_RCVBUFFORCE"))
.subcommand(clap::SubCommand::with_name("SO_SNDBUFFORCE"))
.subcommand(clap::SubCommand::with_name("SO_RCVBUF"))
.subcommand(clap::SubCommand::with_name("SO_SNDBUF"))
.subcommand(clap::SubCommand::with_name("SO_BROADCAST"))
.subcommand(clap::SubCommand::with_name("SO_DONTROUTE"))
.subcommand(clap::SubCommand::with_name("SO_ERROR"))
.subcommand(clap::SubCommand::with_name("SO_TYPE"))
.subcommand(clap::SubCommand::with_name("SO_REUSEADDR"))
.subcommand(clap::SubCommand::with_name("SOL_SOCKET"))
.subcommand(clap::SubCommand::with_name("ERFKILL"))
.subcommand(clap::SubCommand::with_name("EHWPOISON"))
.subcommand(clap::SubCommand::with_name("ENOTRECOVERABLE"))
.subcommand(clap::SubCommand::with_name("EOWNERDEAD"))
.subcommand(clap::SubCommand::with_name("EKEYREJECTED"))
.subcommand(clap::SubCommand::with_name("EKEYREVOKED"))
.subcommand(clap::SubCommand::with_name("EKEYEXPIRED"))
.subcommand(clap::SubCommand::with_name("ENOKEY"))
.subcommand(clap::SubCommand::with_name("ECANCELED"))
.subcommand(clap::SubCommand::with_name("EMEDIUMTYPE"))
.subcommand(clap::SubCommand::with_name("ENOMEDIUM"))
.subcommand(clap::SubCommand::with_name("EDQUOT"))
.subcommand(clap::SubCommand::with_name("ESTALE"))
.subcommand(clap::SubCommand::with_name("EINPROGRESS"))
.subcommand(clap::SubCommand::with_name("EALREADY"))
.subcommand(clap::SubCommand::with_name("EHOSTUNREACH"))
.subcommand(clap::SubCommand::with_name("EHOSTDOWN"))
.subcommand(clap::SubCommand::with_name("ECONNREFUSED"))
.subcommand(clap::SubCommand::with_name("ETIMEDOUT"))
.subcommand(clap::SubCommand::with_name("ETOOMANYREFS"))
.subcommand(clap::SubCommand::with_name("ESHUTDOWN"))
.subcommand(clap::SubCommand::with_name("ENOTCONN"))
.subcommand(clap::SubCommand::with_name("EISCONN"))
.subcommand(clap::SubCommand::with_name("ENOBUFS"))
.subcommand(clap::SubCommand::with_name("ECONNRESET"))
.subcommand(clap::SubCommand::with_name("ECONNABORTED"))
.subcommand(clap::SubCommand::with_name("ENETRESET"))
.subcommand(clap::SubCommand::with_name("ENETUNREACH"))
.subcommand(clap::SubCommand::with_name("ENETDOWN"))
.subcommand(clap::SubCommand::with_name("EADDRNOTAVAIL"))
.subcommand(clap::SubCommand::with_name("EADDRINUSE"))
.subcommand(clap::SubCommand::with_name("EAFNOSUPPORT"))
.subcommand(clap::SubCommand::with_name("EPFNOSUPPORT"))
.subcommand(clap::SubCommand::with_name("EOPNOTSUPP"))
.subcommand(clap::SubCommand::with_name("ESOCKTNOSUPPORT"))
.subcommand(clap::SubCommand::with_name("EPROTONOSUPPORT"))
.subcommand(clap::SubCommand::with_name("ENOPROTOOPT"))
.subcommand(clap::SubCommand::with_name("EPROTOTYPE"))
.subcommand(clap::SubCommand::with_name("EMSGSIZE"))
.subcommand(clap::SubCommand::with_name("EDESTADDRREQ"))
.subcommand(clap::SubCommand::with_name("ENOTSOCK"))
.subcommand(clap::SubCommand::with_name("EUSERS"))
.subcommand(clap::SubCommand::with_name("ESTRPIPE"))
.subcommand(clap::SubCommand::with_name("ERESTART"))
.subcommand(clap::SubCommand::with_name("EILSEQ"))
.subcommand(clap::SubCommand::with_name("ELIBEXEC"))
.subcommand(clap::SubCommand::with_name("ELIBMAX"))
.subcommand(clap::SubCommand::with_name("ELIBSCN"))
.subcommand(clap::SubCommand::with_name("ELIBBAD"))
.subcommand(clap::SubCommand::with_name("ELIBACC"))
.subcommand(clap::SubCommand::with_name("EREMCHG"))
.subcommand(clap::SubCommand::with_name("EBADMSG"))
.subcommand(clap::SubCommand::with_name("EBADFD"))
.subcommand(clap::SubCommand::with_name("ENOTUNIQ"))
.subcommand(clap::SubCommand::with_name("EOVERFLOW"))
.subcommand(clap::SubCommand::with_name("EMULTIHOP"))
.subcommand(clap::SubCommand::with_name("EBADSLT"))
.subcommand(clap::SubCommand::with_name("EBADRQC"))
.subcommand(clap::SubCommand::with_name("ENOANO"))
.subcommand(clap::SubCommand::with_name("EXFULL"))
.subcommand(clap::SubCommand::with_name("EBADR"))
.subcommand(clap::SubCommand::with_name("EBADE"))
.subcommand(clap::SubCommand::with_name("EL2HLT"))
.subcommand(clap::SubCommand::with_name("ENOCSI"))
.subcommand(clap::SubCommand::with_name("EUNATCH"))
.subcommand(clap::SubCommand::with_name("ELNRNG"))
.subcommand(clap::SubCommand::with_name("EL3RST"))
.subcommand(clap::SubCommand::with_name("EL3HLT"))
.subcommand(clap::SubCommand::with_name("EL2NSYNC"))
.subcommand(clap::SubCommand::with_name("ECHRNG"))
.subcommand(clap::SubCommand::with_name("EIDRM"))
.subcommand(clap::SubCommand::with_name("ENOMSG"))
.subcommand(clap::SubCommand::with_name("ELOOP"))
.subcommand(clap::SubCommand::with_name("ENOTEMPTY"))
.subcommand(clap::SubCommand::with_name("ENOSYS"))
.subcommand(clap::SubCommand::with_name("ENOLCK"))
.subcommand(clap::SubCommand::with_name("ENAMETOOLONG"))
.subcommand(clap::SubCommand::with_name("EDEADLK"))
.subcommand(clap::SubCommand::with_name("MAP_GROWSDOWN"))
.subcommand(clap::SubCommand::with_name("MADV_SOFT_OFFLINE"))
.subcommand(clap::SubCommand::with_name("O_TMPFILE"))
.subcommand(clap::SubCommand::with_name("O_PATH"))
.subcommand(clap::SubCommand::with_name("O_NOATIME"))
.subcommand(clap::SubCommand::with_name("O_FSYNC"))
.subcommand(clap::SubCommand::with_name("O_DSYNC"))
.subcommand(clap::SubCommand::with_name("O_RSYNC"))
.subcommand(clap::SubCommand::with_name("O_SYNC"))
.subcommand(clap::SubCommand::with_name("O_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("O_NOCTTY"))
.subcommand(clap::SubCommand::with_name("O_EXCL"))
.subcommand(clap::SubCommand::with_name("O_CREAT"))
.subcommand(clap::SubCommand::with_name("O_APPEND"))
.subcommand(clap::SubCommand::with_name("RLIMIT_NPROC"))
.subcommand(clap::SubCommand::with_name("RLIMIT_NOFILE"))
.subcommand(clap::SubCommand::with_name("RLIMIT_MEMLOCK"))
.subcommand(clap::SubCommand::with_name("RLIMIT_AS"))
.subcommand(clap::SubCommand::with_name("RLIMIT_RSS"))
.subcommand(clap::SubCommand::with_name("TIOCSRS485"))
.subcommand(clap::SubCommand::with_name("TIOCGRS485"))
.subcommand(clap::SubCommand::with_name("TIOCSSOFTCAR"))
.subcommand(clap::SubCommand::with_name("TIOCGSOFTCAR"))
.subcommand(clap::SubCommand::with_name("RTLD_NOLOAD"))
.subcommand(clap::SubCommand::with_name("RTLD_GLOBAL"))
.subcommand(clap::SubCommand::with_name("RTLD_DEEPBIND"))
.subcommand(clap::SubCommand::with_name("VEOF"))
.subcommand(clap::SubCommand::with_name("POSIX_FADV_NOREUSE"))
.subcommand(clap::SubCommand::with_name("POSIX_FADV_DONTNEED"))
.subcommand(clap::SubCommand::with_name("O_LARGEFILE"))
.subcommand(clap::SubCommand::with_name("__SIZEOF_PTHREAD_RWLOCKATTR_T"))
.subcommand(clap::SubCommand::with_name("RLIM_INFINITY"))
.subcommand(clap::SubCommand::with_name("REG_ERPAREN"))
.subcommand(clap::SubCommand::with_name("REG_ESIZE"))
.subcommand(clap::SubCommand::with_name("REG_EEND"))
.subcommand(clap::SubCommand::with_name("REG_STARTEND"))
.subcommand(clap::SubCommand::with_name("PTHREAD_MUTEX_ADAPTIVE_NP"))
.subcommand(clap::SubCommand::with_name("PTHREAD_STACK_MIN"))
.subcommand(clap::SubCommand::with_name("MAXTC"))
.subcommand(clap::SubCommand::with_name("TIME_BAD"))
.subcommand(clap::SubCommand::with_name("TIME_ERROR"))
.subcommand(clap::SubCommand::with_name("TIME_WAIT"))
.subcommand(clap::SubCommand::with_name("TIME_OOP"))
.subcommand(clap::SubCommand::with_name("TIME_DEL"))
.subcommand(clap::SubCommand::with_name("TIME_INS"))
.subcommand(clap::SubCommand::with_name("TIME_OK"))
.subcommand(clap::SubCommand::with_name("NTP_API"))
.subcommand(clap::SubCommand::with_name("STA_RONLY"))
.subcommand(clap::SubCommand::with_name("STA_CLK"))
.subcommand(clap::SubCommand::with_name("STA_MODE"))
.subcommand(clap::SubCommand::with_name("STA_NANO"))
.subcommand(clap::SubCommand::with_name("STA_CLOCKERR"))
.subcommand(clap::SubCommand::with_name("STA_PPSERROR"))
.subcommand(clap::SubCommand::with_name("STA_PPSWANDER"))
.subcommand(clap::SubCommand::with_name("STA_PPSJITTER"))
.subcommand(clap::SubCommand::with_name("STA_PPSSIGNAL"))
.subcommand(clap::SubCommand::with_name("STA_FREQHOLD"))
.subcommand(clap::SubCommand::with_name("STA_UNSYNC"))
.subcommand(clap::SubCommand::with_name("STA_DEL"))
.subcommand(clap::SubCommand::with_name("STA_INS"))
.subcommand(clap::SubCommand::with_name("STA_FLL"))
.subcommand(clap::SubCommand::with_name("STA_PPSTIME"))
.subcommand(clap::SubCommand::with_name("STA_PPSFREQ"))
.subcommand(clap::SubCommand::with_name("STA_PLL"))
.subcommand(clap::SubCommand::with_name("MOD_NANO"))
.subcommand(clap::SubCommand::with_name("MOD_MICRO"))
.subcommand(clap::SubCommand::with_name("MOD_TAI"))
.subcommand(clap::SubCommand::with_name("MOD_CLKA"))
.subcommand(clap::SubCommand::with_name("MOD_CLKB"))
.subcommand(clap::SubCommand::with_name("MOD_TIMECONST"))
.subcommand(clap::SubCommand::with_name("MOD_STATUS"))
.subcommand(clap::SubCommand::with_name("MOD_ESTERROR"))
.subcommand(clap::SubCommand::with_name("MOD_MAXERROR"))
.subcommand(clap::SubCommand::with_name("MOD_FREQUENCY"))
.subcommand(clap::SubCommand::with_name("MOD_OFFSET"))
.subcommand(clap::SubCommand::with_name("ADJ_OFFSET_SS_READ"))
.subcommand(clap::SubCommand::with_name("ADJ_OFFSET_SINGLESHOT"))
.subcommand(clap::SubCommand::with_name("ADJ_TICK"))
.subcommand(clap::SubCommand::with_name("ADJ_NANO"))
.subcommand(clap::SubCommand::with_name("ADJ_MICRO"))
.subcommand(clap::SubCommand::with_name("ADJ_SETOFFSET"))
.subcommand(clap::SubCommand::with_name("ADJ_TAI"))
.subcommand(clap::SubCommand::with_name("ADJ_TIMECONST"))
.subcommand(clap::SubCommand::with_name("ADJ_STATUS"))
.subcommand(clap::SubCommand::with_name("ADJ_ESTERROR"))
.subcommand(clap::SubCommand::with_name("ADJ_MAXERROR"))
.subcommand(clap::SubCommand::with_name("ADJ_FREQUENCY"))
.subcommand(clap::SubCommand::with_name("ADJ_OFFSET"))
.subcommand(clap::SubCommand::with_name("AT_EXECFN"))
.subcommand(clap::SubCommand::with_name("AT_HWCAP2"))
.subcommand(clap::SubCommand::with_name("AT_RANDOM"))
.subcommand(clap::SubCommand::with_name("AT_BASE_PLATFORM"))
.subcommand(clap::SubCommand::with_name("AT_SECURE"))
.subcommand(clap::SubCommand::with_name("AT_CLKTCK"))
.subcommand(clap::SubCommand::with_name("AT_HWCAP"))
.subcommand(clap::SubCommand::with_name("AT_PLATFORM"))
.subcommand(clap::SubCommand::with_name("AT_EGID"))
.subcommand(clap::SubCommand::with_name("AT_GID"))
.subcommand(clap::SubCommand::with_name("AT_EUID"))
.subcommand(clap::SubCommand::with_name("AT_UID"))
.subcommand(clap::SubCommand::with_name("AT_NOTELF"))
.subcommand(clap::SubCommand::with_name("AT_ENTRY"))
.subcommand(clap::SubCommand::with_name("AT_FLAGS"))
.subcommand(clap::SubCommand::with_name("AT_BASE"))
.subcommand(clap::SubCommand::with_name("AT_PAGESZ"))
.subcommand(clap::SubCommand::with_name("AT_PHNUM"))
.subcommand(clap::SubCommand::with_name("AT_PHENT"))
.subcommand(clap::SubCommand::with_name("AT_PHDR"))
.subcommand(clap::SubCommand::with_name("AT_EXECFD"))
.subcommand(clap::SubCommand::with_name("AT_IGNORE"))
.subcommand(clap::SubCommand::with_name("AT_NULL"))
.subcommand(clap::SubCommand::with_name("STATX_ATTR_AUTOMOUNT"))
.subcommand(clap::SubCommand::with_name("STATX_ATTR_ENCRYPTED"))
.subcommand(clap::SubCommand::with_name("STATX_ATTR_NODUMP"))
.subcommand(clap::SubCommand::with_name("STATX_ATTR_APPEND"))
.subcommand(clap::SubCommand::with_name("STATX_ATTR_IMMUTABLE"))
.subcommand(clap::SubCommand::with_name("STATX_ATTR_COMPRESSED"))
.subcommand(clap::SubCommand::with_name("STATX__RESERVED"))
.subcommand(clap::SubCommand::with_name("STATX_ALL"))
.subcommand(clap::SubCommand::with_name("STATX_BTIME"))
.subcommand(clap::SubCommand::with_name("STATX_BASIC_STATS"))
.subcommand(clap::SubCommand::with_name("STATX_BLOCKS"))
.subcommand(clap::SubCommand::with_name("STATX_SIZE"))
.subcommand(clap::SubCommand::with_name("STATX_INO"))
.subcommand(clap::SubCommand::with_name("STATX_CTIME"))
.subcommand(clap::SubCommand::with_name("STATX_MTIME"))
.subcommand(clap::SubCommand::with_name("STATX_ATIME"))
.subcommand(clap::SubCommand::with_name("STATX_GID"))
.subcommand(clap::SubCommand::with_name("STATX_UID"))
.subcommand(clap::SubCommand::with_name("STATX_NLINK"))
.subcommand(clap::SubCommand::with_name("STATX_MODE"))
.subcommand(clap::SubCommand::with_name("STATX_TYPE"))
.subcommand(clap::SubCommand::with_name("AT_STATX_DONT_SYNC"))
.subcommand(clap::SubCommand::with_name("AT_STATX_FORCE_SYNC"))
.subcommand(clap::SubCommand::with_name("AT_STATX_SYNC_AS_STAT"))
.subcommand(clap::SubCommand::with_name("AT_STATX_SYNC_TYPE"))
.subcommand(clap::SubCommand::with_name("M_ARENA_MAX"))
.subcommand(clap::SubCommand::with_name("M_ARENA_TEST"))
.subcommand(clap::SubCommand::with_name("M_PERTURB"))
.subcommand(clap::SubCommand::with_name("M_CHECK_ACTION"))
.subcommand(clap::SubCommand::with_name("M_MMAP_MAX"))
.subcommand(clap::SubCommand::with_name("M_MMAP_THRESHOLD"))
.subcommand(clap::SubCommand::with_name("M_TOP_PAD"))
.subcommand(clap::SubCommand::with_name("M_TRIM_THRESHOLD"))
.subcommand(clap::SubCommand::with_name("M_KEEP"))
.subcommand(clap::SubCommand::with_name("M_GRAIN"))
.subcommand(clap::SubCommand::with_name("M_NLBLKS"))
.subcommand(clap::SubCommand::with_name("M_MXFAST"))
.subcommand(clap::SubCommand::with_name("NFT_NG_RANDOM"))
.subcommand(clap::SubCommand::with_name("NFT_NG_INCREMENTAL"))
.subcommand(clap::SubCommand::with_name("NFT_TRACETYPE_RULE"))
.subcommand(clap::SubCommand::with_name("NFT_TRACETYPE_RETURN"))
.subcommand(clap::SubCommand::with_name("NFT_TRACETYPE_POLICY"))
.subcommand(clap::SubCommand::with_name("NFT_TRACETYPE_UNSPEC"))
.subcommand(clap::SubCommand::with_name("NFT_NAT_DNAT"))
.subcommand(clap::SubCommand::with_name("NFT_NAT_SNAT"))
.subcommand(clap::SubCommand::with_name("NFT_REJECT_ICMPX_ADMIN_PROHIBITED"))
.subcommand(clap::SubCommand::with_name("NFT_REJECT_ICMPX_HOST_UNREACH"))
.subcommand(clap::SubCommand::with_name("NFT_REJECT_ICMPX_PORT_UNREACH"))
.subcommand(clap::SubCommand::with_name("NFT_REJECT_ICMPX_NO_ROUTE"))
.subcommand(clap::SubCommand::with_name("NFT_REJECT_ICMPX_UNREACH"))
.subcommand(clap::SubCommand::with_name("NFT_REJECT_TCP_RST"))
.subcommand(clap::SubCommand::with_name("NFT_REJECT_ICMP_UNREACH"))
.subcommand(clap::SubCommand::with_name("NFT_QUOTA_F_INV"))
.subcommand(clap::SubCommand::with_name("NFT_QUEUE_FLAG_MASK"))
.subcommand(clap::SubCommand::with_name("NFT_QUEUE_FLAG_CPU_FANOUT"))
.subcommand(clap::SubCommand::with_name("NFT_QUEUE_FLAG_BYPASS"))
.subcommand(clap::SubCommand::with_name("NFT_LIMIT_F_INV"))
.subcommand(clap::SubCommand::with_name("NFT_LIMIT_PKT_BYTES"))
.subcommand(clap::SubCommand::with_name("NFT_LIMIT_PKTS"))
.subcommand(clap::SubCommand::with_name("NFT_CT_BYTES"))
.subcommand(clap::SubCommand::with_name("NFT_CT_PKTS"))
.subcommand(clap::SubCommand::with_name("NFT_CT_LABELS"))
.subcommand(clap::SubCommand::with_name("NFT_CT_PROTO_DST"))
.subcommand(clap::SubCommand::with_name("NFT_CT_PROTO_SRC"))
.subcommand(clap::SubCommand::with_name("NFT_CT_PROTOCOL"))
.subcommand(clap::SubCommand::with_name("NFT_CT_DST"))
.subcommand(clap::SubCommand::with_name("NFT_CT_SRC"))
.subcommand(clap::SubCommand::with_name("NFT_CT_L3PROTOCOL"))
.subcommand(clap::SubCommand::with_name("NFT_CT_HELPER"))
.subcommand(clap::SubCommand::with_name("NFT_CT_EXPIRATION"))
.subcommand(clap::SubCommand::with_name("NFT_CT_SECMARK"))
.subcommand(clap::SubCommand::with_name("NFT_CT_MARK"))
.subcommand(clap::SubCommand::with_name("NFT_CT_STATUS"))
.subcommand(clap::SubCommand::with_name("NFT_CT_DIRECTION"))
.subcommand(clap::SubCommand::with_name("NFT_CT_STATE"))
.subcommand(clap::SubCommand::with_name("NFT_META_PRANDOM"))
.subcommand(clap::SubCommand::with_name("NFT_META_CGROUP"))
.subcommand(clap::SubCommand::with_name("NFT_META_OIFGROUP"))
.subcommand(clap::SubCommand::with_name("NFT_META_IIFGROUP"))
.subcommand(clap::SubCommand::with_name("NFT_META_CPU"))
.subcommand(clap::SubCommand::with_name("NFT_META_PKTTYPE"))
.subcommand(clap::SubCommand::with_name("NFT_META_BRI_OIFNAME"))
.subcommand(clap::SubCommand::with_name("NFT_META_BRI_IIFNAME"))
.subcommand(clap::SubCommand::with_name("NFT_META_L4PROTO"))
.subcommand(clap::SubCommand::with_name("NFT_META_NFPROTO"))
.subcommand(clap::SubCommand::with_name("NFT_META_SECMARK"))
.subcommand(clap::SubCommand::with_name("NFT_META_RTCLASSID"))
.subcommand(clap::SubCommand::with_name("NFT_META_NFTRACE"))
.subcommand(clap::SubCommand::with_name("NFT_META_SKGID"))
.subcommand(clap::SubCommand::with_name("NFT_META_SKUID"))
.subcommand(clap::SubCommand::with_name("NFT_META_OIFTYPE"))
.subcommand(clap::SubCommand::with_name("NFT_META_IIFTYPE"))
.subcommand(clap::SubCommand::with_name("NFT_META_OIFNAME"))
.subcommand(clap::SubCommand::with_name("NFT_META_IIFNAME"))
.subcommand(clap::SubCommand::with_name("NFT_META_OIF"))
.subcommand(clap::SubCommand::with_name("NFT_META_IIF"))
.subcommand(clap::SubCommand::with_name("NFT_META_MARK"))
.subcommand(clap::SubCommand::with_name("NFT_META_PRIORITY"))
.subcommand(clap::SubCommand::with_name("NFT_META_PROTOCOL"))
.subcommand(clap::SubCommand::with_name("NFT_META_LEN"))
.subcommand(clap::SubCommand::with_name("NFT_PAYLOAD_CSUM_INET"))
.subcommand(clap::SubCommand::with_name("NFT_PAYLOAD_CSUM_NONE"))
.subcommand(clap::SubCommand::with_name("NFT_PAYLOAD_TRANSPORT_HEADER"))
.subcommand(clap::SubCommand::with_name("NFT_PAYLOAD_NETWORK_HEADER"))
.subcommand(clap::SubCommand::with_name("NFT_PAYLOAD_LL_HEADER"))
.subcommand(clap::SubCommand::with_name("NFT_DYNSET_F_INV"))
.subcommand(clap::SubCommand::with_name("NFT_DYNSET_OP_UPDATE"))
.subcommand(clap::SubCommand::with_name("NFT_DYNSET_OP_ADD"))
.subcommand(clap::SubCommand::with_name("NFT_LOOKUP_F_INV"))
.subcommand(clap::SubCommand::with_name("NFT_RANGE_NEQ"))
.subcommand(clap::SubCommand::with_name("NFT_RANGE_EQ"))
.subcommand(clap::SubCommand::with_name("NFT_CMP_GTE"))
.subcommand(clap::SubCommand::with_name("NFT_CMP_GT"))
.subcommand(clap::SubCommand::with_name("NFT_CMP_LTE"))
.subcommand(clap::SubCommand::with_name("NFT_CMP_LT"))
.subcommand(clap::SubCommand::with_name("NFT_CMP_NEQ"))
.subcommand(clap::SubCommand::with_name("NFT_CMP_EQ"))
.subcommand(clap::SubCommand::with_name("NFT_BYTEORDER_HTON"))
.subcommand(clap::SubCommand::with_name("NFT_BYTEORDER_NTOH"))
.subcommand(clap::SubCommand::with_name("NFT_DATA_VALUE_MAXLEN"))
.subcommand(clap::SubCommand::with_name("NFT_DATA_RESERVED_MASK"))
.subcommand(clap::SubCommand::with_name("NFT_DATA_VERDICT"))
.subcommand(clap::SubCommand::with_name("NFT_DATA_VALUE"))
.subcommand(clap::SubCommand::with_name("NFT_SET_ELEM_INTERVAL_END"))
.subcommand(clap::SubCommand::with_name("NFT_SET_POL_MEMORY"))
.subcommand(clap::SubCommand::with_name("NFT_SET_POL_PERFORMANCE"))
.subcommand(clap::SubCommand::with_name("NFT_SET_EVAL"))
.subcommand(clap::SubCommand::with_name("NFT_SET_TIMEOUT"))
.subcommand(clap::SubCommand::with_name("NFT_SET_MAP"))
.subcommand(clap::SubCommand::with_name("NFT_SET_INTERVAL"))
.subcommand(clap::SubCommand::with_name("NFT_SET_CONSTANT"))
.subcommand(clap::SubCommand::with_name("NFT_SET_ANONYMOUS"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_MAX"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_GETOBJ_RESET"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_DELOBJ"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_GETOBJ"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_NEWOBJ"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_TRACE"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_GETGEN"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_NEWGEN"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_DELSETELEM"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_GETSETELEM"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_NEWSETELEM"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_DELSET"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_GETSET"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_NEWSET"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_DELRULE"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_GETRULE"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_NEWRULE"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_DELCHAIN"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_GETCHAIN"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_NEWCHAIN"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_DELTABLE"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_GETTABLE"))
.subcommand(clap::SubCommand::with_name("NFT_MSG_NEWTABLE"))
.subcommand(clap::SubCommand::with_name("NFT_RETURN"))
.subcommand(clap::SubCommand::with_name("NFT_GOTO"))
.subcommand(clap::SubCommand::with_name("NFT_JUMP"))
.subcommand(clap::SubCommand::with_name("NFT_BREAK"))
.subcommand(clap::SubCommand::with_name("NFT_CONTINUE"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_SIZE"))
.subcommand(clap::SubCommand::with_name("NFT_REG_SIZE"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_15"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_14"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_13"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_12"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_11"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_10"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_09"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_08"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_07"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_06"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_05"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_04"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_03"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_02"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_01"))
.subcommand(clap::SubCommand::with_name("NFT_REG32_00"))
.subcommand(clap::SubCommand::with_name("__NFT_REG_MAX"))
.subcommand(clap::SubCommand::with_name("NFT_REG_4"))
.subcommand(clap::SubCommand::with_name("NFT_REG_3"))
.subcommand(clap::SubCommand::with_name("NFT_REG_2"))
.subcommand(clap::SubCommand::with_name("NFT_REG_1"))
.subcommand(clap::SubCommand::with_name("NFT_REG_VERDICT"))
.subcommand(clap::SubCommand::with_name("NFT_USERDATA_MAXLEN"))
.subcommand(clap::SubCommand::with_name("NFT_OBJ_MAXNAMELEN"))
.subcommand(clap::SubCommand::with_name("NFT_SET_MAXNAMELEN"))
.subcommand(clap::SubCommand::with_name("NFT_CHAIN_MAXNAMELEN"))
.subcommand(clap::SubCommand::with_name("NFT_TABLE_MAXNAMELEN"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS1_NS_KEY_TAG"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS1_NS_KEYRING_NAME"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS0_MOVE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS0_RESTRICT_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS0_INVALIDATE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS0_BIG_KEY"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS0_PUBLIC_KEY"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS0_DIFFIE_HELLMAN"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS0_PERSISTENT_KEYRINGS"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPS0_CAPABILITIES"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CAPABILITIES"))
.subcommand(clap::SubCommand::with_name("KEYCTL_MOVE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SUPPORTS_VERIFY"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SUPPORTS_SIGN"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SUPPORTS_DECRYPT"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SUPPORTS_ENCRYPT"))
.subcommand(clap::SubCommand::with_name("KEYCTL_RESTRICT_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEYCTL_PKEY_VERIFY"))
.subcommand(clap::SubCommand::with_name("KEYCTL_PKEY_SIGN"))
.subcommand(clap::SubCommand::with_name("KEYCTL_PKEY_DECRYPT"))
.subcommand(clap::SubCommand::with_name("KEYCTL_PKEY_ENCRYPT"))
.subcommand(clap::SubCommand::with_name("KEYCTL_PKEY_QUERY"))
.subcommand(clap::SubCommand::with_name("KEYCTL_DH_COMPUTE"))
.subcommand(clap::SubCommand::with_name("NFPROTO_NETDEV"))
.subcommand(clap::SubCommand::with_name("NFPROTO_INET"))
.subcommand(clap::SubCommand::with_name("NF_NETDEV_NUMHOOKS"))
.subcommand(clap::SubCommand::with_name("NF_NETDEV_INGRESS"))
.subcommand(clap::SubCommand::with_name("TIOCM_RI"))
.subcommand(clap::SubCommand::with_name("TIOCM_CD"))
.subcommand(clap::SubCommand::with_name("TIOCM_RTS"))
.subcommand(clap::SubCommand::with_name("TIOCM_DTR"))
.subcommand(clap::SubCommand::with_name("TIOCM_LE"))
.subcommand(clap::SubCommand::with_name("GENL_ID_PMCRAID"))
.subcommand(clap::SubCommand::with_name("GENL_ID_VFS_DQUOT"))
.subcommand(clap::SubCommand::with_name("GENL_UNS_ADMIN_PERM"))
.subcommand(clap::SubCommand::with_name("MAX_LINKS"))
.subcommand(clap::SubCommand::with_name("IFA_F_STABLE_PRIVACY"))
.subcommand(clap::SubCommand::with_name("IFA_F_MCAUTOJOIN"))
.subcommand(clap::SubCommand::with_name("IFA_F_NOPREFIXROUTE"))
.subcommand(clap::SubCommand::with_name("IFA_F_MANAGETEMPADDR"))
.subcommand(clap::SubCommand::with_name("IFA_FLAGS"))
.subcommand(clap::SubCommand::with_name("NDA_SRC_VNI"))
.subcommand(clap::SubCommand::with_name("NDA_LINK_NETNSID"))
.subcommand(clap::SubCommand::with_name("NDA_MASTER"))
.subcommand(clap::SubCommand::with_name("NTF_OFFLOADED"))
.subcommand(clap::SubCommand::with_name("NTF_EXT_LEARNED"))
.subcommand(clap::SubCommand::with_name("RTA_TTL_PROPAGATE"))
.subcommand(clap::SubCommand::with_name("RTA_UID"))
.subcommand(clap::SubCommand::with_name("RTA_PAD"))
.subcommand(clap::SubCommand::with_name("RTA_EXPIRES"))
.subcommand(clap::SubCommand::with_name("RTA_ENCAP"))
.subcommand(clap::SubCommand::with_name("RTA_ENCAP_TYPE"))
.subcommand(clap::SubCommand::with_name("RTA_PREF"))
.subcommand(clap::SubCommand::with_name("RTA_NEWDST"))
.subcommand(clap::SubCommand::with_name("RTA_VIA"))
.subcommand(clap::SubCommand::with_name("RTM_F_FIB_MATCH"))
.subcommand(clap::SubCommand::with_name("RTM_F_LOOKUP_TABLE"))
.subcommand(clap::SubCommand::with_name("RTM_NEWCACHEREPORT"))
.subcommand(clap::SubCommand::with_name("RTM_GETSTATS"))
.subcommand(clap::SubCommand::with_name("RTM_NEWSTATS"))
.subcommand(clap::SubCommand::with_name("RTM_DELNETCONF"))
.subcommand(clap::SubCommand::with_name("TCA_HW_OFFLOAD"))
.subcommand(clap::SubCommand::with_name("TCA_CHAIN"))
.subcommand(clap::SubCommand::with_name("TCA_DUMP_INVISIBLE"))
.subcommand(clap::SubCommand::with_name("TCA_PAD"))
.subcommand(clap::SubCommand::with_name("SEEK_HOLE"))
.subcommand(clap::SubCommand::with_name("SEEK_DATA"))
.subcommand(clap::SubCommand::with_name("EPOLLWAKEUP"))
.subcommand(clap::SubCommand::with_name("PTRACE_PEEKSIGINFO"))
.subcommand(clap::SubCommand::with_name("PTRACE_LISTEN"))
.subcommand(clap::SubCommand::with_name("PTRACE_INTERRUPT"))
.subcommand(clap::SubCommand::with_name("PTRACE_SEIZE"))
.subcommand(clap::SubCommand::with_name("PTRACE_SETREGSET"))
.subcommand(clap::SubCommand::with_name("PTRACE_GETREGSET"))
.subcommand(clap::SubCommand::with_name("PTRACE_SETSIGINFO"))
.subcommand(clap::SubCommand::with_name("PTRACE_GETSIGINFO"))
.subcommand(clap::SubCommand::with_name("PTRACE_GETEVENTMSG"))
.subcommand(clap::SubCommand::with_name("PTRACE_SETOPTIONS"))
.subcommand(clap::SubCommand::with_name("PTRACE_SYSCALL"))
.subcommand(clap::SubCommand::with_name("PTRACE_ATTACH"))
.subcommand(clap::SubCommand::with_name("PTRACE_SINGLESTEP"))
.subcommand(clap::SubCommand::with_name("PTRACE_KILL"))
.subcommand(clap::SubCommand::with_name("PTRACE_CONT"))
.subcommand(clap::SubCommand::with_name("PTRACE_POKEUSER"))
.subcommand(clap::SubCommand::with_name("PTRACE_POKEDATA"))
.subcommand(clap::SubCommand::with_name("PTRACE_POKETEXT"))
.subcommand(clap::SubCommand::with_name("PTRACE_PEEKUSER"))
.subcommand(clap::SubCommand::with_name("PTRACE_PEEKDATA"))
.subcommand(clap::SubCommand::with_name("PTRACE_PEEKTEXT"))
.subcommand(clap::SubCommand::with_name("PTRACE_TRACEME"))
.subcommand(clap::SubCommand::with_name("CPU_SETSIZE"))
.subcommand(clap::SubCommand::with_name("CGROUP2_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("CGROUP_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("USBDEVICE_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("TMPFS_MAGIC"))
.subcommand(clap::SubCommand::with_name("SMB_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("REISERFS_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("QNX4_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("PROC_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("OPENPROM_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("NFS_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("NCP_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("MSDOS_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("MINIX2_SUPER_MAGIC2"))
.subcommand(clap::SubCommand::with_name("MINIX2_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("MINIX_SUPER_MAGIC2"))
.subcommand(clap::SubCommand::with_name("MINIX_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("JFFS2_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("ISOFS_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("HUGETLBFS_MAGIC"))
.subcommand(clap::SubCommand::with_name("HPFS_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("EXT4_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("EXT3_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("EXT2_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("EFS_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("CRAMFS_MAGIC"))
.subcommand(clap::SubCommand::with_name("CODA_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("AFFS_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("ADFS_SUPER_MAGIC"))
.subcommand(clap::SubCommand::with_name("NI_MAXHOST"))
.subcommand(clap::SubCommand::with_name("ST_RELATIME"))
.subcommand(clap::SubCommand::with_name("O_ACCMODE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL4_CACHE_LINESIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL4_CACHE_ASSOC"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL4_CACHE_SIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL3_CACHE_LINESIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL3_CACHE_ASSOC"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL3_CACHE_SIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL2_CACHE_LINESIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL2_CACHE_ASSOC"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL2_CACHE_SIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL1_DCACHE_LINESIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL1_DCACHE_ASSOC"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL1_DCACHE_SIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL1_ICACHE_LINESIZE"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL1_ICACHE_ASSOC"))
.subcommand(clap::SubCommand::with_name("_SC_LEVEL1_ICACHE_SIZE"))
.subcommand(clap::SubCommand::with_name("_SC_USER_GROUPS_R"))
.subcommand(clap::SubCommand::with_name("_SC_USER_GROUPS"))
.subcommand(clap::SubCommand::with_name("_SC_SYSTEM_DATABASE_R"))
.subcommand(clap::SubCommand::with_name("_SC_SYSTEM_DATABASE"))
.subcommand(clap::SubCommand::with_name("_SC_SIGNALS"))
.subcommand(clap::SubCommand::with_name("_SC_REGEX_VERSION"))
.subcommand(clap::SubCommand::with_name("_SC_NETWORKING"))
.subcommand(clap::SubCommand::with_name("_SC_SINGLE_PROCESS"))
.subcommand(clap::SubCommand::with_name("_SC_MULTI_PROCESS"))
.subcommand(clap::SubCommand::with_name("_SC_FILE_SYSTEM"))
.subcommand(clap::SubCommand::with_name("_SC_FILE_LOCKING"))
.subcommand(clap::SubCommand::with_name("_SC_FILE_ATTRIBUTES"))
.subcommand(clap::SubCommand::with_name("_SC_PIPE"))
.subcommand(clap::SubCommand::with_name("_SC_FIFO"))
.subcommand(clap::SubCommand::with_name("_SC_FD_MGMT"))
.subcommand(clap::SubCommand::with_name("_SC_DEVICE_SPECIFIC_R"))
.subcommand(clap::SubCommand::with_name("_SC_DEVICE_SPECIFIC"))
.subcommand(clap::SubCommand::with_name("_SC_DEVICE_IO"))
.subcommand(clap::SubCommand::with_name("_SC_C_LANG_SUPPORT_R"))
.subcommand(clap::SubCommand::with_name("_SC_C_LANG_SUPPORT"))
.subcommand(clap::SubCommand::with_name("_SC_BASE"))
.subcommand(clap::SubCommand::with_name("_SC_NL_TEXTMAX"))
.subcommand(clap::SubCommand::with_name("_SC_NL_SETMAX"))
.subcommand(clap::SubCommand::with_name("_SC_NL_NMAX"))
.subcommand(clap::SubCommand::with_name("_SC_NL_MSGMAX"))
.subcommand(clap::SubCommand::with_name("_SC_NL_LANGMAX"))
.subcommand(clap::SubCommand::with_name("_SC_NL_ARGMAX"))
.subcommand(clap::SubCommand::with_name("_SC_USHRT_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_ULONG_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_UINT_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_UCHAR_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_SHRT_MIN"))
.subcommand(clap::SubCommand::with_name("_SC_SHRT_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_SCHAR_MIN"))
.subcommand(clap::SubCommand::with_name("_SC_SCHAR_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_SSIZE_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_MB_LEN_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_WORD_BIT"))
.subcommand(clap::SubCommand::with_name("_SC_LONG_BIT"))
.subcommand(clap::SubCommand::with_name("_SC_INT_MIN"))
.subcommand(clap::SubCommand::with_name("_SC_INT_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_CHAR_MIN"))
.subcommand(clap::SubCommand::with_name("_SC_CHAR_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_CHAR_BIT"))
.subcommand(clap::SubCommand::with_name("_SC_2_C_VERSION"))
.subcommand(clap::SubCommand::with_name("_SC_T_IOV_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_PII_OSI_M"))
.subcommand(clap::SubCommand::with_name("_SC_PII_OSI_CLTS"))
.subcommand(clap::SubCommand::with_name("_SC_PII_OSI_COTS"))
.subcommand(clap::SubCommand::with_name("_SC_PII_INTERNET_DGRAM"))
.subcommand(clap::SubCommand::with_name("_SC_PII_INTERNET_STREAM"))
.subcommand(clap::SubCommand::with_name("_SC_SELECT"))
.subcommand(clap::SubCommand::with_name("_SC_POLL"))
.subcommand(clap::SubCommand::with_name("_SC_PII_OSI"))
.subcommand(clap::SubCommand::with_name("_SC_PII_INTERNET"))
.subcommand(clap::SubCommand::with_name("_SC_PII_SOCKET"))
.subcommand(clap::SubCommand::with_name("_SC_PII_XTI"))
.subcommand(clap::SubCommand::with_name("_SC_PII"))
.subcommand(clap::SubCommand::with_name("_SC_CHARCLASS_NAME_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_EQUIV_CLASS_MAX"))
.subcommand(clap::SubCommand::with_name("POSIX_MADV_DONTNEED"))
.subcommand(clap::SubCommand::with_name("FOPEN_MAX"))
.subcommand(clap::SubCommand::with_name("TMP_MAX"))
.subcommand(clap::SubCommand::with_name("BUFSIZ"))
.subcommand(clap::SubCommand::with_name("SIGEV_THREAD_ID"))
.subcommand(clap::SubCommand::with_name("DCCP_SERVICE_LIST_MAX_LEN"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_CCID_TX_INFO"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_CCID_RX_INFO"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_QPOLICY_TXQLEN"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_QPOLICY_ID"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_RX_CCID"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_TX_CCID"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_CCID"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_AVAILABLE_CCIDS"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_RECV_CSCOV"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_SEND_CSCOV"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_SERVER_TIMEWAIT"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_GET_CUR_MPS"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_CHANGE_R"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_CHANGE_L"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_SERVICE"))
.subcommand(clap::SubCommand::with_name("DCCP_SOCKOPT_PACKET_SIZE"))
.subcommand(clap::SubCommand::with_name("TCP_FASTOPEN_CONNECT"))
.subcommand(clap::SubCommand::with_name("TCP_TIMESTAMP"))
.subcommand(clap::SubCommand::with_name("TCP_FASTOPEN"))
.subcommand(clap::SubCommand::with_name("TCP_REPAIR_OPTIONS"))
.subcommand(clap::SubCommand::with_name("TCP_QUEUE_SEQ"))
.subcommand(clap::SubCommand::with_name("TCP_REPAIR_QUEUE"))
.subcommand(clap::SubCommand::with_name("TCP_REPAIR"))
.subcommand(clap::SubCommand::with_name("TCP_USER_TIMEOUT"))
.subcommand(clap::SubCommand::with_name("TCP_THIN_DUPACK"))
.subcommand(clap::SubCommand::with_name("TCP_THIN_LINEAR_TIMEOUTS"))
.subcommand(clap::SubCommand::with_name("TCP_COOKIE_TRANSACTIONS"))
.subcommand(clap::SubCommand::with_name("SOCK_PACKET"))
.subcommand(clap::SubCommand::with_name("SOCK_DCCP"))
.subcommand(clap::SubCommand::with_name("SOCK_SEQPACKET"))
.subcommand(clap::SubCommand::with_name("ENOTSUP"))
.subcommand(clap::SubCommand::with_name("LC_ALL_MASK"))
.subcommand(clap::SubCommand::with_name("LC_IDENTIFICATION_MASK"))
.subcommand(clap::SubCommand::with_name("LC_MEASUREMENT_MASK"))
.subcommand(clap::SubCommand::with_name("LC_TELEPHONE_MASK"))
.subcommand(clap::SubCommand::with_name("LC_ADDRESS_MASK"))
.subcommand(clap::SubCommand::with_name("LC_NAME_MASK"))
.subcommand(clap::SubCommand::with_name("LC_PAPER_MASK"))
.subcommand(clap::SubCommand::with_name("LC_IDENTIFICATION"))
.subcommand(clap::SubCommand::with_name("LC_MEASUREMENT"))
.subcommand(clap::SubCommand::with_name("LC_TELEPHONE"))
.subcommand(clap::SubCommand::with_name("LC_ADDRESS"))
.subcommand(clap::SubCommand::with_name("LC_NAME"))
.subcommand(clap::SubCommand::with_name("LC_PAPER"))
.subcommand(clap::SubCommand::with_name("MSG_TRYHARD"))
.subcommand(clap::SubCommand::with_name("SOL_XDP"))
.subcommand(clap::SubCommand::with_name("SOL_NFC"))
.subcommand(clap::SubCommand::with_name("SOL_CAIF"))
.subcommand(clap::SubCommand::with_name("SOL_IUCV"))
.subcommand(clap::SubCommand::with_name("SOL_RDS"))
.subcommand(clap::SubCommand::with_name("SOL_PNPIPE"))
.subcommand(clap::SubCommand::with_name("SOL_PPPOL2TP"))
.subcommand(clap::SubCommand::with_name("SOL_RXRPC"))
.subcommand(clap::SubCommand::with_name("SOCK_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_TLS_DATA"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_TLS_MODID"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_PROFILEOUT"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_PROFILENAME"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_ORIGIN"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_SERINFOSIZE"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_SERINFO"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_CONFIGADDR"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_LINKMAP"))
.subcommand(clap::SubCommand::with_name("RTLD_DI_LMID"))
.subcommand(clap::SubCommand::with_name("LM_ID_NEWLM"))
.subcommand(clap::SubCommand::with_name("LM_ID_BASE"))
.subcommand(clap::SubCommand::with_name("ACCOUNTING"))
.subcommand(clap::SubCommand::with_name("DEAD_PROCESS"))
.subcommand(clap::SubCommand::with_name("USER_PROCESS"))
.subcommand(clap::SubCommand::with_name("LOGIN_PROCESS"))
.subcommand(clap::SubCommand::with_name("INIT_PROCESS"))
.subcommand(clap::SubCommand::with_name("OLD_TIME"))
.subcommand(clap::SubCommand::with_name("NEW_TIME"))
.subcommand(clap::SubCommand::with_name("BOOT_TIME"))
.subcommand(clap::SubCommand::with_name("RUN_LVL"))
.subcommand(clap::SubCommand::with_name("EMPTY"))
.subcommand(clap::SubCommand::with_name("__UT_HOSTSIZE"))
.subcommand(clap::SubCommand::with_name("__UT_NAMESIZE"))
.subcommand(clap::SubCommand::with_name("__UT_LINESIZE"))
.subcommand(clap::SubCommand::with_name("MS_RMT_MASK"))
.subcommand(clap::SubCommand::with_name("RLIMIT_NLIMITS"))
.subcommand(clap::SubCommand::with_name("RLIMIT_RTTIME"))
.subcommand(clap::SubCommand::with_name("RLIMIT_RTPRIO"))
.subcommand(clap::SubCommand::with_name("RLIMIT_NICE"))
.subcommand(clap::SubCommand::with_name("RLIMIT_MSGQUEUE"))
.subcommand(clap::SubCommand::with_name("RLIMIT_SIGPENDING"))
.subcommand(clap::SubCommand::with_name("RLIMIT_LOCKS"))
.subcommand(clap::SubCommand::with_name("RLIMIT_CORE"))
.subcommand(clap::SubCommand::with_name("RLIMIT_STACK"))
.subcommand(clap::SubCommand::with_name("RLIMIT_DATA"))
.subcommand(clap::SubCommand::with_name("RLIMIT_FSIZE"))
.subcommand(clap::SubCommand::with_name("RLIMIT_CPU"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_16GB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_2GB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_1GB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_512MB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_256MB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_32MB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_16MB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_8MB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_2MB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_1MB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_512KB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_64KB"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_MASK"))
.subcommand(clap::SubCommand::with_name("MAP_HUGE_SHIFT"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_16GB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_2GB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_1GB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_512MB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_256MB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_32MB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_16MB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_8MB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_2MB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_1MB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_512KB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_64KB"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_MASK"))
.subcommand(clap::SubCommand::with_name("HUGETLB_FLAG_ENCODE_SHIFT"))
.subcommand(clap::SubCommand::with_name("EWOULDBLOCK"))
.subcommand(clap::SubCommand::with_name("ERANGE"))
.subcommand(clap::SubCommand::with_name("EDOM"))
.subcommand(clap::SubCommand::with_name("EPIPE"))
.subcommand(clap::SubCommand::with_name("EMLINK"))
.subcommand(clap::SubCommand::with_name("EROFS"))
.subcommand(clap::SubCommand::with_name("ESPIPE"))
.subcommand(clap::SubCommand::with_name("ENOSPC"))
.subcommand(clap::SubCommand::with_name("EFBIG"))
.subcommand(clap::SubCommand::with_name("ETXTBSY"))
.subcommand(clap::SubCommand::with_name("ENOTTY"))
.subcommand(clap::SubCommand::with_name("EMFILE"))
.subcommand(clap::SubCommand::with_name("ENFILE"))
.subcommand(clap::SubCommand::with_name("EINVAL"))
.subcommand(clap::SubCommand::with_name("EISDIR"))
.subcommand(clap::SubCommand::with_name("ENOTDIR"))
.subcommand(clap::SubCommand::with_name("ENODEV"))
.subcommand(clap::SubCommand::with_name("EXDEV"))
.subcommand(clap::SubCommand::with_name("EEXIST"))
.subcommand(clap::SubCommand::with_name("EBUSY"))
.subcommand(clap::SubCommand::with_name("ENOTBLK"))
.subcommand(clap::SubCommand::with_name("EFAULT"))
.subcommand(clap::SubCommand::with_name("EACCES"))
.subcommand(clap::SubCommand::with_name("ENOMEM"))
.subcommand(clap::SubCommand::with_name("EAGAIN"))
.subcommand(clap::SubCommand::with_name("ECHILD"))
.subcommand(clap::SubCommand::with_name("EBADF"))
.subcommand(clap::SubCommand::with_name("ENOEXEC"))
.subcommand(clap::SubCommand::with_name("E2BIG"))
.subcommand(clap::SubCommand::with_name("ENXIO"))
.subcommand(clap::SubCommand::with_name("EIO"))
.subcommand(clap::SubCommand::with_name("EINTR"))
.subcommand(clap::SubCommand::with_name("ESRCH"))
.subcommand(clap::SubCommand::with_name("ENOENT"))
.subcommand(clap::SubCommand::with_name("EPERM"))
.subcommand(clap::SubCommand::with_name("SO_EE_ORIGIN_TIMESTAMPING"))
.subcommand(clap::SubCommand::with_name("SO_EE_ORIGIN_TXSTATUS"))
.subcommand(clap::SubCommand::with_name("SO_EE_ORIGIN_ICMP6"))
.subcommand(clap::SubCommand::with_name("SO_EE_ORIGIN_ICMP"))
.subcommand(clap::SubCommand::with_name("SO_EE_ORIGIN_LOCAL"))
.subcommand(clap::SubCommand::with_name("SO_EE_ORIGIN_NONE"))
.subcommand(clap::SubCommand::with_name("REG_BADRPT"))
.subcommand(clap::SubCommand::with_name("REG_ESPACE"))
.subcommand(clap::SubCommand::with_name("REG_ERANGE"))
.subcommand(clap::SubCommand::with_name("REG_BADBR"))
.subcommand(clap::SubCommand::with_name("REG_EBRACE"))
.subcommand(clap::SubCommand::with_name("REG_EPAREN"))
.subcommand(clap::SubCommand::with_name("REG_EBRACK"))
.subcommand(clap::SubCommand::with_name("REG_ESUBREG"))
.subcommand(clap::SubCommand::with_name("REG_EESCAPE"))
.subcommand(clap::SubCommand::with_name("REG_ECTYPE"))
.subcommand(clap::SubCommand::with_name("REG_ECOLLATE"))
.subcommand(clap::SubCommand::with_name("REG_BADPAT"))
.subcommand(clap::SubCommand::with_name("REG_NOMATCH"))
.subcommand(clap::SubCommand::with_name("REG_ENOSYS"))
.subcommand(clap::SubCommand::with_name("REG_NOTEOL"))
.subcommand(clap::SubCommand::with_name("REG_NOTBOL"))
.subcommand(clap::SubCommand::with_name("REG_NOSUB"))
.subcommand(clap::SubCommand::with_name("REG_NEWLINE"))
.subcommand(clap::SubCommand::with_name("REG_ICASE"))
.subcommand(clap::SubCommand::with_name("REG_EXTENDED"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_CMD_KEXEC"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_CMD_SW_SUSPEND"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_CMD_RESTART2"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_CMD_POWER_OFF"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_CMD_CAD_OFF"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_CMD_CAD_ON"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_CMD_HALT"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_CMD_RESTART"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_MAGIC2C"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_MAGIC2B"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_MAGIC2A"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_MAGIC2"))
.subcommand(clap::SubCommand::with_name("LINUX_REBOOT_MAGIC1"))
.subcommand(clap::SubCommand::with_name("FUTEX_CMD_MASK"))
.subcommand(clap::SubCommand::with_name("FUTEX_CLOCK_REALTIME"))
.subcommand(clap::SubCommand::with_name("FUTEX_PRIVATE_FLAG"))
.subcommand(clap::SubCommand::with_name("FUTEX_CMP_REQUEUE_PI"))
.subcommand(clap::SubCommand::with_name("FUTEX_WAIT_REQUEUE_PI"))
.subcommand(clap::SubCommand::with_name("FUTEX_WAKE_BITSET"))
.subcommand(clap::SubCommand::with_name("FUTEX_WAIT_BITSET"))
.subcommand(clap::SubCommand::with_name("FUTEX_TRYLOCK_PI"))
.subcommand(clap::SubCommand::with_name("FUTEX_UNLOCK_PI"))
.subcommand(clap::SubCommand::with_name("FUTEX_LOCK_PI"))
.subcommand(clap::SubCommand::with_name("FUTEX_WAKE_OP"))
.subcommand(clap::SubCommand::with_name("FUTEX_CMP_REQUEUE"))
.subcommand(clap::SubCommand::with_name("FUTEX_REQUEUE"))
.subcommand(clap::SubCommand::with_name("FUTEX_FD"))
.subcommand(clap::SubCommand::with_name("FUTEX_WAKE"))
.subcommand(clap::SubCommand::with_name("FUTEX_WAIT"))
.subcommand(clap::SubCommand::with_name("FAN_NOFD"))
.subcommand(clap::SubCommand::with_name("FAN_DENY"))
.subcommand(clap::SubCommand::with_name("FAN_ALLOW"))
.subcommand(clap::SubCommand::with_name("FANOTIFY_METADATA_VERSION"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_FLUSH"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_IGNORED_SURV_MODIFY"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_IGNORED_MASK"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_FILESYSTEM"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_MOUNT"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_INODE"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_ONLYDIR"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_DONT_FOLLOW"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_REMOVE"))
.subcommand(clap::SubCommand::with_name("FAN_MARK_ADD"))
.subcommand(clap::SubCommand::with_name("FAN_UNLIMITED_MARKS"))
.subcommand(clap::SubCommand::with_name("FAN_UNLIMITED_QUEUE"))
.subcommand(clap::SubCommand::with_name("FAN_CLASS_PRE_CONTENT"))
.subcommand(clap::SubCommand::with_name("FAN_CLASS_CONTENT"))
.subcommand(clap::SubCommand::with_name("FAN_CLASS_NOTIF"))
.subcommand(clap::SubCommand::with_name("FAN_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("FAN_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("FAN_CLOSE"))
.subcommand(clap::SubCommand::with_name("FAN_EVENT_ON_CHILD"))
.subcommand(clap::SubCommand::with_name("FAN_ONDIR"))
.subcommand(clap::SubCommand::with_name("FAN_ACCESS_PERM"))
.subcommand(clap::SubCommand::with_name("FAN_OPEN_PERM"))
.subcommand(clap::SubCommand::with_name("FAN_Q_OVERFLOW"))
.subcommand(clap::SubCommand::with_name("FAN_OPEN"))
.subcommand(clap::SubCommand::with_name("FAN_CLOSE_NOWRITE"))
.subcommand(clap::SubCommand::with_name("FAN_CLOSE_WRITE"))
.subcommand(clap::SubCommand::with_name("FAN_MODIFY"))
.subcommand(clap::SubCommand::with_name("FAN_ACCESS"))
.subcommand(clap::SubCommand::with_name("IN_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("IN_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("IN_ALL_EVENTS"))
.subcommand(clap::SubCommand::with_name("IN_ONESHOT"))
.subcommand(clap::SubCommand::with_name("IN_ISDIR"))
.subcommand(clap::SubCommand::with_name("KEYCTL_GET_PERSISTENT"))
.subcommand(clap::SubCommand::with_name("KEYCTL_INVALIDATE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_INSTANTIATE_IOV"))
.subcommand(clap::SubCommand::with_name("KEYCTL_REJECT"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SESSION_TO_PARENT"))
.subcommand(clap::SubCommand::with_name("KEYCTL_GET_SECURITY"))
.subcommand(clap::SubCommand::with_name("KEYCTL_ASSUME_AUTHORITY"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SET_TIMEOUT"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SET_REQKEY_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEYCTL_NEGATE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_INSTANTIATE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_READ"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SEARCH"))
.subcommand(clap::SubCommand::with_name("KEYCTL_UNLINK"))
.subcommand(clap::SubCommand::with_name("KEYCTL_LINK"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CLEAR"))
.subcommand(clap::SubCommand::with_name("KEYCTL_DESCRIBE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_SETPERM"))
.subcommand(clap::SubCommand::with_name("KEYCTL_CHOWN"))
.subcommand(clap::SubCommand::with_name("KEYCTL_REVOKE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_UPDATE"))
.subcommand(clap::SubCommand::with_name("KEYCTL_JOIN_SESSION_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEYCTL_GET_KEYRING_ID"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_REQUESTOR_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_GROUP_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_USER_SESSION_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_USER_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_SESSION_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_PROCESS_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_THREAD_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_DEFAULT"))
.subcommand(clap::SubCommand::with_name("KEY_REQKEY_DEFL_NO_CHANGE"))
.subcommand(clap::SubCommand::with_name("KEY_SPEC_REQUESTOR_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_SPEC_REQKEY_AUTH_KEY"))
.subcommand(clap::SubCommand::with_name("KEY_SPEC_GROUP_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_SPEC_USER_SESSION_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_SPEC_USER_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_SPEC_SESSION_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_SPEC_PROCESS_KEYRING"))
.subcommand(clap::SubCommand::with_name("KEY_SPEC_THREAD_KEYRING"))
.subcommand(clap::SubCommand::with_name("IN_DONT_FOLLOW"))
.subcommand(clap::SubCommand::with_name("IN_ONLYDIR"))
.subcommand(clap::SubCommand::with_name("IN_IGNORED"))
.subcommand(clap::SubCommand::with_name("IN_Q_OVERFLOW"))
.subcommand(clap::SubCommand::with_name("IN_UNMOUNT"))
.subcommand(clap::SubCommand::with_name("IN_MOVE_SELF"))
.subcommand(clap::SubCommand::with_name("IN_DELETE_SELF"))
.subcommand(clap::SubCommand::with_name("IN_DELETE"))
.subcommand(clap::SubCommand::with_name("IN_CREATE"))
.subcommand(clap::SubCommand::with_name("IN_MOVE"))
.subcommand(clap::SubCommand::with_name("IN_MOVED_TO"))
.subcommand(clap::SubCommand::with_name("IN_MOVED_FROM"))
.subcommand(clap::SubCommand::with_name("IN_OPEN"))
.subcommand(clap::SubCommand::with_name("IN_CLOSE"))
.subcommand(clap::SubCommand::with_name("IN_CLOSE_NOWRITE"))
.subcommand(clap::SubCommand::with_name("IN_CLOSE_WRITE"))
.subcommand(clap::SubCommand::with_name("IN_ATTRIB"))
.subcommand(clap::SubCommand::with_name("IN_MODIFY"))
.subcommand(clap::SubCommand::with_name("IN_ACCESS"))
.subcommand(clap::SubCommand::with_name("VMADDR_PORT_ANY"))
.subcommand(clap::SubCommand::with_name("VMADDR_CID_HOST"))
.subcommand(clap::SubCommand::with_name("VMADDR_CID_RESERVED"))
.subcommand(clap::SubCommand::with_name("VMADDR_CID_HYPERVISOR"))
.subcommand(clap::SubCommand::with_name("VMADDR_CID_ANY"))
.subcommand(clap::SubCommand::with_name("MAP_FIXED_NOREPLACE"))
.subcommand(clap::SubCommand::with_name("MAP_SHARED_VALIDATE"))
.subcommand(clap::SubCommand::with_name("UDP_GRO"))
.subcommand(clap::SubCommand::with_name("UDP_SEGMENT"))
.subcommand(clap::SubCommand::with_name("UDP_NO_CHECK6_RX"))
.subcommand(clap::SubCommand::with_name("UDP_NO_CHECK6_TX"))
.subcommand(clap::SubCommand::with_name("UDP_ENCAP"))
.subcommand(clap::SubCommand::with_name("UDP_CORK"))
.subcommand(clap::SubCommand::with_name("ALG_OP_ENCRYPT"))
.subcommand(clap::SubCommand::with_name("ALG_OP_DECRYPT"))
.subcommand(clap::SubCommand::with_name("ALG_SET_AEAD_AUTHSIZE"))
.subcommand(clap::SubCommand::with_name("ALG_SET_AEAD_ASSOCLEN"))
.subcommand(clap::SubCommand::with_name("ALG_SET_OP"))
.subcommand(clap::SubCommand::with_name("ALG_SET_IV"))
.subcommand(clap::SubCommand::with_name("ALG_SET_KEY"))
.subcommand(clap::SubCommand::with_name("SOF_TIMESTAMPING_RAW_HARDWARE"))
.subcommand(clap::SubCommand::with_name("SOF_TIMESTAMPING_SYS_HARDWARE"))
.subcommand(clap::SubCommand::with_name("SOF_TIMESTAMPING_SOFTWARE"))
.subcommand(clap::SubCommand::with_name("SOF_TIMESTAMPING_RX_SOFTWARE"))
.subcommand(clap::SubCommand::with_name("SOF_TIMESTAMPING_RX_HARDWARE"))
.subcommand(clap::SubCommand::with_name("SOF_TIMESTAMPING_TX_SOFTWARE"))
.subcommand(clap::SubCommand::with_name("SOF_TIMESTAMPING_TX_HARDWARE"))
.subcommand(clap::SubCommand::with_name("MODULE_INIT_IGNORE_VERMAGIC"))
.subcommand(clap::SubCommand::with_name("MODULE_INIT_IGNORE_MODVERSIONS"))
.subcommand(clap::SubCommand::with_name("SCM_TIMESTAMPING"))
.subcommand(clap::SubCommand::with_name("SO_TIMESTAMPING"))
.subcommand(clap::SubCommand::with_name("ATF_MAGIC"))
.subcommand(clap::SubCommand::with_name("ARPD_FLUSH"))
.subcommand(clap::SubCommand::with_name("ARPD_LOOKUP"))
.subcommand(clap::SubCommand::with_name("ARPD_UPDATE"))
.subcommand(clap::SubCommand::with_name("MAX_ADDR_LEN"))
.subcommand(clap::SubCommand::with_name("RTMSG_AR_FAILED"))
.subcommand(clap::SubCommand::with_name("RTMSG_CONTROL"))
.subcommand(clap::SubCommand::with_name("RTMSG_DELRULE"))
.subcommand(clap::SubCommand::with_name("RTMSG_NEWRULE"))
.subcommand(clap::SubCommand::with_name("RTMSG_DELROUTE"))
.subcommand(clap::SubCommand::with_name("RTMSG_NEWROUTE"))
.subcommand(clap::SubCommand::with_name("RTMSG_DELDEVICE"))
.subcommand(clap::SubCommand::with_name("RTMSG_NEWDEVICE"))
.subcommand(clap::SubCommand::with_name("RTMSG_OVERRUN"))
.subcommand(clap::SubCommand::with_name("RT_TABLE_LOCAL"))
.subcommand(clap::SubCommand::with_name("RT_TABLE_MAIN"))
.subcommand(clap::SubCommand::with_name("RT_TABLE_DEFAULT"))
.subcommand(clap::SubCommand::with_name("RT_TABLE_COMPAT"))
.subcommand(clap::SubCommand::with_name("RT_TABLE_UNSPEC"))
.subcommand(clap::SubCommand::with_name("RT_SCOPE_NOWHERE"))
.subcommand(clap::SubCommand::with_name("RT_SCOPE_HOST"))
.subcommand(clap::SubCommand::with_name("RT_SCOPE_LINK"))
.subcommand(clap::SubCommand::with_name("RT_SCOPE_SITE"))
.subcommand(clap::SubCommand::with_name("RT_SCOPE_UNIVERSE"))
.subcommand(clap::SubCommand::with_name("RTPROT_STATIC"))
.subcommand(clap::SubCommand::with_name("RTPROT_BOOT"))
.subcommand(clap::SubCommand::with_name("RTPROT_KERNEL"))
.subcommand(clap::SubCommand::with_name("RTPROT_REDIRECT"))
.subcommand(clap::SubCommand::with_name("RTPROT_UNSPEC"))
.subcommand(clap::SubCommand::with_name("RTN_XRESOLVE"))
.subcommand(clap::SubCommand::with_name("RTN_NAT"))
.subcommand(clap::SubCommand::with_name("RTN_THROW"))
.subcommand(clap::SubCommand::with_name("RTN_PROHIBIT"))
.subcommand(clap::SubCommand::with_name("RTN_UNREACHABLE"))
.subcommand(clap::SubCommand::with_name("RTN_BLACKHOLE"))
.subcommand(clap::SubCommand::with_name("RTN_MULTICAST"))
.subcommand(clap::SubCommand::with_name("RTN_ANYCAST"))
.subcommand(clap::SubCommand::with_name("RTN_BROADCAST"))
.subcommand(clap::SubCommand::with_name("RTN_LOCAL"))
.subcommand(clap::SubCommand::with_name("RTN_UNICAST"))
.subcommand(clap::SubCommand::with_name("RTN_UNSPEC"))
.subcommand(clap::SubCommand::with_name("RTA_MFC_STATS"))
.subcommand(clap::SubCommand::with_name("RTA_MARK"))
.subcommand(clap::SubCommand::with_name("RTA_TABLE"))
.subcommand(clap::SubCommand::with_name("RTA_MP_ALGO"))
.subcommand(clap::SubCommand::with_name("RTA_SESSION"))
.subcommand(clap::SubCommand::with_name("RTA_CACHEINFO"))
.subcommand(clap::SubCommand::with_name("RTA_FLOW"))
.subcommand(clap::SubCommand::with_name("RTA_PROTOINFO"))
.subcommand(clap::SubCommand::with_name("RTA_MULTIPATH"))
.subcommand(clap::SubCommand::with_name("RTA_METRICS"))
.subcommand(clap::SubCommand::with_name("RTA_PREFSRC"))
.subcommand(clap::SubCommand::with_name("RTA_PRIORITY"))
.subcommand(clap::SubCommand::with_name("RTA_GATEWAY"))
.subcommand(clap::SubCommand::with_name("RTA_OIF"))
.subcommand(clap::SubCommand::with_name("RTA_IIF"))
.subcommand(clap::SubCommand::with_name("RTA_SRC"))
.subcommand(clap::SubCommand::with_name("RTA_DST"))
.subcommand(clap::SubCommand::with_name("RTA_UNSPEC"))
.subcommand(clap::SubCommand::with_name("RTM_F_PREFIX"))
.subcommand(clap::SubCommand::with_name("RTM_F_EQUALIZE"))
.subcommand(clap::SubCommand::with_name("RTM_F_CLONED"))
.subcommand(clap::SubCommand::with_name("RTM_F_NOTIFY"))
.subcommand(clap::SubCommand::with_name("RTM_GETNSID"))
.subcommand(clap::SubCommand::with_name("RTM_DELNSID"))
.subcommand(clap::SubCommand::with_name("RTM_NEWNSID"))
.subcommand(clap::SubCommand::with_name("RTM_GETMDB"))
.subcommand(clap::SubCommand::with_name("RTM_DELMDB"))
.subcommand(clap::SubCommand::with_name("RTM_NEWMDB"))
.subcommand(clap::SubCommand::with_name("RTM_GETNETCONF"))
.subcommand(clap::SubCommand::with_name("RTM_NEWNETCONF"))
.subcommand(clap::SubCommand::with_name("RTM_SETDCB"))
.subcommand(clap::SubCommand::with_name("RTM_GETDCB"))
.subcommand(clap::SubCommand::with_name("RTM_GETADDRLABEL"))
.subcommand(clap::SubCommand::with_name("RTM_DELADDRLABEL"))
.subcommand(clap::SubCommand::with_name("RTM_NEWADDRLABEL"))
.subcommand(clap::SubCommand::with_name("RTM_NEWNDUSEROPT"))
.subcommand(clap::SubCommand::with_name("RTM_SETNEIGHTBL"))
.subcommand(clap::SubCommand::with_name("RTM_GETNEIGHTBL"))
.subcommand(clap::SubCommand::with_name("RTM_NEWNEIGHTBL"))
.subcommand(clap::SubCommand::with_name("RTM_GETANYCAST"))
.subcommand(clap::SubCommand::with_name("RTM_GETMULTICAST"))
.subcommand(clap::SubCommand::with_name("RTM_NEWPREFIX"))
.subcommand(clap::SubCommand::with_name("RTM_GETACTION"))
.subcommand(clap::SubCommand::with_name("RTM_DELACTION"))
.subcommand(clap::SubCommand::with_name("RTM_NEWACTION"))
.subcommand(clap::SubCommand::with_name("RTM_GETTFILTER"))
.subcommand(clap::SubCommand::with_name("RTM_DELTFILTER"))
.subcommand(clap::SubCommand::with_name("RTM_NEWTFILTER"))
.subcommand(clap::SubCommand::with_name("RTM_GETTCLASS"))
.subcommand(clap::SubCommand::with_name("RTM_DELTCLASS"))
.subcommand(clap::SubCommand::with_name("RTM_NEWTCLASS"))
.subcommand(clap::SubCommand::with_name("RTM_GETQDISC"))
.subcommand(clap::SubCommand::with_name("RTM_DELQDISC"))
.subcommand(clap::SubCommand::with_name("RTM_NEWQDISC"))
.subcommand(clap::SubCommand::with_name("RTM_GETRULE"))
.subcommand(clap::SubCommand::with_name("RTM_DELRULE"))
.subcommand(clap::SubCommand::with_name("RTM_NEWRULE"))
.subcommand(clap::SubCommand::with_name("RTM_GETNEIGH"))
.subcommand(clap::SubCommand::with_name("RTM_DELNEIGH"))
.subcommand(clap::SubCommand::with_name("RTM_NEWNEIGH"))
.subcommand(clap::SubCommand::with_name("RTM_GETROUTE"))
.subcommand(clap::SubCommand::with_name("RTM_DELROUTE"))
.subcommand(clap::SubCommand::with_name("RTM_NEWROUTE"))
.subcommand(clap::SubCommand::with_name("RTM_GETADDR"))
.subcommand(clap::SubCommand::with_name("RTM_DELADDR"))
.subcommand(clap::SubCommand::with_name("RTM_NEWADDR"))
.subcommand(clap::SubCommand::with_name("RTM_SETLINK"))
.subcommand(clap::SubCommand::with_name("RTM_GETLINK"))
.subcommand(clap::SubCommand::with_name("RTM_DELLINK"))
.subcommand(clap::SubCommand::with_name("RTM_NEWLINK"))
.subcommand(clap::SubCommand::with_name("TCA_STAB"))
.subcommand(clap::SubCommand::with_name("TCA_STATS2"))
.subcommand(clap::SubCommand::with_name("TCA_FCNT"))
.subcommand(clap::SubCommand::with_name("TCA_RATE"))
.subcommand(clap::SubCommand::with_name("TCA_XSTATS"))
.subcommand(clap::SubCommand::with_name("TCA_STATS"))
.subcommand(clap::SubCommand::with_name("TCA_OPTIONS"))
.subcommand(clap::SubCommand::with_name("TCA_KIND"))
.subcommand(clap::SubCommand::with_name("TCA_UNSPEC"))
.subcommand(clap::SubCommand::with_name("NLA_TYPE_MASK"))
.subcommand(clap::SubCommand::with_name("NLA_F_NET_BYTEORDER"))
.subcommand(clap::SubCommand::with_name("NLA_F_NESTED"))
.subcommand(clap::SubCommand::with_name("NETLINK_CAP_ACK"))
.subcommand(clap::SubCommand::with_name("NETLINK_LIST_MEMBERSHIPS"))
.subcommand(clap::SubCommand::with_name("NETLINK_LISTEN_ALL_NSID"))
.subcommand(clap::SubCommand::with_name("NETLINK_TX_RING"))
.subcommand(clap::SubCommand::with_name("NETLINK_RX_RING"))
.subcommand(clap::SubCommand::with_name("NETLINK_NO_ENOBUFS"))
.subcommand(clap::SubCommand::with_name("NETLINK_BROADCAST_ERROR"))
.subcommand(clap::SubCommand::with_name("NETLINK_PKTINFO"))
.subcommand(clap::SubCommand::with_name("NETLINK_DROP_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("NETLINK_ADD_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("NLM_F_APPEND"))
.subcommand(clap::SubCommand::with_name("NLM_F_CREATE"))
.subcommand(clap::SubCommand::with_name("NLM_F_EXCL"))
.subcommand(clap::SubCommand::with_name("NLM_F_REPLACE"))
.subcommand(clap::SubCommand::with_name("NLM_F_DUMP"))
.subcommand(clap::SubCommand::with_name("NLM_F_ATOMIC"))
.subcommand(clap::SubCommand::with_name("NLM_F_MATCH"))
.subcommand(clap::SubCommand::with_name("NLM_F_ROOT"))
.subcommand(clap::SubCommand::with_name("NLM_F_DUMP_FILTERED"))
.subcommand(clap::SubCommand::with_name("NLM_F_DUMP_INTR"))
.subcommand(clap::SubCommand::with_name("NLM_F_ECHO"))
.subcommand(clap::SubCommand::with_name("NLM_F_ACK"))
.subcommand(clap::SubCommand::with_name("NLM_F_MULTI"))
.subcommand(clap::SubCommand::with_name("NLM_F_REQUEST"))
.subcommand(clap::SubCommand::with_name("NETLINK_INET_DIAG"))
.subcommand(clap::SubCommand::with_name("NETLINK_CRYPTO"))
.subcommand(clap::SubCommand::with_name("NETLINK_RDMA"))
.subcommand(clap::SubCommand::with_name("NETLINK_ECRYPTFS"))
.subcommand(clap::SubCommand::with_name("NETLINK_SCSITRANSPORT"))
.subcommand(clap::SubCommand::with_name("NETLINK_GENERIC"))
.subcommand(clap::SubCommand::with_name("NETLINK_KOBJECT_UEVENT"))
.subcommand(clap::SubCommand::with_name("NETLINK_DNRTMSG"))
.subcommand(clap::SubCommand::with_name("NETLINK_IP6_FW"))
.subcommand(clap::SubCommand::with_name("NETLINK_NETFILTER"))
.subcommand(clap::SubCommand::with_name("NETLINK_CONNECTOR"))
.subcommand(clap::SubCommand::with_name("NETLINK_FIB_LOOKUP"))
.subcommand(clap::SubCommand::with_name("NETLINK_AUDIT"))
.subcommand(clap::SubCommand::with_name("NETLINK_ISCSI"))
.subcommand(clap::SubCommand::with_name("NETLINK_SELINUX"))
.subcommand(clap::SubCommand::with_name("NETLINK_XFRM"))
.subcommand(clap::SubCommand::with_name("NETLINK_NFLOG"))
.subcommand(clap::SubCommand::with_name("NETLINK_SOCK_DIAG"))
.subcommand(clap::SubCommand::with_name("NETLINK_FIREWALL"))
.subcommand(clap::SubCommand::with_name("NETLINK_USERSOCK"))
.subcommand(clap::SubCommand::with_name("NETLINK_UNUSED"))
.subcommand(clap::SubCommand::with_name("NETLINK_ROUTE"))
.subcommand(clap::SubCommand::with_name("NLA_ALIGNTO"))
.subcommand(clap::SubCommand::with_name("NDA_IFINDEX"))
.subcommand(clap::SubCommand::with_name("NDA_VNI"))
.subcommand(clap::SubCommand::with_name("NDA_PORT"))
.subcommand(clap::SubCommand::with_name("NDA_VLAN"))
.subcommand(clap::SubCommand::with_name("NDA_PROBES"))
.subcommand(clap::SubCommand::with_name("NDA_CACHEINFO"))
.subcommand(clap::SubCommand::with_name("NDA_LLADDR"))
.subcommand(clap::SubCommand::with_name("NDA_DST"))
.subcommand(clap::SubCommand::with_name("NDA_UNSPEC"))
.subcommand(clap::SubCommand::with_name("NTF_ROUTER"))
.subcommand(clap::SubCommand::with_name("NTF_PROXY"))
.subcommand(clap::SubCommand::with_name("NTF_MASTER"))
.subcommand(clap::SubCommand::with_name("NTF_SELF"))
.subcommand(clap::SubCommand::with_name("NTF_USE"))
.subcommand(clap::SubCommand::with_name("NUD_PERMANENT"))
.subcommand(clap::SubCommand::with_name("NUD_NOARP"))
.subcommand(clap::SubCommand::with_name("NUD_FAILED"))
.subcommand(clap::SubCommand::with_name("NUD_PROBE"))
.subcommand(clap::SubCommand::with_name("NUD_DELAY"))
.subcommand(clap::SubCommand::with_name("NUD_STALE"))
.subcommand(clap::SubCommand::with_name("NUD_REACHABLE"))
.subcommand(clap::SubCommand::with_name("NUD_INCOMPLETE"))
.subcommand(clap::SubCommand::with_name("NUD_NONE"))
.subcommand(clap::SubCommand::with_name("RT_CLASS_MAX"))
.subcommand(clap::SubCommand::with_name("RT_CLASS_LOCAL"))
.subcommand(clap::SubCommand::with_name("RT_CLASS_MAIN"))
.subcommand(clap::SubCommand::with_name("RT_CLASS_DEFAULT"))
.subcommand(clap::SubCommand::with_name("RT_CLASS_UNSPEC"))
.subcommand(clap::SubCommand::with_name("RTF_ADDRCLASSMASK"))
.subcommand(clap::SubCommand::with_name("RTF_NAT"))
.subcommand(clap::SubCommand::with_name("RTF_BROADCAST"))
.subcommand(clap::SubCommand::with_name("RTF_MULTICAST"))
.subcommand(clap::SubCommand::with_name("RTF_INTERFACE"))
.subcommand(clap::SubCommand::with_name("RTF_LOCAL"))
.subcommand(clap::SubCommand::with_name("RTCF_DIRECTSRC"))
.subcommand(clap::SubCommand::with_name("RTCF_LOG"))
.subcommand(clap::SubCommand::with_name("RTCF_DOREDIRECT"))
.subcommand(clap::SubCommand::with_name("RTCF_NAT"))
.subcommand(clap::SubCommand::with_name("RTCF_MASQ"))
.subcommand(clap::SubCommand::with_name("RTCF_VALVE"))
.subcommand(clap::SubCommand::with_name("RTF_POLICY"))
.subcommand(clap::SubCommand::with_name("RTF_FLOW"))
.subcommand(clap::SubCommand::with_name("RTF_CACHE"))
.subcommand(clap::SubCommand::with_name("RTF_NONEXTHOP"))
.subcommand(clap::SubCommand::with_name("RTF_LINKRT"))
.subcommand(clap::SubCommand::with_name("RTF_ADDRCONF"))
.subcommand(clap::SubCommand::with_name("RTF_ALLONLINK"))
.subcommand(clap::SubCommand::with_name("RTF_DEFAULT"))
.subcommand(clap::SubCommand::with_name("RTF_NOPMTUDISC"))
.subcommand(clap::SubCommand::with_name("RTF_THROW"))
.subcommand(clap::SubCommand::with_name("RTF_NOFORWARD"))
.subcommand(clap::SubCommand::with_name("RTF_XRESOLVE"))
.subcommand(clap::SubCommand::with_name("RTF_STATIC"))
.subcommand(clap::SubCommand::with_name("RTF_REJECT"))
.subcommand(clap::SubCommand::with_name("RTF_IRTT"))
.subcommand(clap::SubCommand::with_name("RTF_WINDOW"))
.subcommand(clap::SubCommand::with_name("RTF_MSS"))
.subcommand(clap::SubCommand::with_name("RTF_MTU"))
.subcommand(clap::SubCommand::with_name("RTF_MODIFIED"))
.subcommand(clap::SubCommand::with_name("RTF_DYNAMIC"))
.subcommand(clap::SubCommand::with_name("RTF_REINSTATE"))
.subcommand(clap::SubCommand::with_name("RTF_HOST"))
.subcommand(clap::SubCommand::with_name("RTF_GATEWAY"))
.subcommand(clap::SubCommand::with_name("RTF_UP"))
.subcommand(clap::SubCommand::with_name("IPTOS_ECN_NOT_ECT"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_MASK"))
.subcommand(clap::SubCommand::with_name("IPTOS_TOS_MASK"))
.subcommand(clap::SubCommand::with_name("SIOCSIFMAP"))
.subcommand(clap::SubCommand::with_name("SIOCGIFMAP"))
.subcommand(clap::SubCommand::with_name("SIOCSRARP"))
.subcommand(clap::SubCommand::with_name("SIOCGRARP"))
.subcommand(clap::SubCommand::with_name("SIOCDRARP"))
.subcommand(clap::SubCommand::with_name("SIOCSARP"))
.subcommand(clap::SubCommand::with_name("SIOCGARP"))
.subcommand(clap::SubCommand::with_name("SIOCDARP"))
.subcommand(clap::SubCommand::with_name("SIOCDELMULTI"))
.subcommand(clap::SubCommand::with_name("SIOCADDMULTI"))
.subcommand(clap::SubCommand::with_name("SIOCSIFSLAVE"))
.subcommand(clap::SubCommand::with_name("SIOCGIFSLAVE"))
.subcommand(clap::SubCommand::with_name("SIOCGIFHWADDR"))
.subcommand(clap::SubCommand::with_name("SIOCSIFENCAP"))
.subcommand(clap::SubCommand::with_name("SIOCGIFENCAP"))
.subcommand(clap::SubCommand::with_name("SIOCSIFHWADDR"))
.subcommand(clap::SubCommand::with_name("SIOCSIFMTU"))
.subcommand(clap::SubCommand::with_name("SIOCGIFMTU"))
.subcommand(clap::SubCommand::with_name("SIOCSIFMEM"))
.subcommand(clap::SubCommand::with_name("SIOCGIFMEM"))
.subcommand(clap::SubCommand::with_name("SIOCSIFMETRIC"))
.subcommand(clap::SubCommand::with_name("SIOCGIFMETRIC"))
.subcommand(clap::SubCommand::with_name("SIOCSIFNETMASK"))
.subcommand(clap::SubCommand::with_name("SIOCGIFNETMASK"))
.subcommand(clap::SubCommand::with_name("SIOCSIFBRDADDR"))
.subcommand(clap::SubCommand::with_name("SIOCGIFBRDADDR"))
.subcommand(clap::SubCommand::with_name("SIOCSIFDSTADDR"))
.subcommand(clap::SubCommand::with_name("SIOCGIFDSTADDR"))
.subcommand(clap::SubCommand::with_name("SIOCSIFADDR"))
.subcommand(clap::SubCommand::with_name("SIOCGIFADDR"))
.subcommand(clap::SubCommand::with_name("SIOCSIFFLAGS"))
.subcommand(clap::SubCommand::with_name("SIOCGIFFLAGS"))
.subcommand(clap::SubCommand::with_name("SIOCGIFCONF"))
.subcommand(clap::SubCommand::with_name("SIOCSIFLINK"))
.subcommand(clap::SubCommand::with_name("SIOCGIFNAME"))
.subcommand(clap::SubCommand::with_name("SIOCDELRT"))
.subcommand(clap::SubCommand::with_name("SIOCADDRT"))
.subcommand(clap::SubCommand::with_name("IP6T_SO_ORIGINAL_DST"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_LAST"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_CONNTRACK_HELPER"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_SELINUX_LAST"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_NAT_SRC"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_SECURITY"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_FILTER"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_NAT_DST"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_MANGLE"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_CONNTRACK"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_SELINUX_FIRST"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_RAW"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_CONNTRACK_DEFRAG"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRI_FIRST"))
.subcommand(clap::SubCommand::with_name("NF_IP6_NUMHOOKS"))
.subcommand(clap::SubCommand::with_name("NF_IP6_POST_ROUTING"))
.subcommand(clap::SubCommand::with_name("NF_IP6_LOCAL_OUT"))
.subcommand(clap::SubCommand::with_name("NF_IP6_FORWARD"))
.subcommand(clap::SubCommand::with_name("NF_IP6_LOCAL_IN"))
.subcommand(clap::SubCommand::with_name("NF_IP6_PRE_ROUTING"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_LAST"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_CONNTRACK_CONFIRM"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_CONNTRACK_HELPER"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_SELINUX_LAST"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_NAT_SRC"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_SECURITY"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_FILTER"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_NAT_DST"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_MANGLE"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_CONNTRACK"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_SELINUX_FIRST"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_RAW"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_CONNTRACK_DEFRAG"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRI_FIRST"))
.subcommand(clap::SubCommand::with_name("NF_IP_NUMHOOKS"))
.subcommand(clap::SubCommand::with_name("NF_IP_POST_ROUTING"))
.subcommand(clap::SubCommand::with_name("NF_IP_LOCAL_OUT"))
.subcommand(clap::SubCommand::with_name("NF_IP_FORWARD"))
.subcommand(clap::SubCommand::with_name("NF_IP_LOCAL_IN"))
.subcommand(clap::SubCommand::with_name("NF_IP_PRE_ROUTING"))
.subcommand(clap::SubCommand::with_name("NFPROTO_NUMPROTO"))
.subcommand(clap::SubCommand::with_name("NFPROTO_DECNET"))
.subcommand(clap::SubCommand::with_name("NFPROTO_IPV6"))
.subcommand(clap::SubCommand::with_name("NFPROTO_BRIDGE"))
.subcommand(clap::SubCommand::with_name("NFPROTO_ARP"))
.subcommand(clap::SubCommand::with_name("NFPROTO_IPV4"))
.subcommand(clap::SubCommand::with_name("NFPROTO_UNSPEC"))
.subcommand(clap::SubCommand::with_name("NF_INET_NUMHOOKS"))
.subcommand(clap::SubCommand::with_name("NF_INET_POST_ROUTING"))
.subcommand(clap::SubCommand::with_name("NF_INET_LOCAL_OUT"))
.subcommand(clap::SubCommand::with_name("NF_INET_FORWARD"))
.subcommand(clap::SubCommand::with_name("NF_INET_LOCAL_IN"))
.subcommand(clap::SubCommand::with_name("NF_INET_PRE_ROUTING"))
.subcommand(clap::SubCommand::with_name("NF_VERDICT_BITS"))
.subcommand(clap::SubCommand::with_name("NF_VERDICT_QBITS"))
.subcommand(clap::SubCommand::with_name("NF_VERDICT_QMASK"))
.subcommand(clap::SubCommand::with_name("NF_VERDICT_FLAG_QUEUE_BYPASS"))
.subcommand(clap::SubCommand::with_name("NF_VERDICT_MASK"))
.subcommand(clap::SubCommand::with_name("NF_MAX_VERDICT"))
.subcommand(clap::SubCommand::with_name("NF_STOP"))
.subcommand(clap::SubCommand::with_name("NF_REPEAT"))
.subcommand(clap::SubCommand::with_name("NF_QUEUE"))
.subcommand(clap::SubCommand::with_name("NF_STOLEN"))
.subcommand(clap::SubCommand::with_name("NF_ACCEPT"))
.subcommand(clap::SubCommand::with_name("NF_DROP"))
.subcommand(clap::SubCommand::with_name("PACKET_MR_UNICAST"))
.subcommand(clap::SubCommand::with_name("PACKET_MR_ALLMULTI"))
.subcommand(clap::SubCommand::with_name("PACKET_MR_PROMISC"))
.subcommand(clap::SubCommand::with_name("PACKET_MR_MULTICAST"))
.subcommand(clap::SubCommand::with_name("PACKET_DROP_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("PACKET_ADD_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_MCAST_GRP_ID"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_MCAST_GRP_NAME"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_MCAST_GRP_UNSPEC"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_OP_FLAGS"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_OP_ID"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_OP_UNSPEC"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_MCAST_GROUPS"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_OPS"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_MAXATTR"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_HDRSIZE"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_VERSION"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_FAMILY_NAME"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_FAMILY_ID"))
.subcommand(clap::SubCommand::with_name("CTRL_ATTR_UNSPEC"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_GETMCAST_GRP"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_DELMCAST_GRP"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_NEWMCAST_GRP"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_GETOPS"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_DELOPS"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_NEWOPS"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_GETFAMILY"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_DELFAMILY"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_NEWFAMILY"))
.subcommand(clap::SubCommand::with_name("CTRL_CMD_UNSPEC"))
.subcommand(clap::SubCommand::with_name("GENL_ID_CTRL"))
.subcommand(clap::SubCommand::with_name("GENL_CMD_CAP_HASPOL"))
.subcommand(clap::SubCommand::with_name("GENL_CMD_CAP_DUMP"))
.subcommand(clap::SubCommand::with_name("GENL_CMD_CAP_DO"))
.subcommand(clap::SubCommand::with_name("GENL_ADMIN_PERM"))
.subcommand(clap::SubCommand::with_name("GENL_MAX_ID"))
.subcommand(clap::SubCommand::with_name("GENL_MIN_ID"))
.subcommand(clap::SubCommand::with_name("GENL_NAMSIZ"))
.subcommand(clap::SubCommand::with_name("NFQA_SKB_CSUM_NOTVERIFIED"))
.subcommand(clap::SubCommand::with_name("NFQA_SKB_GSO"))
.subcommand(clap::SubCommand::with_name("NFQA_SKB_CSUMNOTREADY"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_F_MAX"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_F_SECCTX"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_F_UID_GID"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_F_GSO"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_F_CONNTRACK"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_F_FAIL_OPEN"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_FLAGS"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_MASK"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_QUEUE_MAXLEN"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_PARAMS"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_CMD"))
.subcommand(clap::SubCommand::with_name("NFQA_CFG_UNSPEC"))
.subcommand(clap::SubCommand::with_name("NFQNL_COPY_PACKET"))
.subcommand(clap::SubCommand::with_name("NFQNL_COPY_META"))
.subcommand(clap::SubCommand::with_name("NFQNL_COPY_NONE"))
.subcommand(clap::SubCommand::with_name("NFQNL_CFG_CMD_PF_UNBIND"))
.subcommand(clap::SubCommand::with_name("NFQNL_CFG_CMD_PF_BIND"))
.subcommand(clap::SubCommand::with_name("NFQNL_CFG_CMD_UNBIND"))
.subcommand(clap::SubCommand::with_name("NFQNL_CFG_CMD_BIND"))
.subcommand(clap::SubCommand::with_name("NFQNL_CFG_CMD_NONE"))
.subcommand(clap::SubCommand::with_name("NFQA_SECCTX"))
.subcommand(clap::SubCommand::with_name("NFQA_GID"))
.subcommand(clap::SubCommand::with_name("NFQA_UID"))
.subcommand(clap::SubCommand::with_name("NFQA_EXP"))
.subcommand(clap::SubCommand::with_name("NFQA_SKB_INFO"))
.subcommand(clap::SubCommand::with_name("NFQA_CAP_LEN"))
.subcommand(clap::SubCommand::with_name("NFQA_CT_INFO"))
.subcommand(clap::SubCommand::with_name("NFQA_CT"))
.subcommand(clap::SubCommand::with_name("NFQA_PAYLOAD"))
.subcommand(clap::SubCommand::with_name("NFQA_HWADDR"))
.subcommand(clap::SubCommand::with_name("NFQA_IFINDEX_PHYSOUTDEV"))
.subcommand(clap::SubCommand::with_name("NFQA_IFINDEX_PHYSINDEV"))
.subcommand(clap::SubCommand::with_name("NFQA_IFINDEX_OUTDEV"))
.subcommand(clap::SubCommand::with_name("NFQA_IFINDEX_INDEV"))
.subcommand(clap::SubCommand::with_name("NFQA_TIMESTAMP"))
.subcommand(clap::SubCommand::with_name("NFQA_MARK"))
.subcommand(clap::SubCommand::with_name("NFQA_VERDICT_HDR"))
.subcommand(clap::SubCommand::with_name("NFQA_PACKET_HDR"))
.subcommand(clap::SubCommand::with_name("NFQA_UNSPEC"))
.subcommand(clap::SubCommand::with_name("NFQNL_MSG_VERDICT_BATCH"))
.subcommand(clap::SubCommand::with_name("NFQNL_MSG_CONFIG"))
.subcommand(clap::SubCommand::with_name("NFQNL_MSG_VERDICT"))
.subcommand(clap::SubCommand::with_name("NFQNL_MSG_PACKET"))
.subcommand(clap::SubCommand::with_name("NFULNL_CFG_F_CONNTRACK"))
.subcommand(clap::SubCommand::with_name("NFULNL_CFG_F_SEQ_GLOBAL"))
.subcommand(clap::SubCommand::with_name("NFULNL_CFG_F_SEQ"))
.subcommand(clap::SubCommand::with_name("NFULNL_COPY_PACKET"))
.subcommand(clap::SubCommand::with_name("NFULNL_COPY_META"))
.subcommand(clap::SubCommand::with_name("NFULNL_COPY_NONE"))
.subcommand(clap::SubCommand::with_name("NFULA_CFG_FLAGS"))
.subcommand(clap::SubCommand::with_name("NFULA_CFG_QTHRESH"))
.subcommand(clap::SubCommand::with_name("NFULA_CFG_TIMEOUT"))
.subcommand(clap::SubCommand::with_name("NFULA_CFG_NLBUFSIZ"))
.subcommand(clap::SubCommand::with_name("NFULA_CFG_MODE"))
.subcommand(clap::SubCommand::with_name("NFULA_CFG_CMD"))
.subcommand(clap::SubCommand::with_name("NFULA_CFG_UNSPEC"))
.subcommand(clap::SubCommand::with_name("NFULNL_CFG_CMD_PF_UNBIND"))
.subcommand(clap::SubCommand::with_name("NFULNL_CFG_CMD_PF_BIND"))
.subcommand(clap::SubCommand::with_name("NFULNL_CFG_CMD_UNBIND"))
.subcommand(clap::SubCommand::with_name("NFULNL_CFG_CMD_BIND"))
.subcommand(clap::SubCommand::with_name("NFULNL_CFG_CMD_NONE"))
.subcommand(clap::SubCommand::with_name("NFULA_CT_INFO"))
.subcommand(clap::SubCommand::with_name("NFULA_CT"))
.subcommand(clap::SubCommand::with_name("NFULA_HWLEN"))
.subcommand(clap::SubCommand::with_name("NFULA_HWHEADER"))
.subcommand(clap::SubCommand::with_name("NFULA_HWTYPE"))
.subcommand(clap::SubCommand::with_name("NFULA_GID"))
.subcommand(clap::SubCommand::with_name("NFULA_SEQ_GLOBAL"))
.subcommand(clap::SubCommand::with_name("NFULA_SEQ"))
.subcommand(clap::SubCommand::with_name("NFULA_UID"))
.subcommand(clap::SubCommand::with_name("NFULA_PREFIX"))
.subcommand(clap::SubCommand::with_name("NFULA_PAYLOAD"))
.subcommand(clap::SubCommand::with_name("NFULA_HWADDR"))
.subcommand(clap::SubCommand::with_name("NFULA_IFINDEX_PHYSOUTDEV"))
.subcommand(clap::SubCommand::with_name("NFULA_IFINDEX_PHYSINDEV"))
.subcommand(clap::SubCommand::with_name("NFULA_IFINDEX_OUTDEV"))
.subcommand(clap::SubCommand::with_name("NFULA_IFINDEX_INDEV"))
.subcommand(clap::SubCommand::with_name("NFULA_TIMESTAMP"))
.subcommand(clap::SubCommand::with_name("NFULA_MARK"))
.subcommand(clap::SubCommand::with_name("NFULA_PACKET_HDR"))
.subcommand(clap::SubCommand::with_name("NFULA_UNSPEC"))
.subcommand(clap::SubCommand::with_name("NFULNL_MSG_CONFIG"))
.subcommand(clap::SubCommand::with_name("NFULNL_MSG_PACKET"))
.subcommand(clap::SubCommand::with_name("NFNL_MSG_BATCH_END"))
.subcommand(clap::SubCommand::with_name("NFNL_MSG_BATCH_BEGIN"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_COUNT"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_NFT_COMPAT"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_NFTABLES"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_CTHELPER"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_CTNETLINK_TIMEOUT"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_ACCT"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_IPSET"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_OSF"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_ULOG"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_QUEUE"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_CTNETLINK_EXP"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_CTNETLINK"))
.subcommand(clap::SubCommand::with_name("NFNL_SUBSYS_NONE"))
.subcommand(clap::SubCommand::with_name("NFNETLINK_V0"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_ACCT_QUOTA"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_NFTABLES"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_CONNTRACK_EXP_DESTROY"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_CONNTRACK_EXP_UPDATE"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_CONNTRACK_EXP_NEW"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_CONNTRACK_DESTROY"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_CONNTRACK_UPDATE"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_CONNTRACK_NEW"))
.subcommand(clap::SubCommand::with_name("NFNLGRP_NONE"))
.subcommand(clap::SubCommand::with_name("NLMSG_MIN_TYPE"))
.subcommand(clap::SubCommand::with_name("NLMSG_OVERRUN"))
.subcommand(clap::SubCommand::with_name("NLMSG_DONE"))
.subcommand(clap::SubCommand::with_name("NLMSG_ERROR"))
.subcommand(clap::SubCommand::with_name("NLMSG_NOOP"))
.subcommand(clap::SubCommand::with_name("POSIX_SPAWN_SETSCHEDULER"))
.subcommand(clap::SubCommand::with_name("POSIX_SPAWN_SETSCHEDPARAM"))
.subcommand(clap::SubCommand::with_name("POSIX_SPAWN_SETSIGMASK"))
.subcommand(clap::SubCommand::with_name("POSIX_SPAWN_SETSIGDEF"))
.subcommand(clap::SubCommand::with_name("POSIX_SPAWN_SETPGROUP"))
.subcommand(clap::SubCommand::with_name("POSIX_SPAWN_RESETIDS"))
.subcommand(clap::SubCommand::with_name("ETH_P_CAIF"))
.subcommand(clap::SubCommand::with_name("ETH_P_IEEE802154"))
.subcommand(clap::SubCommand::with_name("ETH_P_PHONET"))
.subcommand(clap::SubCommand::with_name("ETH_P_TRAILER"))
.subcommand(clap::SubCommand::with_name("ETH_P_DSA"))
.subcommand(clap::SubCommand::with_name("ETH_P_ARCNET"))
.subcommand(clap::SubCommand::with_name("ETH_P_HDLC"))
.subcommand(clap::SubCommand::with_name("ETH_P_ECONET"))
.subcommand(clap::SubCommand::with_name("ETH_P_IRDA"))
.subcommand(clap::SubCommand::with_name("ETH_P_CONTROL"))
.subcommand(clap::SubCommand::with_name("ETH_P_MOBITEX"))
.subcommand(clap::SubCommand::with_name("ETH_P_TR_802_2"))
.subcommand(clap::SubCommand::with_name("ETH_P_PPPTALK"))
.subcommand(clap::SubCommand::with_name("ETH_P_CANFD"))
.subcommand(clap::SubCommand::with_name("ETH_P_LOCALTALK"))
.subcommand(clap::SubCommand::with_name("ETH_P_PPP_MP"))
.subcommand(clap::SubCommand::with_name("ETH_P_WAN_PPP"))
.subcommand(clap::SubCommand::with_name("ETH_P_DDCMP"))
.subcommand(clap::SubCommand::with_name("ETH_P_SNAP"))
.subcommand(clap::SubCommand::with_name("ETH_P_802_2"))
.subcommand(clap::SubCommand::with_name("ETH_P_ALL"))
.subcommand(clap::SubCommand::with_name("ETH_P_AX25"))
.subcommand(clap::SubCommand::with_name("ETH_P_802_3"))
.subcommand(clap::SubCommand::with_name("ETH_P_802_3_MIN"))
.subcommand(clap::SubCommand::with_name("ETH_P_AF_IUCV"))
.subcommand(clap::SubCommand::with_name("ETH_P_EDSA"))
.subcommand(clap::SubCommand::with_name("ETH_P_QINQ3"))
.subcommand(clap::SubCommand::with_name("ETH_P_QINQ2"))
.subcommand(clap::SubCommand::with_name("ETH_P_QINQ1"))
.subcommand(clap::SubCommand::with_name("ETH_P_LOOPBACK"))
.subcommand(clap::SubCommand::with_name("ETH_P_80221"))
.subcommand(clap::SubCommand::with_name("ETH_P_FIP"))
.subcommand(clap::SubCommand::with_name("ETH_P_TDLS"))
.subcommand(clap::SubCommand::with_name("ETH_P_FCOE"))
.subcommand(clap::SubCommand::with_name("ETH_P_PRP"))
.subcommand(clap::SubCommand::with_name("ETH_P_1588"))
.subcommand(clap::SubCommand::with_name("ETH_P_MVRP"))
.subcommand(clap::SubCommand::with_name("ETH_P_8021AH"))
.subcommand(clap::SubCommand::with_name("ETH_P_MACSEC"))
.subcommand(clap::SubCommand::with_name("ETH_P_TIPC"))
.subcommand(clap::SubCommand::with_name("ETH_P_802_EX1"))
.subcommand(clap::SubCommand::with_name("ETH_P_8021AD"))
.subcommand(clap::SubCommand::with_name("ETH_P_AOE"))
.subcommand(clap::SubCommand::with_name("ETH_P_PAE"))
.subcommand(clap::SubCommand::with_name("ETH_P_ATMFATE"))
.subcommand(clap::SubCommand::with_name("ETH_P_LINK_CTL"))
.subcommand(clap::SubCommand::with_name("ETH_P_PPP_SES"))
.subcommand(clap::SubCommand::with_name("ETH_P_PPP_DISC"))
.subcommand(clap::SubCommand::with_name("ETH_P_ATMMPOA"))
.subcommand(clap::SubCommand::with_name("ETH_P_MPLS_MC"))
.subcommand(clap::SubCommand::with_name("ETH_P_MPLS_UC"))
.subcommand(clap::SubCommand::with_name("ETH_P_WCCP"))
.subcommand(clap::SubCommand::with_name("ETH_P_SLOW"))
.subcommand(clap::SubCommand::with_name("ETH_P_PAUSE"))
.subcommand(clap::SubCommand::with_name("ETH_P_IPV6"))
.subcommand(clap::SubCommand::with_name("ETH_P_IPX"))
.subcommand(clap::SubCommand::with_name("ETH_P_8021Q"))
.subcommand(clap::SubCommand::with_name("ETH_P_AARP"))
.subcommand(clap::SubCommand::with_name("ETH_P_ATALK"))
.subcommand(clap::SubCommand::with_name("ETH_P_RARP"))
.subcommand(clap::SubCommand::with_name("ETH_P_TEB"))
.subcommand(clap::SubCommand::with_name("ETH_P_SCA"))
.subcommand(clap::SubCommand::with_name("ETH_P_CUST"))
.subcommand(clap::SubCommand::with_name("ETH_P_DIAG"))
.subcommand(clap::SubCommand::with_name("ETH_P_LAT"))
.subcommand(clap::SubCommand::with_name("ETH_P_DNA_RT"))
.subcommand(clap::SubCommand::with_name("ETH_P_DNA_RC"))
.subcommand(clap::SubCommand::with_name("ETH_P_DNA_DL"))
.subcommand(clap::SubCommand::with_name("ETH_P_DEC"))
.subcommand(clap::SubCommand::with_name("ETH_P_BATMAN"))
.subcommand(clap::SubCommand::with_name("ETH_P_IEEEPUPAT"))
.subcommand(clap::SubCommand::with_name("ETH_P_IEEEPUP"))
.subcommand(clap::SubCommand::with_name("ETH_P_BPQ"))
.subcommand(clap::SubCommand::with_name("ETH_P_ARP"))
.subcommand(clap::SubCommand::with_name("ETH_P_X25"))
.subcommand(clap::SubCommand::with_name("ETH_P_IP"))
.subcommand(clap::SubCommand::with_name("ETH_P_PUPAT"))
.subcommand(clap::SubCommand::with_name("ETH_P_PUP"))
.subcommand(clap::SubCommand::with_name("ETH_P_LOOP"))
.subcommand(clap::SubCommand::with_name("ETH_FCS_LEN"))
.subcommand(clap::SubCommand::with_name("ETH_FRAME_LEN"))
.subcommand(clap::SubCommand::with_name("ETH_DATA_LEN"))
.subcommand(clap::SubCommand::with_name("ETH_ZLEN"))
.subcommand(clap::SubCommand::with_name("ETH_HLEN"))
.subcommand(clap::SubCommand::with_name("ETH_ALEN"))
.subcommand(clap::SubCommand::with_name("PT_GNU_RELRO"))
.subcommand(clap::SubCommand::with_name("PT_GNU_STACK"))
.subcommand(clap::SubCommand::with_name("PT_GNU_EH_FRAME"))
.subcommand(clap::SubCommand::with_name("PT_LOOS"))
.subcommand(clap::SubCommand::with_name("PT_NUM"))
.subcommand(clap::SubCommand::with_name("PT_TLS"))
.subcommand(clap::SubCommand::with_name("PT_PHDR"))
.subcommand(clap::SubCommand::with_name("PT_SHLIB"))
.subcommand(clap::SubCommand::with_name("PT_NOTE"))
.subcommand(clap::SubCommand::with_name("PT_INTERP"))
.subcommand(clap::SubCommand::with_name("PT_DYNAMIC"))
.subcommand(clap::SubCommand::with_name("PT_LOAD"))
.subcommand(clap::SubCommand::with_name("PT_NULL"))
.subcommand(clap::SubCommand::with_name("MFD_HUGETLB"))
.subcommand(clap::SubCommand::with_name("MFD_ALLOW_SEALING"))
.subcommand(clap::SubCommand::with_name("MFD_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("CMSPAR"))
.subcommand(clap::SubCommand::with_name("IUTF8"))
.subcommand(clap::SubCommand::with_name("IPV6_FLOWINFO_PRIORITY"))
.subcommand(clap::SubCommand::with_name("IPV6_FLOWINFO_FLOWLABEL"))
.subcommand(clap::SubCommand::with_name("IPV6_FLOWINFO_SEND"))
.subcommand(clap::SubCommand::with_name("IPV6_FLOWLABEL_MGR"))
.subcommand(clap::SubCommand::with_name("IPV6_RECVORIGDSTADDR"))
.subcommand(clap::SubCommand::with_name("IPV6_ORIGDSTADDR"))
.subcommand(clap::SubCommand::with_name("IPV6_FLOWINFO"))
.subcommand(clap::SubCommand::with_name("IP_RECVORIGDSTADDR"))
.subcommand(clap::SubCommand::with_name("IP_ORIGDSTADDR"))
.subcommand(clap::SubCommand::with_name("SO_ORIGINAL_DST"))
.subcommand(clap::SubCommand::with_name("ENOATTR"))
.subcommand(clap::SubCommand::with_name("FALLOC_FL_UNSHARE_RANGE"))
.subcommand(clap::SubCommand::with_name("FALLOC_FL_INSERT_RANGE"))
.subcommand(clap::SubCommand::with_name("FALLOC_FL_ZERO_RANGE"))
.subcommand(clap::SubCommand::with_name("FALLOC_FL_COLLAPSE_RANGE"))
.subcommand(clap::SubCommand::with_name("FALLOC_FL_PUNCH_HOLE"))
.subcommand(clap::SubCommand::with_name("FALLOC_FL_KEEP_SIZE"))
.subcommand(clap::SubCommand::with_name("_POSIX_VDISABLE"))
.subcommand(clap::SubCommand::with_name("XATTR_REPLACE"))
.subcommand(clap::SubCommand::with_name("XATTR_CREATE"))
.subcommand(clap::SubCommand::with_name("TFD_TIMER_ABSTIME"))
.subcommand(clap::SubCommand::with_name("TFD_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("TFD_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("ITIMER_PROF"))
.subcommand(clap::SubCommand::with_name("ITIMER_VIRTUAL"))
.subcommand(clap::SubCommand::with_name("ITIMER_REAL"))
.subcommand(clap::SubCommand::with_name("SECCOMP_MODE_FILTER"))
.subcommand(clap::SubCommand::with_name("SECCOMP_MODE_STRICT"))
.subcommand(clap::SubCommand::with_name("SECCOMP_MODE_DISABLED"))
.subcommand(clap::SubCommand::with_name("GRND_RANDOM"))
.subcommand(clap::SubCommand::with_name("GRND_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("PR_CAP_AMBIENT_CLEAR_ALL"))
.subcommand(clap::SubCommand::with_name("PR_CAP_AMBIENT_LOWER"))
.subcommand(clap::SubCommand::with_name("PR_CAP_AMBIENT_RAISE"))
.subcommand(clap::SubCommand::with_name("PR_CAP_AMBIENT_IS_SET"))
.subcommand(clap::SubCommand::with_name("PR_CAP_AMBIENT"))
.subcommand(clap::SubCommand::with_name("PR_FP_MODE_FRE"))
.subcommand(clap::SubCommand::with_name("PR_FP_MODE_FR"))
.subcommand(clap::SubCommand::with_name("PR_GET_FP_MODE"))
.subcommand(clap::SubCommand::with_name("PR_SET_FP_MODE"))
.subcommand(clap::SubCommand::with_name("PR_MPX_DISABLE_MANAGEMENT"))
.subcommand(clap::SubCommand::with_name("PR_MPX_ENABLE_MANAGEMENT"))
.subcommand(clap::SubCommand::with_name("PR_GET_THP_DISABLE"))
.subcommand(clap::SubCommand::with_name("PR_SET_THP_DISABLE"))
.subcommand(clap::SubCommand::with_name("PR_GET_TID_ADDRESS"))
.subcommand(clap::SubCommand::with_name("PR_GET_NO_NEW_PRIVS"))
.subcommand(clap::SubCommand::with_name("PR_SET_NO_NEW_PRIVS"))
.subcommand(clap::SubCommand::with_name("PR_GET_CHILD_SUBREAPER"))
.subcommand(clap::SubCommand::with_name("PR_SET_CHILD_SUBREAPER"))
.subcommand(clap::SubCommand::with_name("PR_SET_PTRACER"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_MAP_SIZE"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_MAP"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_EXE_FILE"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_AUXV"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_ENV_END"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_ENV_START"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_ARG_END"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_ARG_START"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_BRK"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_START_BRK"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_START_STACK"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_END_DATA"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_START_DATA"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_END_CODE"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM_START_CODE"))
.subcommand(clap::SubCommand::with_name("PR_SET_MM"))
.subcommand(clap::SubCommand::with_name("PR_MCE_KILL_GET"))
.subcommand(clap::SubCommand::with_name("PR_MCE_KILL_DEFAULT"))
.subcommand(clap::SubCommand::with_name("PR_MCE_KILL_EARLY"))
.subcommand(clap::SubCommand::with_name("PR_MCE_KILL_LATE"))
.subcommand(clap::SubCommand::with_name("PR_MCE_KILL_SET"))
.subcommand(clap::SubCommand::with_name("PR_MCE_KILL_CLEAR"))
.subcommand(clap::SubCommand::with_name("PR_MCE_KILL"))
.subcommand(clap::SubCommand::with_name("PR_TASK_PERF_EVENTS_ENABLE"))
.subcommand(clap::SubCommand::with_name("PR_TASK_PERF_EVENTS_DISABLE"))
.subcommand(clap::SubCommand::with_name("PR_GET_TIMERSLACK"))
.subcommand(clap::SubCommand::with_name("PR_SET_TIMERSLACK"))
.subcommand(clap::SubCommand::with_name("PR_SET_SECUREBITS"))
.subcommand(clap::SubCommand::with_name("PR_GET_SECUREBITS"))
.subcommand(clap::SubCommand::with_name("PR_TSC_SIGSEGV"))
.subcommand(clap::SubCommand::with_name("PR_TSC_ENABLE"))
.subcommand(clap::SubCommand::with_name("PR_SET_TSC"))
.subcommand(clap::SubCommand::with_name("PR_GET_TSC"))
.subcommand(clap::SubCommand::with_name("PR_CAPBSET_DROP"))
.subcommand(clap::SubCommand::with_name("PR_CAPBSET_READ"))
.subcommand(clap::SubCommand::with_name("PR_SET_SECCOMP"))
.subcommand(clap::SubCommand::with_name("PR_GET_SECCOMP"))
.subcommand(clap::SubCommand::with_name("PR_ENDIAN_PPC_LITTLE"))
.subcommand(clap::SubCommand::with_name("PR_ENDIAN_LITTLE"))
.subcommand(clap::SubCommand::with_name("PR_ENDIAN_BIG"))
.subcommand(clap::SubCommand::with_name("PR_SET_ENDIAN"))
.subcommand(clap::SubCommand::with_name("PR_GET_ENDIAN"))
.subcommand(clap::SubCommand::with_name("PR_GET_NAME"))
.subcommand(clap::SubCommand::with_name("PR_SET_NAME"))
.subcommand(clap::SubCommand::with_name("PR_TIMING_TIMESTAMP"))
.subcommand(clap::SubCommand::with_name("PR_TIMING_STATISTICAL"))
.subcommand(clap::SubCommand::with_name("PR_SET_TIMING"))
.subcommand(clap::SubCommand::with_name("PR_GET_TIMING"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_PRECISE"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_ASYNC"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_NONRECOV"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_DISABLED"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_INV"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_RES"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_UND"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_OVF"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_DIV"))
.subcommand(clap::SubCommand::with_name("PR_FP_EXC_SW_ENABLE"))
.subcommand(clap::SubCommand::with_name("PR_SET_FPEXC"))
.subcommand(clap::SubCommand::with_name("PR_GET_FPEXC"))
.subcommand(clap::SubCommand::with_name("PR_FPEMU_SIGFPE"))
.subcommand(clap::SubCommand::with_name("PR_FPEMU_NOPRINT"))
.subcommand(clap::SubCommand::with_name("PR_SET_FPEMU"))
.subcommand(clap::SubCommand::with_name("PR_GET_FPEMU"))
.subcommand(clap::SubCommand::with_name("PR_SET_KEEPCAPS"))
.subcommand(clap::SubCommand::with_name("PR_GET_KEEPCAPS"))
.subcommand(clap::SubCommand::with_name("PR_UNALIGN_SIGBUS"))
.subcommand(clap::SubCommand::with_name("PR_UNALIGN_NOPRINT"))
.subcommand(clap::SubCommand::with_name("PR_SET_UNALIGN"))
.subcommand(clap::SubCommand::with_name("PR_GET_UNALIGN"))
.subcommand(clap::SubCommand::with_name("PR_SET_DUMPABLE"))
.subcommand(clap::SubCommand::with_name("PR_GET_DUMPABLE"))
.subcommand(clap::SubCommand::with_name("PR_GET_PDEATHSIG"))
.subcommand(clap::SubCommand::with_name("PR_SET_PDEATHSIG"))
.subcommand(clap::SubCommand::with_name("MREMAP_FIXED"))
.subcommand(clap::SubCommand::with_name("MREMAP_MAYMOVE"))
.subcommand(clap::SubCommand::with_name("LIO_NOWAIT"))
.subcommand(clap::SubCommand::with_name("LIO_WAIT"))
.subcommand(clap::SubCommand::with_name("LIO_NOP"))
.subcommand(clap::SubCommand::with_name("LIO_WRITE"))
.subcommand(clap::SubCommand::with_name("LIO_READ"))
.subcommand(clap::SubCommand::with_name("AIO_ALLDONE"))
.subcommand(clap::SubCommand::with_name("AIO_NOTCANCELED"))
.subcommand(clap::SubCommand::with_name("AIO_CANCELED"))
.subcommand(clap::SubCommand::with_name("SYNC_FILE_RANGE_WAIT_AFTER"))
.subcommand(clap::SubCommand::with_name("SYNC_FILE_RANGE_WRITE"))
.subcommand(clap::SubCommand::with_name("SYNC_FILE_RANGE_WAIT_BEFORE"))
.subcommand(clap::SubCommand::with_name("NI_DGRAM"))
.subcommand(clap::SubCommand::with_name("NI_NAMEREQD"))
.subcommand(clap::SubCommand::with_name("NI_NOFQDN"))
.subcommand(clap::SubCommand::with_name("NI_NUMERICSERV"))
.subcommand(clap::SubCommand::with_name("NI_NUMERICHOST"))
.subcommand(clap::SubCommand::with_name("EAI_OVERFLOW"))
.subcommand(clap::SubCommand::with_name("EAI_SYSTEM"))
.subcommand(clap::SubCommand::with_name("EAI_MEMORY"))
.subcommand(clap::SubCommand::with_name("EAI_SERVICE"))
.subcommand(clap::SubCommand::with_name("EAI_SOCKTYPE"))
.subcommand(clap::SubCommand::with_name("EAI_FAMILY"))
.subcommand(clap::SubCommand::with_name("EAI_NODATA"))
.subcommand(clap::SubCommand::with_name("EAI_FAIL"))
.subcommand(clap::SubCommand::with_name("EAI_AGAIN"))
.subcommand(clap::SubCommand::with_name("EAI_NONAME"))
.subcommand(clap::SubCommand::with_name("EAI_BADFLAGS"))
.subcommand(clap::SubCommand::with_name("AI_NUMERICSERV"))
.subcommand(clap::SubCommand::with_name("AI_ADDRCONFIG"))
.subcommand(clap::SubCommand::with_name("AI_ALL"))
.subcommand(clap::SubCommand::with_name("AI_V4MAPPED"))
.subcommand(clap::SubCommand::with_name("AI_NUMERICHOST"))
.subcommand(clap::SubCommand::with_name("AI_CANONNAME"))
.subcommand(clap::SubCommand::with_name("AI_PASSIVE"))
.subcommand(clap::SubCommand::with_name("RB_KEXEC"))
.subcommand(clap::SubCommand::with_name("RB_SW_SUSPEND"))
.subcommand(clap::SubCommand::with_name("RB_POWER_OFF"))
.subcommand(clap::SubCommand::with_name("RB_DISABLE_CAD"))
.subcommand(clap::SubCommand::with_name("RB_ENABLE_CAD"))
.subcommand(clap::SubCommand::with_name("RB_HALT_SYSTEM"))
.subcommand(clap::SubCommand::with_name("RB_AUTOBOOT"))
.subcommand(clap::SubCommand::with_name("LOG_NFACILITIES"))
.subcommand(clap::SubCommand::with_name("EFD_SEMAPHORE"))
.subcommand(clap::SubCommand::with_name("QFMT_VFS_V1"))
.subcommand(clap::SubCommand::with_name("QFMT_VFS_V0"))
.subcommand(clap::SubCommand::with_name("QFMT_VFS_OLD"))
.subcommand(clap::SubCommand::with_name("EPOLLONESHOT"))
.subcommand(clap::SubCommand::with_name("EPOLLEXCLUSIVE"))
.subcommand(clap::SubCommand::with_name("EPOLLRDHUP"))
.subcommand(clap::SubCommand::with_name("SHM_NORESERVE"))
.subcommand(clap::SubCommand::with_name("SHM_HUGETLB"))
.subcommand(clap::SubCommand::with_name("SHM_UNLOCK"))
.subcommand(clap::SubCommand::with_name("SHM_LOCK"))
.subcommand(clap::SubCommand::with_name("SHM_EXEC"))
.subcommand(clap::SubCommand::with_name("SHM_REMAP"))
.subcommand(clap::SubCommand::with_name("SHM_RND"))
.subcommand(clap::SubCommand::with_name("SHM_RDONLY"))
.subcommand(clap::SubCommand::with_name("SHM_W"))
.subcommand(clap::SubCommand::with_name("SHM_R"))
.subcommand(clap::SubCommand::with_name("MSG_COPY"))
.subcommand(clap::SubCommand::with_name("MSG_EXCEPT"))
.subcommand(clap::SubCommand::with_name("MSG_NOERROR"))
.subcommand(clap::SubCommand::with_name("MSG_INFO"))
.subcommand(clap::SubCommand::with_name("MSG_STAT"))
.subcommand(clap::SubCommand::with_name("IPC_INFO"))
.subcommand(clap::SubCommand::with_name("IPC_STAT"))
.subcommand(clap::SubCommand::with_name("IPC_SET"))
.subcommand(clap::SubCommand::with_name("IPC_RMID"))
.subcommand(clap::SubCommand::with_name("IPC_NOWAIT"))
.subcommand(clap::SubCommand::with_name("IPC_EXCL"))
.subcommand(clap::SubCommand::with_name("IPC_CREAT"))
.subcommand(clap::SubCommand::with_name("IPC_PRIVATE"))
.subcommand(clap::SubCommand::with_name("PF_XDP"))
.subcommand(clap::SubCommand::with_name("PF_VSOCK"))
.subcommand(clap::SubCommand::with_name("PF_NFC"))
.subcommand(clap::SubCommand::with_name("PF_MPLS"))
.subcommand(clap::SubCommand::with_name("PF_IB"))
.subcommand(clap::SubCommand::with_name("AF_XDP"))
.subcommand(clap::SubCommand::with_name("AF_VSOCK"))
.subcommand(clap::SubCommand::with_name("AF_NFC"))
.subcommand(clap::SubCommand::with_name("AF_MPLS"))
.subcommand(clap::SubCommand::with_name("AF_IB"))
.subcommand(clap::SubCommand::with_name("IP_UNICAST_IF"))
.subcommand(clap::SubCommand::with_name("IP_MULTICAST_ALL"))
.subcommand(clap::SubCommand::with_name("MCAST_MSFILTER"))
.subcommand(clap::SubCommand::with_name("MCAST_LEAVE_SOURCE_GROUP"))
.subcommand(clap::SubCommand::with_name("MCAST_JOIN_SOURCE_GROUP"))
.subcommand(clap::SubCommand::with_name("MCAST_LEAVE_GROUP"))
.subcommand(clap::SubCommand::with_name("MCAST_UNBLOCK_SOURCE"))
.subcommand(clap::SubCommand::with_name("MCAST_BLOCK_SOURCE"))
.subcommand(clap::SubCommand::with_name("MCAST_JOIN_GROUP"))
.subcommand(clap::SubCommand::with_name("IP_MSFILTER"))
.subcommand(clap::SubCommand::with_name("IPPROTO_MAX"))
.subcommand(clap::SubCommand::with_name("IPPROTO_RAW"))
.subcommand(clap::SubCommand::with_name("IPPROTO_MPLS"))
.subcommand(clap::SubCommand::with_name("IPPROTO_UDPLITE"))
.subcommand(clap::SubCommand::with_name("IPPROTO_MH"))
.subcommand(clap::SubCommand::with_name("IPPROTO_SCTP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_COMP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_PIM"))
.subcommand(clap::SubCommand::with_name("IPPROTO_ENCAP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_BEETPH"))
.subcommand(clap::SubCommand::with_name("IPPROTO_MTP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_DSTOPTS"))
.subcommand(clap::SubCommand::with_name("IPPROTO_NONE"))
.subcommand(clap::SubCommand::with_name("IPPROTO_AH"))
.subcommand(clap::SubCommand::with_name("IPPROTO_ESP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_GRE"))
.subcommand(clap::SubCommand::with_name("IPPROTO_RSVP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_FRAGMENT"))
.subcommand(clap::SubCommand::with_name("IPPROTO_ROUTING"))
.subcommand(clap::SubCommand::with_name("IPPROTO_DCCP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_TP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_IDP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_PUP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_EGP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_IPIP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_IGMP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_HOPOPTS"))
.subcommand(clap::SubCommand::with_name("SCHED_RESET_ON_FORK"))
.subcommand(clap::SubCommand::with_name("SCHED_IDLE"))
.subcommand(clap::SubCommand::with_name("SCHED_BATCH"))
.subcommand(clap::SubCommand::with_name("SCHED_RR"))
.subcommand(clap::SubCommand::with_name("SCHED_FIFO"))
.subcommand(clap::SubCommand::with_name("SCHED_OTHER"))
.subcommand(clap::SubCommand::with_name("RENAME_WHITEOUT"))
.subcommand(clap::SubCommand::with_name("RENAME_EXCHANGE"))
.subcommand(clap::SubCommand::with_name("RENAME_NOREPLACE"))
.subcommand(clap::SubCommand::with_name("__SIZEOF_PTHREAD_COND_T"))
.subcommand(clap::SubCommand::with_name("PTHREAD_PROCESS_SHARED"))
.subcommand(clap::SubCommand::with_name("PTHREAD_PROCESS_PRIVATE"))
.subcommand(clap::SubCommand::with_name("PTHREAD_MUTEX_DEFAULT"))
.subcommand(clap::SubCommand::with_name("PTHREAD_MUTEX_ERRORCHECK"))
.subcommand(clap::SubCommand::with_name("PTHREAD_MUTEX_RECURSIVE"))
.subcommand(clap::SubCommand::with_name("PTHREAD_MUTEX_NORMAL"))
.subcommand(clap::SubCommand::with_name("TCP_MD5SIG"))
.subcommand(clap::SubCommand::with_name("AT_EACCESS"))
.subcommand(clap::SubCommand::with_name("RTLD_NOW"))
.subcommand(clap::SubCommand::with_name("RTLD_NODELETE"))
.subcommand(clap::SubCommand::with_name("ST_NODIRATIME"))
.subcommand(clap::SubCommand::with_name("ST_NOATIME"))
.subcommand(clap::SubCommand::with_name("ST_IMMUTABLE"))
.subcommand(clap::SubCommand::with_name("ST_APPEND"))
.subcommand(clap::SubCommand::with_name("ST_WRITE"))
.subcommand(clap::SubCommand::with_name("ST_MANDLOCK"))
.subcommand(clap::SubCommand::with_name("ST_SYNCHRONOUS"))
.subcommand(clap::SubCommand::with_name("ST_NOEXEC"))
.subcommand(clap::SubCommand::with_name("ST_NODEV"))
.subcommand(clap::SubCommand::with_name("ST_NOSUID"))
.subcommand(clap::SubCommand::with_name("ST_RDONLY"))
.subcommand(clap::SubCommand::with_name("IFF_NOFILTER"))
.subcommand(clap::SubCommand::with_name("IFF_PERSIST"))
.subcommand(clap::SubCommand::with_name("IFF_DETACH_QUEUE"))
.subcommand(clap::SubCommand::with_name("IFF_ATTACH_QUEUE"))
.subcommand(clap::SubCommand::with_name("IFF_MULTI_QUEUE"))
.subcommand(clap::SubCommand::with_name("IFF_TUN_EXCL"))
.subcommand(clap::SubCommand::with_name("IFF_VNET_HDR"))
.subcommand(clap::SubCommand::with_name("IFF_ONE_QUEUE"))
.subcommand(clap::SubCommand::with_name("TUN_TYPE_MASK"))
.subcommand(clap::SubCommand::with_name("TUN_TAP_DEV"))
.subcommand(clap::SubCommand::with_name("TUN_TUN_DEV"))
.subcommand(clap::SubCommand::with_name("TUN_READQ_SIZE"))
.subcommand(clap::SubCommand::with_name("IFF_NO_PI"))
.subcommand(clap::SubCommand::with_name("IFF_TAP"))
.subcommand(clap::SubCommand::with_name("IFF_TUN"))
.subcommand(clap::SubCommand::with_name("IFLA_INFO_SLAVE_DATA"))
.subcommand(clap::SubCommand::with_name("IFLA_INFO_SLAVE_KIND"))
.subcommand(clap::SubCommand::with_name("IFLA_INFO_XSTATS"))
.subcommand(clap::SubCommand::with_name("IFLA_INFO_DATA"))
.subcommand(clap::SubCommand::with_name("IFLA_INFO_KIND"))
.subcommand(clap::SubCommand::with_name("IFLA_INFO_UNSPEC"))
.subcommand(clap::SubCommand::with_name("IFLA_PROTO_DOWN"))
.subcommand(clap::SubCommand::with_name("IFLA_PHYS_PORT_NAME"))
.subcommand(clap::SubCommand::with_name("IFLA_LINK_NETNSID"))
.subcommand(clap::SubCommand::with_name("IFLA_PHYS_SWITCH_ID"))
.subcommand(clap::SubCommand::with_name("IFLA_CARRIER_CHANGES"))
.subcommand(clap::SubCommand::with_name("IFLA_PHYS_PORT_ID"))
.subcommand(clap::SubCommand::with_name("IFLA_CARRIER"))
.subcommand(clap::SubCommand::with_name("IFLA_NUM_RX_QUEUES"))
.subcommand(clap::SubCommand::with_name("IFLA_NUM_TX_QUEUES"))
.subcommand(clap::SubCommand::with_name("IFLA_PROMISCUITY"))
.subcommand(clap::SubCommand::with_name("IFLA_EXT_MASK"))
.subcommand(clap::SubCommand::with_name("IFLA_NET_NS_FD"))
.subcommand(clap::SubCommand::with_name("IFLA_GROUP"))
.subcommand(clap::SubCommand::with_name("IFLA_AF_SPEC"))
.subcommand(clap::SubCommand::with_name("IFLA_PORT_SELF"))
.subcommand(clap::SubCommand::with_name("IFLA_VF_PORTS"))
.subcommand(clap::SubCommand::with_name("IFLA_STATS64"))
.subcommand(clap::SubCommand::with_name("IFLA_VFINFO_LIST"))
.subcommand(clap::SubCommand::with_name("IFLA_NUM_VF"))
.subcommand(clap::SubCommand::with_name("IFLA_IFALIAS"))
.subcommand(clap::SubCommand::with_name("IFLA_NET_NS_PID"))
.subcommand(clap::SubCommand::with_name("IFLA_LINKINFO"))
.subcommand(clap::SubCommand::with_name("IFLA_LINKMODE"))
.subcommand(clap::SubCommand::with_name("IFLA_OPERSTATE"))
.subcommand(clap::SubCommand::with_name("IFLA_WEIGHT"))
.subcommand(clap::SubCommand::with_name("IFLA_MAP"))
.subcommand(clap::SubCommand::with_name("IFLA_TXQLEN"))
.subcommand(clap::SubCommand::with_name("IFLA_PROTINFO"))
.subcommand(clap::SubCommand::with_name("IFLA_WIRELESS"))
.subcommand(clap::SubCommand::with_name("IFLA_MASTER"))
.subcommand(clap::SubCommand::with_name("IFLA_PRIORITY"))
.subcommand(clap::SubCommand::with_name("IFLA_COST"))
.subcommand(clap::SubCommand::with_name("IFLA_STATS"))
.subcommand(clap::SubCommand::with_name("IFLA_QDISC"))
.subcommand(clap::SubCommand::with_name("IFLA_LINK"))
.subcommand(clap::SubCommand::with_name("IFLA_MTU"))
.subcommand(clap::SubCommand::with_name("IFLA_IFNAME"))
.subcommand(clap::SubCommand::with_name("IFLA_BROADCAST"))
.subcommand(clap::SubCommand::with_name("IFLA_ADDRESS"))
.subcommand(clap::SubCommand::with_name("IFLA_UNSPEC"))
.subcommand(clap::SubCommand::with_name("IFA_F_PERMANENT"))
.subcommand(clap::SubCommand::with_name("IFA_F_TENTATIVE"))
.subcommand(clap::SubCommand::with_name("IFA_F_DEPRECATED"))
.subcommand(clap::SubCommand::with_name("IFA_F_HOMEADDRESS"))
.subcommand(clap::SubCommand::with_name("IFA_F_DADFAILED"))
.subcommand(clap::SubCommand::with_name("IFA_F_OPTIMISTIC"))
.subcommand(clap::SubCommand::with_name("IFA_F_NODAD"))
.subcommand(clap::SubCommand::with_name("IFA_F_TEMPORARY"))
.subcommand(clap::SubCommand::with_name("IFA_F_SECONDARY"))
.subcommand(clap::SubCommand::with_name("IFA_MULTICAST"))
.subcommand(clap::SubCommand::with_name("IFA_CACHEINFO"))
.subcommand(clap::SubCommand::with_name("IFA_ANYCAST"))
.subcommand(clap::SubCommand::with_name("IFA_BROADCAST"))
.subcommand(clap::SubCommand::with_name("IFA_LABEL"))
.subcommand(clap::SubCommand::with_name("IFA_LOCAL"))
.subcommand(clap::SubCommand::with_name("IFA_ADDRESS"))
.subcommand(clap::SubCommand::with_name("IFA_UNSPEC"))
.subcommand(clap::SubCommand::with_name("IFF_ECHO"))
.subcommand(clap::SubCommand::with_name("IFF_DORMANT"))
.subcommand(clap::SubCommand::with_name("IFF_LOWER_UP"))
.subcommand(clap::SubCommand::with_name("F_SEAL_FUTURE_WRITE"))
.subcommand(clap::SubCommand::with_name("F_ULOCK"))
.subcommand(clap::SubCommand::with_name("F_TLOCK"))
.subcommand(clap::SubCommand::with_name("F_TEST"))
.subcommand(clap::SubCommand::with_name("F_LOCK"))
.subcommand(clap::SubCommand::with_name("S_IREAD"))
.subcommand(clap::SubCommand::with_name("S_IWRITE"))
.subcommand(clap::SubCommand::with_name("S_IEXEC"))
.subcommand(clap::SubCommand::with_name("POSIX_MADV_WILLNEED"))
.subcommand(clap::SubCommand::with_name("POSIX_MADV_SEQUENTIAL"))
.subcommand(clap::SubCommand::with_name("POSIX_MADV_RANDOM"))
.subcommand(clap::SubCommand::with_name("POSIX_MADV_NORMAL"))
.subcommand(clap::SubCommand::with_name("GLOB_NOMATCH"))
.subcommand(clap::SubCommand::with_name("GLOB_ABORTED"))
.subcommand(clap::SubCommand::with_name("GLOB_NOSPACE"))
.subcommand(clap::SubCommand::with_name("GLOB_NOESCAPE"))
.subcommand(clap::SubCommand::with_name("GLOB_APPEND"))
.subcommand(clap::SubCommand::with_name("GLOB_NOCHECK"))
.subcommand(clap::SubCommand::with_name("GLOB_DOOFFS"))
.subcommand(clap::SubCommand::with_name("GLOB_NOSORT"))
.subcommand(clap::SubCommand::with_name("GLOB_MARK"))
.subcommand(clap::SubCommand::with_name("GLOB_ERR"))
.subcommand(clap::SubCommand::with_name("RLIM_SAVED_CUR"))
.subcommand(clap::SubCommand::with_name("RLIM_SAVED_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_ROBUST_PRIO_PROTECT"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_ROBUST_PRIO_INHERIT"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_STREAMS"))
.subcommand(clap::SubCommand::with_name("_SC_TRACE_USER_EVENT_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_TRACE_SYS_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_TRACE_NAME_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_TRACE_EVENT_NAME_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_SS_REPL_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_V7_LPBIG_OFFBIG"))
.subcommand(clap::SubCommand::with_name("_SC_V7_LP64_OFF64"))
.subcommand(clap::SubCommand::with_name("_SC_V7_ILP32_OFFBIG"))
.subcommand(clap::SubCommand::with_name("_SC_V7_ILP32_OFF32"))
.subcommand(clap::SubCommand::with_name("_SC_RAW_SOCKETS"))
.subcommand(clap::SubCommand::with_name("_SC_IPV6"))
.subcommand(clap::SubCommand::with_name("_SC_TRACE_LOG"))
.subcommand(clap::SubCommand::with_name("_SC_TRACE_INHERIT"))
.subcommand(clap::SubCommand::with_name("_SC_TRACE_EVENT_FILTER"))
.subcommand(clap::SubCommand::with_name("_SC_TRACE"))
.subcommand(clap::SubCommand::with_name("_SC_HOST_NAME_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_V6_LPBIG_OFFBIG"))
.subcommand(clap::SubCommand::with_name("_SC_V6_LP64_OFF64"))
.subcommand(clap::SubCommand::with_name("_SC_V6_ILP32_OFFBIG"))
.subcommand(clap::SubCommand::with_name("_SC_V6_ILP32_OFF32"))
.subcommand(clap::SubCommand::with_name("_SC_2_PBS_CHECKPOINT"))
.subcommand(clap::SubCommand::with_name("_SC_STREAMS"))
.subcommand(clap::SubCommand::with_name("_SC_SYMLOOP_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_2_PBS_TRACK"))
.subcommand(clap::SubCommand::with_name("_SC_2_PBS_MESSAGE"))
.subcommand(clap::SubCommand::with_name("_SC_2_PBS_LOCATE"))
.subcommand(clap::SubCommand::with_name("_SC_2_PBS_ACCOUNTING"))
.subcommand(clap::SubCommand::with_name("_SC_2_PBS"))
.subcommand(clap::SubCommand::with_name("_SC_TYPED_MEMORY_OBJECTS"))
.subcommand(clap::SubCommand::with_name("_SC_TIMEOUTS"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_SPORADIC_SERVER"))
.subcommand(clap::SubCommand::with_name("_SC_SPORADIC_SERVER"))
.subcommand(clap::SubCommand::with_name("_SC_SPAWN"))
.subcommand(clap::SubCommand::with_name("_SC_SHELL"))
.subcommand(clap::SubCommand::with_name("_SC_REGEXP"))
.subcommand(clap::SubCommand::with_name("_SC_SPIN_LOCKS"))
.subcommand(clap::SubCommand::with_name("_SC_READER_WRITER_LOCKS"))
.subcommand(clap::SubCommand::with_name("_SC_MONOTONIC_CLOCK"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_CPUTIME"))
.subcommand(clap::SubCommand::with_name("_SC_CPUTIME"))
.subcommand(clap::SubCommand::with_name("_SC_CLOCK_SELECTION"))
.subcommand(clap::SubCommand::with_name("_SC_BARRIERS"))
.subcommand(clap::SubCommand::with_name("_SC_ADVISORY_INFO"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_REALTIME_THREADS"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_REALTIME"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_LEGACY"))
.subcommand(clap::SubCommand::with_name("_SC_XBS5_LPBIG_OFFBIG"))
.subcommand(clap::SubCommand::with_name("_SC_XBS5_LP64_OFF64"))
.subcommand(clap::SubCommand::with_name("_SC_XBS5_ILP32_OFFBIG"))
.subcommand(clap::SubCommand::with_name("_SC_XBS5_ILP32_OFF32"))
.subcommand(clap::SubCommand::with_name("_SC_NZERO"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_XPG4"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_XPG3"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_XPG2"))
.subcommand(clap::SubCommand::with_name("_SC_2_UPE"))
.subcommand(clap::SubCommand::with_name("_SC_2_CHAR_TERM"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_SHM"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_ENH_I18N"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_CRYPT"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_UNIX"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_XCU_VERSION"))
.subcommand(clap::SubCommand::with_name("_SC_XOPEN_VERSION"))
.subcommand(clap::SubCommand::with_name("_SC_PASS_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_ATEXIT_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_AVPHYS_PAGES"))
.subcommand(clap::SubCommand::with_name("_SC_PHYS_PAGES"))
.subcommand(clap::SubCommand::with_name("_SC_NPROCESSORS_ONLN"))
.subcommand(clap::SubCommand::with_name("_SC_NPROCESSORS_CONF"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_PROCESS_SHARED"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_PRIO_PROTECT"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_PRIO_INHERIT"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_PRIORITY_SCHEDULING"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_ATTR_STACKSIZE"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_ATTR_STACKADDR"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_THREADS_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_STACK_MIN"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_KEYS_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_DESTRUCTOR_ITERATIONS"))
.subcommand(clap::SubCommand::with_name("_SC_TTY_NAME_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_LOGIN_NAME_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_GETPW_R_SIZE_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_GETGR_R_SIZE_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_THREAD_SAFE_FUNCTIONS"))
.subcommand(clap::SubCommand::with_name("_SC_THREADS"))
.subcommand(clap::SubCommand::with_name("_SC_IOV_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_UIO_MAXIOV"))
.subcommand(clap::SubCommand::with_name("_SC_2_LOCALEDEF"))
.subcommand(clap::SubCommand::with_name("_SC_2_SW_DEV"))
.subcommand(clap::SubCommand::with_name("_SC_2_FORT_RUN"))
.subcommand(clap::SubCommand::with_name("_SC_2_FORT_DEV"))
.subcommand(clap::SubCommand::with_name("_SC_2_C_DEV"))
.subcommand(clap::SubCommand::with_name("_SC_2_C_BIND"))
.subcommand(clap::SubCommand::with_name("_SC_2_VERSION"))
.subcommand(clap::SubCommand::with_name("_SC_RE_DUP_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_LINE_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_EXPR_NEST_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_COLL_WEIGHTS_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_BC_STRING_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_BC_SCALE_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_BC_DIM_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_BC_BASE_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_TIMER_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_SIGQUEUE_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_SEM_VALUE_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_SEM_NSEMS_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_RTSIG_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_PAGE_SIZE"))
.subcommand(clap::SubCommand::with_name("_SC_PAGESIZE"))
.subcommand(clap::SubCommand::with_name("_SC_VERSION"))
.subcommand(clap::SubCommand::with_name("_SC_MQ_PRIO_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_MQ_OPEN_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_DELAYTIMER_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_AIO_PRIO_DELTA_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_AIO_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_AIO_LISTIO_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_SHARED_MEMORY_OBJECTS"))
.subcommand(clap::SubCommand::with_name("_SC_SEMAPHORES"))
.subcommand(clap::SubCommand::with_name("_SC_MESSAGE_PASSING"))
.subcommand(clap::SubCommand::with_name("_SC_MEMORY_PROTECTION"))
.subcommand(clap::SubCommand::with_name("_SC_MEMLOCK_RANGE"))
.subcommand(clap::SubCommand::with_name("_SC_MEMLOCK"))
.subcommand(clap::SubCommand::with_name("_SC_MAPPED_FILES"))
.subcommand(clap::SubCommand::with_name("_SC_FSYNC"))
.subcommand(clap::SubCommand::with_name("_SC_SYNCHRONIZED_IO"))
.subcommand(clap::SubCommand::with_name("_SC_PRIORITIZED_IO"))
.subcommand(clap::SubCommand::with_name("_SC_ASYNCHRONOUS_IO"))
.subcommand(clap::SubCommand::with_name("_SC_TIMERS"))
.subcommand(clap::SubCommand::with_name("_SC_PRIORITY_SCHEDULING"))
.subcommand(clap::SubCommand::with_name("_SC_REALTIME_SIGNALS"))
.subcommand(clap::SubCommand::with_name("_SC_SAVED_IDS"))
.subcommand(clap::SubCommand::with_name("_SC_JOB_CONTROL"))
.subcommand(clap::SubCommand::with_name("_SC_TZNAME_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_STREAM_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_OPEN_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_NGROUPS_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_CLK_TCK"))
.subcommand(clap::SubCommand::with_name("_SC_CHILD_MAX"))
.subcommand(clap::SubCommand::with_name("_SC_ARG_MAX"))
.subcommand(clap::SubCommand::with_name("MS_NOUSER"))
.subcommand(clap::SubCommand::with_name("_PC_2_SYMLINKS"))
.subcommand(clap::SubCommand::with_name("_PC_SYMLINK_MAX"))
.subcommand(clap::SubCommand::with_name("_PC_ALLOC_SIZE_MIN"))
.subcommand(clap::SubCommand::with_name("_PC_REC_XFER_ALIGN"))
.subcommand(clap::SubCommand::with_name("_PC_REC_MIN_XFER_SIZE"))
.subcommand(clap::SubCommand::with_name("_PC_REC_MAX_XFER_SIZE"))
.subcommand(clap::SubCommand::with_name("_PC_REC_INCR_XFER_SIZE"))
.subcommand(clap::SubCommand::with_name("_PC_FILESIZEBITS"))
.subcommand(clap::SubCommand::with_name("_PC_SOCK_MAXBUF"))
.subcommand(clap::SubCommand::with_name("_PC_PRIO_IO"))
.subcommand(clap::SubCommand::with_name("_PC_ASYNC_IO"))
.subcommand(clap::SubCommand::with_name("_PC_SYNC_IO"))
.subcommand(clap::SubCommand::with_name("_PC_VDISABLE"))
.subcommand(clap::SubCommand::with_name("_PC_NO_TRUNC"))
.subcommand(clap::SubCommand::with_name("_PC_CHOWN_RESTRICTED"))
.subcommand(clap::SubCommand::with_name("_PC_PIPE_BUF"))
.subcommand(clap::SubCommand::with_name("_PC_PATH_MAX"))
.subcommand(clap::SubCommand::with_name("_PC_NAME_MAX"))
.subcommand(clap::SubCommand::with_name("_PC_MAX_INPUT"))
.subcommand(clap::SubCommand::with_name("_PC_MAX_CANON"))
.subcommand(clap::SubCommand::with_name("_PC_LINK_MAX"))
.subcommand(clap::SubCommand::with_name("L_tmpnam"))
.subcommand(clap::SubCommand::with_name("FILENAME_MAX"))
.subcommand(clap::SubCommand::with_name("NOSTR"))
.subcommand(clap::SubCommand::with_name("YESSTR"))
.subcommand(clap::SubCommand::with_name("NOEXPR"))
.subcommand(clap::SubCommand::with_name("YESEXPR"))
.subcommand(clap::SubCommand::with_name("THOUSEP"))
.subcommand(clap::SubCommand::with_name("RADIXCHAR"))
.subcommand(clap::SubCommand::with_name("RUSAGE_CHILDREN"))
.subcommand(clap::SubCommand::with_name("RUSAGE_THREAD"))
.subcommand(clap::SubCommand::with_name("CRNCYSTR"))
.subcommand(clap::SubCommand::with_name("CODESET"))
.subcommand(clap::SubCommand::with_name("ERA_T_FMT"))
.subcommand(clap::SubCommand::with_name("ERA_D_T_FMT"))
.subcommand(clap::SubCommand::with_name("ALT_DIGITS"))
.subcommand(clap::SubCommand::with_name("ERA_D_FMT"))
.subcommand(clap::SubCommand::with_name("ERA"))
.subcommand(clap::SubCommand::with_name("T_FMT_AMPM"))
.subcommand(clap::SubCommand::with_name("T_FMT"))
.subcommand(clap::SubCommand::with_name("D_FMT"))
.subcommand(clap::SubCommand::with_name("D_T_FMT"))
.subcommand(clap::SubCommand::with_name("PM_STR"))
.subcommand(clap::SubCommand::with_name("AM_STR"))
.subcommand(clap::SubCommand::with_name("MON_12"))
.subcommand(clap::SubCommand::with_name("MON_11"))
.subcommand(clap::SubCommand::with_name("MON_10"))
.subcommand(clap::SubCommand::with_name("MON_9"))
.subcommand(clap::SubCommand::with_name("MON_8"))
.subcommand(clap::SubCommand::with_name("MON_7"))
.subcommand(clap::SubCommand::with_name("MON_6"))
.subcommand(clap::SubCommand::with_name("MON_5"))
.subcommand(clap::SubCommand::with_name("MON_4"))
.subcommand(clap::SubCommand::with_name("MON_3"))
.subcommand(clap::SubCommand::with_name("MON_2"))
.subcommand(clap::SubCommand::with_name("MON_1"))
.subcommand(clap::SubCommand::with_name("ABMON_12"))
.subcommand(clap::SubCommand::with_name("ABMON_11"))
.subcommand(clap::SubCommand::with_name("ABMON_10"))
.subcommand(clap::SubCommand::with_name("ABMON_9"))
.subcommand(clap::SubCommand::with_name("ABMON_8"))
.subcommand(clap::SubCommand::with_name("ABMON_7"))
.subcommand(clap::SubCommand::with_name("ABMON_6"))
.subcommand(clap::SubCommand::with_name("ABMON_5"))
.subcommand(clap::SubCommand::with_name("ABMON_4"))
.subcommand(clap::SubCommand::with_name("ABMON_3"))
.subcommand(clap::SubCommand::with_name("ABMON_2"))
.subcommand(clap::SubCommand::with_name("ABMON_1"))
.subcommand(clap::SubCommand::with_name("DAY_7"))
.subcommand(clap::SubCommand::with_name("DAY_6"))
.subcommand(clap::SubCommand::with_name("DAY_5"))
.subcommand(clap::SubCommand::with_name("DAY_4"))
.subcommand(clap::SubCommand::with_name("DAY_3"))
.subcommand(clap::SubCommand::with_name("DAY_2"))
.subcommand(clap::SubCommand::with_name("DAY_1"))
.subcommand(clap::SubCommand::with_name("ABDAY_7"))
.subcommand(clap::SubCommand::with_name("ABDAY_6"))
.subcommand(clap::SubCommand::with_name("ABDAY_5"))
.subcommand(clap::SubCommand::with_name("ABDAY_4"))
.subcommand(clap::SubCommand::with_name("ABDAY_3"))
.subcommand(clap::SubCommand::with_name("ABDAY_2"))
.subcommand(clap::SubCommand::with_name("ABDAY_1"))
.subcommand(clap::SubCommand::with_name("ARPHRD_NONE"))
.subcommand(clap::SubCommand::with_name("ARPHRD_VOID"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IEEE802154"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IEEE80211_RADIOTAP"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IEEE80211_PRISM"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IEEE80211"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IEEE802_TR"))
.subcommand(clap::SubCommand::with_name("ARPHRD_FCFABRIC"))
.subcommand(clap::SubCommand::with_name("ARPHRD_FCPL"))
.subcommand(clap::SubCommand::with_name("ARPHRD_FCAL"))
.subcommand(clap::SubCommand::with_name("ARPHRD_FCPP"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IRDA"))
.subcommand(clap::SubCommand::with_name("ARPHRD_ECONET"))
.subcommand(clap::SubCommand::with_name("ARPHRD_ASH"))
.subcommand(clap::SubCommand::with_name("ARPHRD_HIPPI"))
.subcommand(clap::SubCommand::with_name("ARPHRD_PIMREG"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IPGRE"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IPDDP"))
.subcommand(clap::SubCommand::with_name("ARPHRD_SIT"))
.subcommand(clap::SubCommand::with_name("ARPHRD_BIF"))
.subcommand(clap::SubCommand::with_name("ARPHRD_FDDI"))
.subcommand(clap::SubCommand::with_name("ARPHRD_LOCALTLK"))
.subcommand(clap::SubCommand::with_name("ARPHRD_LOOPBACK"))
.subcommand(clap::SubCommand::with_name("ARPHRD_SKIP"))
.subcommand(clap::SubCommand::with_name("ARPHRD_FRAD"))
.subcommand(clap::SubCommand::with_name("ARPHRD_TUNNEL6"))
.subcommand(clap::SubCommand::with_name("ARPHRD_TUNNEL"))
.subcommand(clap::SubCommand::with_name("ARPHRD_RAWHDLC"))
.subcommand(clap::SubCommand::with_name("ARPHRD_DDCMP"))
.subcommand(clap::SubCommand::with_name("ARPHRD_LAPB"))
.subcommand(clap::SubCommand::with_name("ARPHRD_HDLC"))
.subcommand(clap::SubCommand::with_name("ARPHRD_CISCO"))
.subcommand(clap::SubCommand::with_name("ARPHRD_PPP"))
.subcommand(clap::SubCommand::with_name("ARPHRD_HWX25"))
.subcommand(clap::SubCommand::with_name("ARPHRD_X25"))
.subcommand(clap::SubCommand::with_name("ARPHRD_ROSE"))
.subcommand(clap::SubCommand::with_name("ARPHRD_ADAPT"))
.subcommand(clap::SubCommand::with_name("ARPHRD_RSRVD"))
.subcommand(clap::SubCommand::with_name("ARPHRD_CSLIP6"))
.subcommand(clap::SubCommand::with_name("ARPHRD_SLIP6"))
.subcommand(clap::SubCommand::with_name("ARPHRD_CSLIP"))
.subcommand(clap::SubCommand::with_name("ARPHRD_SLIP"))
.subcommand(clap::SubCommand::with_name("ARPHRD_INFINIBAND"))
.subcommand(clap::SubCommand::with_name("ARPHRD_EUI64"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IEEE1394"))
.subcommand(clap::SubCommand::with_name("ARPHRD_METRICOM"))
.subcommand(clap::SubCommand::with_name("ARPHRD_ATM"))
.subcommand(clap::SubCommand::with_name("ARPHRD_DLCI"))
.subcommand(clap::SubCommand::with_name("ARPHRD_APPLETLK"))
.subcommand(clap::SubCommand::with_name("ARPHRD_ARCNET"))
.subcommand(clap::SubCommand::with_name("ARPHRD_IEEE802"))
.subcommand(clap::SubCommand::with_name("ARPHRD_CHAOS"))
.subcommand(clap::SubCommand::with_name("ARPHRD_PRONET"))
.subcommand(clap::SubCommand::with_name("ARPHRD_AX25"))
.subcommand(clap::SubCommand::with_name("ARPHRD_EETHER"))
.subcommand(clap::SubCommand::with_name("ARPHRD_ETHER"))
.subcommand(clap::SubCommand::with_name("ARPHRD_NETROM"))
.subcommand(clap::SubCommand::with_name("ATF_DONTPUB"))
.subcommand(clap::SubCommand::with_name("ATF_NETMASK"))
.subcommand(clap::SubCommand::with_name("ARPOP_NAK"))
.subcommand(clap::SubCommand::with_name("ARPOP_InREPLY"))
.subcommand(clap::SubCommand::with_name("ARPOP_InREQUEST"))
.subcommand(clap::SubCommand::with_name("ARPOP_RREPLY"))
.subcommand(clap::SubCommand::with_name("ARPOP_RREQUEST"))
.subcommand(clap::SubCommand::with_name("IPOPT_TS_PRESPEC"))
.subcommand(clap::SubCommand::with_name("IPOPT_TS_TSANDADDR"))
.subcommand(clap::SubCommand::with_name("IPOPT_TS_TSONLY"))
.subcommand(clap::SubCommand::with_name("IPOPT_TS"))
.subcommand(clap::SubCommand::with_name("IPOPT_EOL"))
.subcommand(clap::SubCommand::with_name("IPOPT_NOP"))
.subcommand(clap::SubCommand::with_name("MAX_IPOPTLEN"))
.subcommand(clap::SubCommand::with_name("IPOPT_MINOFF"))
.subcommand(clap::SubCommand::with_name("IPOPT_OFFSET"))
.subcommand(clap::SubCommand::with_name("IPOPT_OLEN"))
.subcommand(clap::SubCommand::with_name("IPOPT_OPTVAL"))
.subcommand(clap::SubCommand::with_name("IPDEFTTL"))
.subcommand(clap::SubCommand::with_name("MAXTTL"))
.subcommand(clap::SubCommand::with_name("IPVERSION"))
.subcommand(clap::SubCommand::with_name("IPOPT_RA"))
.subcommand(clap::SubCommand::with_name("IPOPT_SSRR"))
.subcommand(clap::SubCommand::with_name("IPOPT_SID"))
.subcommand(clap::SubCommand::with_name("IPOPT_RR"))
.subcommand(clap::SubCommand::with_name("IPOPT_TIMESTAMP"))
.subcommand(clap::SubCommand::with_name("IPOPT_LSRR"))
.subcommand(clap::SubCommand::with_name("IPOPT_SEC"))
.subcommand(clap::SubCommand::with_name("IPOPT_NOOP"))
.subcommand(clap::SubCommand::with_name("IPOPT_END"))
.subcommand(clap::SubCommand::with_name("IPOPT_RESERVED2"))
.subcommand(clap::SubCommand::with_name("IPOPT_MEASUREMENT"))
.subcommand(clap::SubCommand::with_name("IPOPT_RESERVED1"))
.subcommand(clap::SubCommand::with_name("IPOPT_CONTROL"))
.subcommand(clap::SubCommand::with_name("IPOPT_NUMBER_MASK"))
.subcommand(clap::SubCommand::with_name("IPOPT_CLASS_MASK"))
.subcommand(clap::SubCommand::with_name("IPOPT_COPY"))
.subcommand(clap::SubCommand::with_name("IPTOS_ECN_CE"))
.subcommand(clap::SubCommand::with_name("IPTOS_ECN_ECT0"))
.subcommand(clap::SubCommand::with_name("IPTOS_ECN_ECT1"))
.subcommand(clap::SubCommand::with_name("IPTOS_ECN_MASK"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_ROUTINE"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_PRIORITY"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_IMMEDIATE"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_FLASH"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_FLASHOVERRIDE"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_CRITIC_ECP"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_INTERNETCONTROL"))
.subcommand(clap::SubCommand::with_name("IPTOS_PREC_NETCONTROL"))
.subcommand(clap::SubCommand::with_name("IPTOS_MINCOST"))
.subcommand(clap::SubCommand::with_name("IPTOS_RELIABILITY"))
.subcommand(clap::SubCommand::with_name("IPTOS_THROUGHPUT"))
.subcommand(clap::SubCommand::with_name("IPTOS_LOWDELAY"))
.subcommand(clap::SubCommand::with_name("POLLRDBAND"))
.subcommand(clap::SubCommand::with_name("POLLRDNORM"))
.subcommand(clap::SubCommand::with_name("POLLNVAL"))
.subcommand(clap::SubCommand::with_name("POLLHUP"))
.subcommand(clap::SubCommand::with_name("POLLERR"))
.subcommand(clap::SubCommand::with_name("POLLOUT"))
.subcommand(clap::SubCommand::with_name("POLLPRI"))
.subcommand(clap::SubCommand::with_name("POLLIN"))
.subcommand(clap::SubCommand::with_name("UTIME_NOW"))
.subcommand(clap::SubCommand::with_name("UTIME_OMIT"))
.subcommand(clap::SubCommand::with_name("P_PGID"))
.subcommand(clap::SubCommand::with_name("P_PID"))
.subcommand(clap::SubCommand::with_name("P_ALL"))
.subcommand(clap::SubCommand::with_name("SIGEV_THREAD"))
.subcommand(clap::SubCommand::with_name("SIGEV_NONE"))
.subcommand(clap::SubCommand::with_name("SIGEV_SIGNAL"))
.subcommand(clap::SubCommand::with_name("SI_LOAD_SHIFT"))
.subcommand(clap::SubCommand::with_name("PIPE_BUF"))
.subcommand(clap::SubCommand::with_name("LOG_PERROR"))
.subcommand(clap::SubCommand::with_name("LOG_FTP"))
.subcommand(clap::SubCommand::with_name("LOG_AUTHPRIV"))
.subcommand(clap::SubCommand::with_name("LOG_CRON"))
.subcommand(clap::SubCommand::with_name("AT_EMPTY_PATH"))
.subcommand(clap::SubCommand::with_name("AT_NO_AUTOMOUNT"))
.subcommand(clap::SubCommand::with_name("AT_SYMLINK_FOLLOW"))
.subcommand(clap::SubCommand::with_name("AT_REMOVEDIR"))
.subcommand(clap::SubCommand::with_name("AT_SYMLINK_NOFOLLOW"))
.subcommand(clap::SubCommand::with_name("AT_FDCWD"))
.subcommand(clap::SubCommand::with_name("POSIX_FADV_WILLNEED"))
.subcommand(clap::SubCommand::with_name("POSIX_FADV_SEQUENTIAL"))
.subcommand(clap::SubCommand::with_name("POSIX_FADV_RANDOM"))
.subcommand(clap::SubCommand::with_name("POSIX_FADV_NORMAL"))
.subcommand(clap::SubCommand::with_name("RTLD_LAZY"))
.subcommand(clap::SubCommand::with_name("RTLD_LOCAL"))
.subcommand(clap::SubCommand::with_name("SPLICE_F_GIFT"))
.subcommand(clap::SubCommand::with_name("SPLICE_F_MORE"))
.subcommand(clap::SubCommand::with_name("SPLICE_F_NONBLOCK"))
.subcommand(clap::SubCommand::with_name("SPLICE_F_MOVE"))
.subcommand(clap::SubCommand::with_name("__WCLONE"))
.subcommand(clap::SubCommand::with_name("__WALL"))
.subcommand(clap::SubCommand::with_name("__WNOTHREAD"))
.subcommand(clap::SubCommand::with_name("PTRACE_EVENT_SECCOMP"))
.subcommand(clap::SubCommand::with_name("PTRACE_EVENT_EXIT"))
.subcommand(clap::SubCommand::with_name("PTRACE_EVENT_VFORK_DONE"))
.subcommand(clap::SubCommand::with_name("PTRACE_EVENT_EXEC"))
.subcommand(clap::SubCommand::with_name("PTRACE_EVENT_CLONE"))
.subcommand(clap::SubCommand::with_name("PTRACE_EVENT_VFORK"))
.subcommand(clap::SubCommand::with_name("PTRACE_EVENT_FORK"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_MASK"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_SUSPEND_SECCOMP"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_EXITKILL"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_TRACESECCOMP"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_TRACEEXIT"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_TRACEVFORKDONE"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_TRACEEXEC"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_TRACECLONE"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_TRACEVFORK"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_TRACEFORK"))
.subcommand(clap::SubCommand::with_name("PTRACE_O_TRACESYSGOOD"))
.subcommand(clap::SubCommand::with_name("WNOWAIT"))
.subcommand(clap::SubCommand::with_name("WCONTINUED"))
.subcommand(clap::SubCommand::with_name("WEXITED"))
.subcommand(clap::SubCommand::with_name("WSTOPPED"))
.subcommand(clap::SubCommand::with_name("WUNTRACED"))
.subcommand(clap::SubCommand::with_name("WNOHANG"))
.subcommand(clap::SubCommand::with_name("CLONE_NEWCGROUP"))
.subcommand(clap::SubCommand::with_name("CLONE_IO"))
.subcommand(clap::SubCommand::with_name("CLONE_NEWNET"))
.subcommand(clap::SubCommand::with_name("CLONE_NEWPID"))
.subcommand(clap::SubCommand::with_name("CLONE_NEWUSER"))
.subcommand(clap::SubCommand::with_name("CLONE_NEWIPC"))
.subcommand(clap::SubCommand::with_name("CLONE_NEWUTS"))
.subcommand(clap::SubCommand::with_name("CLONE_CHILD_SETTID"))
.subcommand(clap::SubCommand::with_name("CLONE_UNTRACED"))
.subcommand(clap::SubCommand::with_name("CLONE_DETACHED"))
.subcommand(clap::SubCommand::with_name("CLONE_CHILD_CLEARTID"))
.subcommand(clap::SubCommand::with_name("CLONE_PARENT_SETTID"))
.subcommand(clap::SubCommand::with_name("CLONE_SETTLS"))
.subcommand(clap::SubCommand::with_name("CLONE_SYSVSEM"))
.subcommand(clap::SubCommand::with_name("CLONE_NEWNS"))
.subcommand(clap::SubCommand::with_name("CLONE_THREAD"))
.subcommand(clap::SubCommand::with_name("CLONE_PARENT"))
.subcommand(clap::SubCommand::with_name("CLONE_VFORK"))
.subcommand(clap::SubCommand::with_name("CLONE_PTRACE"))
.subcommand(clap::SubCommand::with_name("CLONE_SIGHAND"))
.subcommand(clap::SubCommand::with_name("CLONE_FILES"))
.subcommand(clap::SubCommand::with_name("CLONE_FS"))
.subcommand(clap::SubCommand::with_name("CLONE_VM"))
.subcommand(clap::SubCommand::with_name("OFDEL"))
.subcommand(clap::SubCommand::with_name("OFILL"))
.subcommand(clap::SubCommand::with_name("ONLRET"))
.subcommand(clap::SubCommand::with_name("ONOCR"))
.subcommand(clap::SubCommand::with_name("OCRNL"))
.subcommand(clap::SubCommand::with_name("ECHO"))
.subcommand(clap::SubCommand::with_name("CRTSCTS"))
.subcommand(clap::SubCommand::with_name("CS5"))
.subcommand(clap::SubCommand::with_name("OPOST"))
.subcommand(clap::SubCommand::with_name("IMAXBEL"))
.subcommand(clap::SubCommand::with_name("IXANY"))
.subcommand(clap::SubCommand::with_name("ICRNL"))
.subcommand(clap::SubCommand::with_name("IGNCR"))
.subcommand(clap::SubCommand::with_name("INLCR"))
.subcommand(clap::SubCommand::with_name("ISTRIP"))
.subcommand(clap::SubCommand::with_name("INPCK"))
.subcommand(clap::SubCommand::with_name("PARMRK"))
.subcommand(clap::SubCommand::with_name("IGNPAR"))
.subcommand(clap::SubCommand::with_name("BRKINT"))
.subcommand(clap::SubCommand::with_name("IGNBRK"))
.subcommand(clap::SubCommand::with_name("VLNEXT"))
.subcommand(clap::SubCommand::with_name("VQUIT"))
.subcommand(clap::SubCommand::with_name("VINTR"))
.subcommand(clap::SubCommand::with_name("VKILL"))
.subcommand(clap::SubCommand::with_name("VERASE"))
.subcommand(clap::SubCommand::with_name("VT0"))
.subcommand(clap::SubCommand::with_name("BS0"))
.subcommand(clap::SubCommand::with_name("FF0"))
.subcommand(clap::SubCommand::with_name("CR0"))
.subcommand(clap::SubCommand::with_name("TAB0"))
.subcommand(clap::SubCommand::with_name("NL1"))
.subcommand(clap::SubCommand::with_name("NL0"))
.subcommand(clap::SubCommand::with_name("TCIOFLUSH"))
.subcommand(clap::SubCommand::with_name("TCOFLUSH"))
.subcommand(clap::SubCommand::with_name("TCIFLUSH"))
.subcommand(clap::SubCommand::with_name("TCOON"))
.subcommand(clap::SubCommand::with_name("TCOOFF"))
.subcommand(clap::SubCommand::with_name("TCION"))
.subcommand(clap::SubCommand::with_name("TCIOFF"))
.subcommand(clap::SubCommand::with_name("Q_SETQUOTA"))
.subcommand(clap::SubCommand::with_name("Q_GETQUOTA"))
.subcommand(clap::SubCommand::with_name("Q_QUOTAOFF"))
.subcommand(clap::SubCommand::with_name("Q_QUOTAON"))
.subcommand(clap::SubCommand::with_name("Q_SYNC"))
.subcommand(clap::SubCommand::with_name("MNT_FORCE"))
.subcommand(clap::SubCommand::with_name("QIF_ALL"))
.subcommand(clap::SubCommand::with_name("QIF_TIMES"))
.subcommand(clap::SubCommand::with_name("QIF_USAGE"))
.subcommand(clap::SubCommand::with_name("QIF_LIMITS"))
.subcommand(clap::SubCommand::with_name("QIF_ITIME"))
.subcommand(clap::SubCommand::with_name("QIF_BTIME"))
.subcommand(clap::SubCommand::with_name("QIF_INODES"))
.subcommand(clap::SubCommand::with_name("QIF_ILIMITS"))
.subcommand(clap::SubCommand::with_name("QIF_SPACE"))
.subcommand(clap::SubCommand::with_name("QIF_BLIMITS"))
.subcommand(clap::SubCommand::with_name("Q_SETINFO"))
.subcommand(clap::SubCommand::with_name("Q_GETINFO"))
.subcommand(clap::SubCommand::with_name("Q_GETFMT"))
.subcommand(clap::SubCommand::with_name("MNT_EXPIRE"))
.subcommand(clap::SubCommand::with_name("MNT_DETACH"))
.subcommand(clap::SubCommand::with_name("EPOLL_CTL_DEL"))
.subcommand(clap::SubCommand::with_name("EPOLL_CTL_MOD"))
.subcommand(clap::SubCommand::with_name("EPOLL_CTL_ADD"))
.subcommand(clap::SubCommand::with_name("EPOLLET"))
.subcommand(clap::SubCommand::with_name("EPOLLHUP"))
.subcommand(clap::SubCommand::with_name("EPOLLERR"))
.subcommand(clap::SubCommand::with_name("EPOLLMSG"))
.subcommand(clap::SubCommand::with_name("EPOLLWRBAND"))
.subcommand(clap::SubCommand::with_name("EPOLLWRNORM"))
.subcommand(clap::SubCommand::with_name("EPOLLRDBAND"))
.subcommand(clap::SubCommand::with_name("EPOLLRDNORM"))
.subcommand(clap::SubCommand::with_name("EPOLLOUT"))
.subcommand(clap::SubCommand::with_name("EPOLLPRI"))
.subcommand(clap::SubCommand::with_name("EPOLLIN"))
.subcommand(clap::SubCommand::with_name("FD_SETSIZE"))
.subcommand(clap::SubCommand::with_name("PATH_MAX"))
.subcommand(clap::SubCommand::with_name("SS_DISABLE"))
.subcommand(clap::SubCommand::with_name("SS_ONSTACK"))
.subcommand(clap::SubCommand::with_name("LOCK_UN"))
.subcommand(clap::SubCommand::with_name("LOCK_NB"))
.subcommand(clap::SubCommand::with_name("LOCK_EX"))
.subcommand(clap::SubCommand::with_name("LOCK_SH"))
.subcommand(clap::SubCommand::with_name("SHUT_RDWR"))
.subcommand(clap::SubCommand::with_name("SHUT_WR"))
.subcommand(clap::SubCommand::with_name("SHUT_RD"))
.subcommand(clap::SubCommand::with_name("SO_DEBUG"))
.subcommand(clap::SubCommand::with_name("TCP_CONGESTION"))
.subcommand(clap::SubCommand::with_name("TCP_QUICKACK"))
.subcommand(clap::SubCommand::with_name("TCP_INFO"))
.subcommand(clap::SubCommand::with_name("TCP_WINDOW_CLAMP"))
.subcommand(clap::SubCommand::with_name("TCP_DEFER_ACCEPT"))
.subcommand(clap::SubCommand::with_name("TCP_LINGER2"))
.subcommand(clap::SubCommand::with_name("TCP_SYNCNT"))
.subcommand(clap::SubCommand::with_name("TCP_KEEPCNT"))
.subcommand(clap::SubCommand::with_name("TCP_KEEPINTVL"))
.subcommand(clap::SubCommand::with_name("TCP_KEEPIDLE"))
.subcommand(clap::SubCommand::with_name("TCP_CORK"))
.subcommand(clap::SubCommand::with_name("TCP_MAXSEG"))
.subcommand(clap::SubCommand::with_name("TCP_NODELAY"))
.subcommand(clap::SubCommand::with_name("IP_PMTUDISC_PROBE"))
.subcommand(clap::SubCommand::with_name("IP_PMTUDISC_DO"))
.subcommand(clap::SubCommand::with_name("IP_PMTUDISC_WANT"))
.subcommand(clap::SubCommand::with_name("IP_PMTUDISC_DONT"))
.subcommand(clap::SubCommand::with_name("IPV6_TCLASS"))
.subcommand(clap::SubCommand::with_name("IPV6_RECVTCLASS"))
.subcommand(clap::SubCommand::with_name("IPV6_PKTINFO"))
.subcommand(clap::SubCommand::with_name("IPV6_RECVPKTINFO"))
.subcommand(clap::SubCommand::with_name("IPV6_LEAVE_ANYCAST"))
.subcommand(clap::SubCommand::with_name("IPV6_JOIN_ANYCAST"))
.subcommand(clap::SubCommand::with_name("IPV6_V6ONLY"))
.subcommand(clap::SubCommand::with_name("IPV6_RECVERR"))
.subcommand(clap::SubCommand::with_name("IPV6_MTU"))
.subcommand(clap::SubCommand::with_name("IPV6_MTU_DISCOVER"))
.subcommand(clap::SubCommand::with_name("IPV6_ROUTER_ALERT"))
.subcommand(clap::SubCommand::with_name("IPV6_DROP_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("IPV6_ADD_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("IPV6_MULTICAST_LOOP"))
.subcommand(clap::SubCommand::with_name("IPV6_MULTICAST_HOPS"))
.subcommand(clap::SubCommand::with_name("IPV6_MULTICAST_IF"))
.subcommand(clap::SubCommand::with_name("IPV6_UNICAST_HOPS"))
.subcommand(clap::SubCommand::with_name("IPV6_NEXTHOP"))
.subcommand(clap::SubCommand::with_name("IPV6_2292HOPLIMIT"))
.subcommand(clap::SubCommand::with_name("IPV6_CHECKSUM"))
.subcommand(clap::SubCommand::with_name("IPV6_2292PKTOPTIONS"))
.subcommand(clap::SubCommand::with_name("IPV6_2292RTHDR"))
.subcommand(clap::SubCommand::with_name("IPV6_2292DSTOPTS"))
.subcommand(clap::SubCommand::with_name("IPV6_2292HOPOPTS"))
.subcommand(clap::SubCommand::with_name("IPV6_2292PKTINFO"))
.subcommand(clap::SubCommand::with_name("IPV6_ADDRFORM"))
.subcommand(clap::SubCommand::with_name("IP_TRANSPARENT"))
.subcommand(clap::SubCommand::with_name("IP_DROP_SOURCE_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("IP_ADD_SOURCE_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("IP_DROP_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("IP_ADD_MEMBERSHIP"))
.subcommand(clap::SubCommand::with_name("IP_RECVERR"))
.subcommand(clap::SubCommand::with_name("IP_RECVTOS"))
.subcommand(clap::SubCommand::with_name("IP_MTU_DISCOVER"))
.subcommand(clap::SubCommand::with_name("IP_PKTINFO"))
.subcommand(clap::SubCommand::with_name("IP_HDRINCL"))
.subcommand(clap::SubCommand::with_name("IP_TTL"))
.subcommand(clap::SubCommand::with_name("IP_TOS"))
.subcommand(clap::SubCommand::with_name("IP_MULTICAST_LOOP"))
.subcommand(clap::SubCommand::with_name("IP_MULTICAST_TTL"))
.subcommand(clap::SubCommand::with_name("IP_MULTICAST_IF"))
.subcommand(clap::SubCommand::with_name("SOCK_RDM"))
.subcommand(clap::SubCommand::with_name("SOCK_RAW"))
.subcommand(clap::SubCommand::with_name("SCM_TIMESTAMP"))
.subcommand(clap::SubCommand::with_name("MSG_CMSG_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("MSG_FASTOPEN"))
.subcommand(clap::SubCommand::with_name("MSG_WAITFORONE"))
.subcommand(clap::SubCommand::with_name("MSG_MORE"))
.subcommand(clap::SubCommand::with_name("MSG_NOSIGNAL"))
.subcommand(clap::SubCommand::with_name("MSG_ERRQUEUE"))
.subcommand(clap::SubCommand::with_name("MSG_RST"))
.subcommand(clap::SubCommand::with_name("MSG_CONFIRM"))
.subcommand(clap::SubCommand::with_name("MSG_SYN"))
.subcommand(clap::SubCommand::with_name("MSG_FIN"))
.subcommand(clap::SubCommand::with_name("MSG_WAITALL"))
.subcommand(clap::SubCommand::with_name("MSG_EOR"))
.subcommand(clap::SubCommand::with_name("MSG_DONTWAIT"))
.subcommand(clap::SubCommand::with_name("MSG_TRUNC"))
.subcommand(clap::SubCommand::with_name("MSG_CTRUNC"))
.subcommand(clap::SubCommand::with_name("MSG_DONTROUTE"))
.subcommand(clap::SubCommand::with_name("MSG_PEEK"))
.subcommand(clap::SubCommand::with_name("MSG_OOB"))
.subcommand(clap::SubCommand::with_name("SOMAXCONN"))
.subcommand(clap::SubCommand::with_name("PF_ALG"))
.subcommand(clap::SubCommand::with_name("PF_CAIF"))
.subcommand(clap::SubCommand::with_name("PF_IEEE802154"))
.subcommand(clap::SubCommand::with_name("PF_PHONET"))
.subcommand(clap::SubCommand::with_name("PF_ISDN"))
.subcommand(clap::SubCommand::with_name("PF_RXRPC"))
.subcommand(clap::SubCommand::with_name("PF_IUCV"))
.subcommand(clap::SubCommand::with_name("PF_BLUETOOTH"))
.subcommand(clap::SubCommand::with_name("PF_TIPC"))
.subcommand(clap::SubCommand::with_name("PF_CAN"))
.subcommand(clap::SubCommand::with_name("PF_LLC"))
.subcommand(clap::SubCommand::with_name("PF_WANPIPE"))
.subcommand(clap::SubCommand::with_name("PF_PPPOX"))
.subcommand(clap::SubCommand::with_name("PF_IRDA"))
.subcommand(clap::SubCommand::with_name("PF_SNA"))
.subcommand(clap::SubCommand::with_name("PF_RDS"))
.subcommand(clap::SubCommand::with_name("PF_ATMSVC"))
.subcommand(clap::SubCommand::with_name("PF_ECONET"))
.subcommand(clap::SubCommand::with_name("PF_ASH"))
.subcommand(clap::SubCommand::with_name("PF_PACKET"))
.subcommand(clap::SubCommand::with_name("PF_ROUTE"))
.subcommand(clap::SubCommand::with_name("PF_NETLINK"))
.subcommand(clap::SubCommand::with_name("PF_KEY"))
.subcommand(clap::SubCommand::with_name("PF_SECURITY"))
.subcommand(clap::SubCommand::with_name("PF_NETBEUI"))
.subcommand(clap::SubCommand::with_name("PF_DECnet"))
.subcommand(clap::SubCommand::with_name("PF_ROSE"))
.subcommand(clap::SubCommand::with_name("PF_INET6"))
.subcommand(clap::SubCommand::with_name("PF_X25"))
.subcommand(clap::SubCommand::with_name("PF_ATMPVC"))
.subcommand(clap::SubCommand::with_name("PF_BRIDGE"))
.subcommand(clap::SubCommand::with_name("PF_NETROM"))
.subcommand(clap::SubCommand::with_name("PF_APPLETALK"))
.subcommand(clap::SubCommand::with_name("PF_IPX"))
.subcommand(clap::SubCommand::with_name("PF_AX25"))
.subcommand(clap::SubCommand::with_name("PF_INET"))
.subcommand(clap::SubCommand::with_name("PF_LOCAL"))
.subcommand(clap::SubCommand::with_name("PF_UNIX"))
.subcommand(clap::SubCommand::with_name("PF_UNSPEC"))
.subcommand(clap::SubCommand::with_name("AF_ALG"))
.subcommand(clap::SubCommand::with_name("AF_CAIF"))
.subcommand(clap::SubCommand::with_name("AF_IEEE802154"))
.subcommand(clap::SubCommand::with_name("AF_PHONET"))
.subcommand(clap::SubCommand::with_name("AF_ISDN"))
.subcommand(clap::SubCommand::with_name("AF_RXRPC"))
.subcommand(clap::SubCommand::with_name("AF_IUCV"))
.subcommand(clap::SubCommand::with_name("AF_BLUETOOTH"))
.subcommand(clap::SubCommand::with_name("AF_TIPC"))
.subcommand(clap::SubCommand::with_name("AF_CAN"))
.subcommand(clap::SubCommand::with_name("AF_LLC"))
.subcommand(clap::SubCommand::with_name("AF_WANPIPE"))
.subcommand(clap::SubCommand::with_name("AF_PPPOX"))
.subcommand(clap::SubCommand::with_name("AF_IRDA"))
.subcommand(clap::SubCommand::with_name("AF_SNA"))
.subcommand(clap::SubCommand::with_name("AF_RDS"))
.subcommand(clap::SubCommand::with_name("AF_ATMSVC"))
.subcommand(clap::SubCommand::with_name("AF_ECONET"))
.subcommand(clap::SubCommand::with_name("AF_ASH"))
.subcommand(clap::SubCommand::with_name("AF_PACKET"))
.subcommand(clap::SubCommand::with_name("AF_ROUTE"))
.subcommand(clap::SubCommand::with_name("AF_NETLINK"))
.subcommand(clap::SubCommand::with_name("AF_KEY"))
.subcommand(clap::SubCommand::with_name("AF_SECURITY"))
.subcommand(clap::SubCommand::with_name("AF_NETBEUI"))
.subcommand(clap::SubCommand::with_name("AF_DECnet"))
.subcommand(clap::SubCommand::with_name("AF_ROSE"))
.subcommand(clap::SubCommand::with_name("AF_INET6"))
.subcommand(clap::SubCommand::with_name("AF_X25"))
.subcommand(clap::SubCommand::with_name("AF_ATMPVC"))
.subcommand(clap::SubCommand::with_name("AF_BRIDGE"))
.subcommand(clap::SubCommand::with_name("AF_NETROM"))
.subcommand(clap::SubCommand::with_name("AF_APPLETALK"))
.subcommand(clap::SubCommand::with_name("AF_IPX"))
.subcommand(clap::SubCommand::with_name("AF_AX25"))
.subcommand(clap::SubCommand::with_name("AF_INET"))
.subcommand(clap::SubCommand::with_name("AF_LOCAL"))
.subcommand(clap::SubCommand::with_name("AF_UNIX"))
.subcommand(clap::SubCommand::with_name("AF_UNSPEC"))
.subcommand(clap::SubCommand::with_name("SOL_ALG"))
.subcommand(clap::SubCommand::with_name("SOL_BLUETOOTH"))
.subcommand(clap::SubCommand::with_name("SOL_TIPC"))
.subcommand(clap::SubCommand::with_name("SOL_NETLINK"))
.subcommand(clap::SubCommand::with_name("SOL_DCCP"))
.subcommand(clap::SubCommand::with_name("SOL_LLC"))
.subcommand(clap::SubCommand::with_name("SOL_NETBEUI"))
.subcommand(clap::SubCommand::with_name("SOL_IRDA"))
.subcommand(clap::SubCommand::with_name("SOL_AAL"))
.subcommand(clap::SubCommand::with_name("SOL_ATM"))
.subcommand(clap::SubCommand::with_name("SOL_PACKET"))
.subcommand(clap::SubCommand::with_name("SOL_X25"))
.subcommand(clap::SubCommand::with_name("SOL_DECNET"))
.subcommand(clap::SubCommand::with_name("SOL_RAW"))
.subcommand(clap::SubCommand::with_name("SOL_ICMPV6"))
.subcommand(clap::SubCommand::with_name("SOL_IPV6"))
.subcommand(clap::SubCommand::with_name("SOL_UDP"))
.subcommand(clap::SubCommand::with_name("SOL_TCP"))
.subcommand(clap::SubCommand::with_name("SOL_IP"))
.subcommand(clap::SubCommand::with_name("IFF_DYNAMIC"))
.subcommand(clap::SubCommand::with_name("IFF_AUTOMEDIA"))
.subcommand(clap::SubCommand::with_name("IFF_PORTSEL"))
.subcommand(clap::SubCommand::with_name("IFF_MULTICAST"))
.subcommand(clap::SubCommand::with_name("IFF_SLAVE"))
.subcommand(clap::SubCommand::with_name("IFF_MASTER"))
.subcommand(clap::SubCommand::with_name("IFF_ALLMULTI"))
.subcommand(clap::SubCommand::with_name("IFF_PROMISC"))
.subcommand(clap::SubCommand::with_name("IFF_NOARP"))
.subcommand(clap::SubCommand::with_name("IFF_RUNNING"))
.subcommand(clap::SubCommand::with_name("IFF_NOTRAILERS"))
.subcommand(clap::SubCommand::with_name("IFF_POINTOPOINT"))
.subcommand(clap::SubCommand::with_name("IFF_LOOPBACK"))
.subcommand(clap::SubCommand::with_name("IFF_DEBUG"))
.subcommand(clap::SubCommand::with_name("IFF_BROADCAST"))
.subcommand(clap::SubCommand::with_name("IFF_UP"))
.subcommand(clap::SubCommand::with_name("MADV_HWPOISON"))
.subcommand(clap::SubCommand::with_name("MADV_DODUMP"))
.subcommand(clap::SubCommand::with_name("MADV_DONTDUMP"))
.subcommand(clap::SubCommand::with_name("MADV_NOHUGEPAGE"))
.subcommand(clap::SubCommand::with_name("MADV_HUGEPAGE"))
.subcommand(clap::SubCommand::with_name("MADV_UNMERGEABLE"))
.subcommand(clap::SubCommand::with_name("MADV_MERGEABLE"))
.subcommand(clap::SubCommand::with_name("MADV_DOFORK"))
.subcommand(clap::SubCommand::with_name("MADV_DONTFORK"))
.subcommand(clap::SubCommand::with_name("MADV_REMOVE"))
.subcommand(clap::SubCommand::with_name("MADV_FREE"))
.subcommand(clap::SubCommand::with_name("MADV_DONTNEED"))
.subcommand(clap::SubCommand::with_name("MADV_WILLNEED"))
.subcommand(clap::SubCommand::with_name("MADV_SEQUENTIAL"))
.subcommand(clap::SubCommand::with_name("MADV_RANDOM"))
.subcommand(clap::SubCommand::with_name("MADV_NORMAL"))
.subcommand(clap::SubCommand::with_name("MAP_TYPE"))
.subcommand(clap::SubCommand::with_name("PROT_GROWSUP"))
.subcommand(clap::SubCommand::with_name("PROT_GROWSDOWN"))
.subcommand(clap::SubCommand::with_name("SCM_CREDENTIALS"))
.subcommand(clap::SubCommand::with_name("SCM_RIGHTS"))
.subcommand(clap::SubCommand::with_name("MS_MGC_MSK"))
.subcommand(clap::SubCommand::with_name("MS_MGC_VAL"))
.subcommand(clap::SubCommand::with_name("MS_ACTIVE"))
.subcommand(clap::SubCommand::with_name("MS_STRICTATIME"))
.subcommand(clap::SubCommand::with_name("MS_I_VERSION"))
.subcommand(clap::SubCommand::with_name("MS_KERNMOUNT"))
.subcommand(clap::SubCommand::with_name("MS_RELATIME"))
.subcommand(clap::SubCommand::with_name("MS_SHARED"))
.subcommand(clap::SubCommand::with_name("MS_SLAVE"))
.subcommand(clap::SubCommand::with_name("MS_PRIVATE"))
.subcommand(clap::SubCommand::with_name("MS_UNBINDABLE"))
.subcommand(clap::SubCommand::with_name("MS_POSIXACL"))
.subcommand(clap::SubCommand::with_name("MS_SILENT"))
.subcommand(clap::SubCommand::with_name("MS_REC"))
.subcommand(clap::SubCommand::with_name("MS_MOVE"))
.subcommand(clap::SubCommand::with_name("MS_BIND"))
.subcommand(clap::SubCommand::with_name("MS_NODIRATIME"))
.subcommand(clap::SubCommand::with_name("MS_NOATIME"))
.subcommand(clap::SubCommand::with_name("MS_DIRSYNC"))
.subcommand(clap::SubCommand::with_name("MS_MANDLOCK"))
.subcommand(clap::SubCommand::with_name("MS_REMOUNT"))
.subcommand(clap::SubCommand::with_name("MS_SYNCHRONOUS"))
.subcommand(clap::SubCommand::with_name("MS_NOEXEC"))
.subcommand(clap::SubCommand::with_name("MS_NODEV"))
.subcommand(clap::SubCommand::with_name("MS_NOSUID"))
.subcommand(clap::SubCommand::with_name("MS_RDONLY"))
.subcommand(clap::SubCommand::with_name("MS_SYNC"))
.subcommand(clap::SubCommand::with_name("MS_INVALIDATE"))
.subcommand(clap::SubCommand::with_name("MS_ASYNC"))
.subcommand(clap::SubCommand::with_name("MAP_FIXED"))
.subcommand(clap::SubCommand::with_name("MAP_PRIVATE"))
.subcommand(clap::SubCommand::with_name("MAP_SHARED"))
.subcommand(clap::SubCommand::with_name("MAP_FILE"))
.subcommand(clap::SubCommand::with_name("LC_MESSAGES_MASK"))
.subcommand(clap::SubCommand::with_name("LC_MONETARY_MASK"))
.subcommand(clap::SubCommand::with_name("LC_COLLATE_MASK"))
.subcommand(clap::SubCommand::with_name("LC_TIME_MASK"))
.subcommand(clap::SubCommand::with_name("LC_NUMERIC_MASK"))
.subcommand(clap::SubCommand::with_name("LC_CTYPE_MASK"))
.subcommand(clap::SubCommand::with_name("LC_ALL"))
.subcommand(clap::SubCommand::with_name("LC_MESSAGES"))
.subcommand(clap::SubCommand::with_name("LC_MONETARY"))
.subcommand(clap::SubCommand::with_name("LC_COLLATE"))
.subcommand(clap::SubCommand::with_name("LC_TIME"))
.subcommand(clap::SubCommand::with_name("LC_NUMERIC"))
.subcommand(clap::SubCommand::with_name("LC_CTYPE"))
.subcommand(clap::SubCommand::with_name("PROT_EXEC"))
.subcommand(clap::SubCommand::with_name("PROT_WRITE"))
.subcommand(clap::SubCommand::with_name("PROT_READ"))
.subcommand(clap::SubCommand::with_name("PROT_NONE"))
.subcommand(clap::SubCommand::with_name("SIGTERM"))
.subcommand(clap::SubCommand::with_name("SIGALRM"))
.subcommand(clap::SubCommand::with_name("SIGPIPE"))
.subcommand(clap::SubCommand::with_name("SIGSEGV"))
.subcommand(clap::SubCommand::with_name("SIGKILL"))
.subcommand(clap::SubCommand::with_name("SIGFPE"))
.subcommand(clap::SubCommand::with_name("SIGABRT"))
.subcommand(clap::SubCommand::with_name("SIGILL"))
.subcommand(clap::SubCommand::with_name("SIGQUIT"))
.subcommand(clap::SubCommand::with_name("SIGINT"))
.subcommand(clap::SubCommand::with_name("SIGHUP"))
.subcommand(clap::SubCommand::with_name("STDERR_FILENO"))
.subcommand(clap::SubCommand::with_name("STDOUT_FILENO"))
.subcommand(clap::SubCommand::with_name("STDIN_FILENO"))
.subcommand(clap::SubCommand::with_name("X_OK"))
.subcommand(clap::SubCommand::with_name("W_OK"))
.subcommand(clap::SubCommand::with_name("R_OK"))
.subcommand(clap::SubCommand::with_name("F_OK"))
.subcommand(clap::SubCommand::with_name("S_IROTH"))
.subcommand(clap::SubCommand::with_name("S_IWOTH"))
.subcommand(clap::SubCommand::with_name("S_IXOTH"))
.subcommand(clap::SubCommand::with_name("S_IRWXO"))
.subcommand(clap::SubCommand::with_name("S_IRGRP"))
.subcommand(clap::SubCommand::with_name("S_IWGRP"))
.subcommand(clap::SubCommand::with_name("S_IXGRP"))
.subcommand(clap::SubCommand::with_name("S_IRWXG"))
.subcommand(clap::SubCommand::with_name("S_IRUSR"))
.subcommand(clap::SubCommand::with_name("S_IWUSR"))
.subcommand(clap::SubCommand::with_name("S_IXUSR"))
.subcommand(clap::SubCommand::with_name("S_IRWXU"))
.subcommand(clap::SubCommand::with_name("S_IFMT"))
.subcommand(clap::SubCommand::with_name("S_IFSOCK"))
.subcommand(clap::SubCommand::with_name("S_IFLNK"))
.subcommand(clap::SubCommand::with_name("S_IFREG"))
.subcommand(clap::SubCommand::with_name("S_IFDIR"))
.subcommand(clap::SubCommand::with_name("S_IFBLK"))
.subcommand(clap::SubCommand::with_name("S_IFCHR"))
.subcommand(clap::SubCommand::with_name("S_IFIFO"))
.subcommand(clap::SubCommand::with_name("SOCK_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("O_RDWR"))
.subcommand(clap::SubCommand::with_name("O_WRONLY"))
.subcommand(clap::SubCommand::with_name("O_RDONLY"))
.subcommand(clap::SubCommand::with_name("RUSAGE_SELF"))
.subcommand(clap::SubCommand::with_name("TIMER_ABSTIME"))
.subcommand(clap::SubCommand::with_name("CLOCK_TAI"))
.subcommand(clap::SubCommand::with_name("CLOCK_BOOTTIME_ALARM"))
.subcommand(clap::SubCommand::with_name("CLOCK_REALTIME_ALARM"))
.subcommand(clap::SubCommand::with_name("CLOCK_BOOTTIME"))
.subcommand(clap::SubCommand::with_name("CLOCK_MONOTONIC_COARSE"))
.subcommand(clap::SubCommand::with_name("CLOCK_REALTIME_COARSE"))
.subcommand(clap::SubCommand::with_name("CLOCK_MONOTONIC_RAW"))
.subcommand(clap::SubCommand::with_name("CLOCK_THREAD_CPUTIME_ID"))
.subcommand(clap::SubCommand::with_name("CLOCK_PROCESS_CPUTIME_ID"))
.subcommand(clap::SubCommand::with_name("CLOCK_MONOTONIC"))
.subcommand(clap::SubCommand::with_name("CLOCK_REALTIME"))
.subcommand(clap::SubCommand::with_name("PTHREAD_CREATE_DETACHED"))
.subcommand(clap::SubCommand::with_name("PTHREAD_CREATE_JOINABLE"))
.subcommand(clap::SubCommand::with_name("SIGTRAP"))
.subcommand(clap::SubCommand::with_name("F_SEAL_WRITE"))
.subcommand(clap::SubCommand::with_name("F_SEAL_GROW"))
.subcommand(clap::SubCommand::with_name("F_SEAL_SHRINK"))
.subcommand(clap::SubCommand::with_name("F_SEAL_SEAL"))
.subcommand(clap::SubCommand::with_name("F_GET_SEALS"))
.subcommand(clap::SubCommand::with_name("F_ADD_SEALS"))
.subcommand(clap::SubCommand::with_name("F_GETPIPE_SZ"))
.subcommand(clap::SubCommand::with_name("F_SETPIPE_SZ"))
.subcommand(clap::SubCommand::with_name("F_DUPFD_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("F_CANCELLK"))
.subcommand(clap::SubCommand::with_name("F_NOTIFY"))
.subcommand(clap::SubCommand::with_name("F_GETLEASE"))
.subcommand(clap::SubCommand::with_name("F_SETLEASE"))
.subcommand(clap::SubCommand::with_name("F_SETFL"))
.subcommand(clap::SubCommand::with_name("F_GETFL"))
.subcommand(clap::SubCommand::with_name("F_SETFD"))
.subcommand(clap::SubCommand::with_name("F_GETFD"))
.subcommand(clap::SubCommand::with_name("F_DUPFD"))
.subcommand(clap::SubCommand::with_name("_IOLBF"))
.subcommand(clap::SubCommand::with_name("_IONBF"))
.subcommand(clap::SubCommand::with_name("_IOFBF"))
.subcommand(clap::SubCommand::with_name("SEEK_END"))
.subcommand(clap::SubCommand::with_name("SEEK_CUR"))
.subcommand(clap::SubCommand::with_name("SEEK_SET"))
.subcommand(clap::SubCommand::with_name("EOF"))
.subcommand(clap::SubCommand::with_name("RAND_MAX"))
.subcommand(clap::SubCommand::with_name("EXIT_SUCCESS"))
.subcommand(clap::SubCommand::with_name("EXIT_FAILURE"))
.subcommand(clap::SubCommand::with_name("ATF_USETRAILERS"))
.subcommand(clap::SubCommand::with_name("ATF_PUBL"))
.subcommand(clap::SubCommand::with_name("ATF_PERM"))
.subcommand(clap::SubCommand::with_name("ATF_COM"))
.subcommand(clap::SubCommand::with_name("ARPOP_REPLY"))
.subcommand(clap::SubCommand::with_name("ARPOP_REQUEST"))
.subcommand(clap::SubCommand::with_name("INADDR_NONE"))
.subcommand(clap::SubCommand::with_name("INADDR_BROADCAST"))
.subcommand(clap::SubCommand::with_name("INADDR_ANY"))
.subcommand(clap::SubCommand::with_name("INADDR_LOOPBACK"))
.subcommand(clap::SubCommand::with_name("IPPROTO_IPV6"))
.subcommand(clap::SubCommand::with_name("IPPROTO_IP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_UDP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_TCP"))
.subcommand(clap::SubCommand::with_name("IPPROTO_ICMPV6"))
.subcommand(clap::SubCommand::with_name("IPPROTO_ICMP"))
.subcommand(clap::SubCommand::with_name("PRIO_MAX"))
.subcommand(clap::SubCommand::with_name("PRIO_MIN"))
.subcommand(clap::SubCommand::with_name("PRIO_USER"))
.subcommand(clap::SubCommand::with_name("PRIO_PGRP"))
.subcommand(clap::SubCommand::with_name("PRIO_PROCESS"))
.subcommand(clap::SubCommand::with_name("LOG_FACMASK"))
.subcommand(clap::SubCommand::with_name("LOG_PRIMASK"))
.subcommand(clap::SubCommand::with_name("LOG_NOWAIT"))
.subcommand(clap::SubCommand::with_name("LOG_NDELAY"))
.subcommand(clap::SubCommand::with_name("LOG_ODELAY"))
.subcommand(clap::SubCommand::with_name("LOG_CONS"))
.subcommand(clap::SubCommand::with_name("LOG_PID"))
.subcommand(clap::SubCommand::with_name("LOG_LOCAL7"))
.subcommand(clap::SubCommand::with_name("LOG_LOCAL6"))
.subcommand(clap::SubCommand::with_name("LOG_LOCAL5"))
.subcommand(clap::SubCommand::with_name("LOG_LOCAL4"))
.subcommand(clap::SubCommand::with_name("LOG_LOCAL3"))
.subcommand(clap::SubCommand::with_name("LOG_LOCAL2"))
.subcommand(clap::SubCommand::with_name("LOG_LOCAL1"))
.subcommand(clap::SubCommand::with_name("LOG_LOCAL0"))
.subcommand(clap::SubCommand::with_name("LOG_UUCP"))
.subcommand(clap::SubCommand::with_name("LOG_NEWS"))
.subcommand(clap::SubCommand::with_name("LOG_LPR"))
.subcommand(clap::SubCommand::with_name("LOG_SYSLOG"))
.subcommand(clap::SubCommand::with_name("LOG_AUTH"))
.subcommand(clap::SubCommand::with_name("LOG_DAEMON"))
.subcommand(clap::SubCommand::with_name("LOG_MAIL"))
.subcommand(clap::SubCommand::with_name("LOG_USER"))
.subcommand(clap::SubCommand::with_name("LOG_KERN"))
.subcommand(clap::SubCommand::with_name("LOG_DEBUG"))
.subcommand(clap::SubCommand::with_name("LOG_INFO"))
.subcommand(clap::SubCommand::with_name("LOG_NOTICE"))
.subcommand(clap::SubCommand::with_name("LOG_WARNING"))
.subcommand(clap::SubCommand::with_name("LOG_ERR"))
.subcommand(clap::SubCommand::with_name("LOG_CRIT"))
.subcommand(clap::SubCommand::with_name("LOG_ALERT"))
.subcommand(clap::SubCommand::with_name("LOG_EMERG"))
.subcommand(clap::SubCommand::with_name("IFNAMSIZ"))
.subcommand(clap::SubCommand::with_name("IF_NAMESIZE"))
.subcommand(clap::SubCommand::with_name("S_ISVTX"))
.subcommand(clap::SubCommand::with_name("S_ISGID"))
.subcommand(clap::SubCommand::with_name("S_ISUID"))
.subcommand(clap::SubCommand::with_name("SIGIOT"))
.subcommand(clap::SubCommand::with_name("GRPQUOTA"))
.subcommand(clap::SubCommand::with_name("USRQUOTA"))
.subcommand(clap::SubCommand::with_name("FD_CLOEXEC"))
.subcommand(clap::SubCommand::with_name("DT_SOCK"))
.subcommand(clap::SubCommand::with_name("DT_LNK"))
.subcommand(clap::SubCommand::with_name("DT_REG"))
.subcommand(clap::SubCommand::with_name("DT_BLK"))
.subcommand(clap::SubCommand::with_name("DT_DIR"))
.subcommand(clap::SubCommand::with_name("DT_CHR"))
.subcommand(clap::SubCommand::with_name("DT_FIFO"))
.subcommand(clap::SubCommand::with_name("DT_UNKNOWN"))
.subcommand(clap::SubCommand::with_name("SIG_ERR"))
.subcommand(clap::SubCommand::with_name("SIG_IGN"))
.subcommand(clap::SubCommand::with_name("SIG_DFL"))
.subcommand(clap::SubCommand::with_name("INT_MAX"))
.subcommand(clap::SubCommand::with_name("INT_MIN"))
.subcommand(clap::SubCommand::with_name("TIOCCBRK"))
.subcommand(clap::SubCommand::with_name("TIOCSBRK"))
.subcommand(clap::SubCommand::with_name("IPV6_HOPLIMIT"))

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
