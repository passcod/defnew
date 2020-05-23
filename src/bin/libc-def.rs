
			#[rustfmt::skip]
			#[allow(deprecated)]
			fn main() {
				let author = format!("CC BY-SA-NC 4.0 - {}", env!("CARGO_PKG_HOMEPAGE"));
				let args = clap::App::new("defnew")
					.author(author.as_ref())
					.about("libc-def: provides defs for libc types")
					.after_help("Defs are hard-coded at compile and are not guaranteed to be correct for your system.")
					.version(clap::crate_version!())
					.setting(clap::AppSettings::SubcommandRequired)
			
.subcommand(clap::App::new("ff_trigger"))
.subcommand(clap::App::new("Elf32_Addr"))
.subcommand(clap::App::new("Elf64_Chdr"))
.subcommand(clap::App::new("timezone"))
.subcommand(clap::App::new("rtentry"))
.subcommand(clap::App::new("_libc_xmmreg"))
.subcommand(clap::App::new("rlimit64"))
.subcommand(clap::App::new("__u32"))
.subcommand(clap::App::new("Elf32_Phdr"))
.subcommand(clap::App::new("Elf64_Addr"))
.subcommand(clap::App::new("ino_t"))
.subcommand(clap::App::new("mcontext_t"))
.subcommand(clap::App::new("cc_t"))
.subcommand(clap::App::new("statfs64"))
.subcommand(clap::App::new("c_uint"))
.subcommand(clap::App::new("__u16"))
.subcommand(clap::App::new("__rlimit_resource_t"))
.subcommand(clap::App::new("Dl_info"))
.subcommand(clap::App::new("pollfd"))
.subcommand(clap::App::new("id_t"))
.subcommand(clap::App::new("sighandler_t"))
.subcommand(clap::App::new("int32_t"))
.subcommand(clap::App::new("intptr_t"))
.subcommand(clap::App::new("utimbuf"))
.subcommand(clap::App::new("__fsword_t"))
.subcommand(clap::App::new("input_keymap_entry"))
.subcommand(clap::App::new("ino64_t"))
.subcommand(clap::App::new("msqid_ds"))
.subcommand(clap::App::new("tcflag_t"))
.subcommand(clap::App::new("cmsghdr"))
.subcommand(clap::App::new("tms"))
.subcommand(clap::App::new("regmatch_t"))
.subcommand(clap::App::new("flock"))
.subcommand(clap::App::new("in_pktinfo"))
.subcommand(clap::App::new("servent"))
.subcommand(clap::App::new("protoent"))
.subcommand(clap::App::new("Lmid_t"))
.subcommand(clap::App::new("dirent"))
.subcommand(clap::App::new("fd_set"))
.subcommand(clap::App::new("pthread_rwlock_t"))
.subcommand(clap::App::new("FILE"))
.subcommand(clap::App::new("wchar_t"))
.subcommand(clap::App::new("spwd"))
.subcommand(clap::App::new("ssize_t"))
.subcommand(clap::App::new("pthread_cond_t"))
.subcommand(clap::App::new("uint16_t"))
.subcommand(clap::App::new("Elf64_Off"))
.subcommand(clap::App::new("posix_spawn_file_actions_t"))
.subcommand(clap::App::new("ntptimeval"))
.subcommand(clap::App::new("arpd_request"))
.subcommand(clap::App::new("ip_mreq_source"))
.subcommand(clap::App::new("sembuf"))
.subcommand(clap::App::new("ff_envelope"))
.subcommand(clap::App::new("statx"))
.subcommand(clap::App::new("ipc_perm"))
.subcommand(clap::App::new("rusage"))
.subcommand(clap::App::new("pthread_mutexattr_t"))
.subcommand(clap::App::new("ip_mreq"))
.subcommand(clap::App::new("c_int"))
.subcommand(clap::App::new("mqd_t"))
.subcommand(clap::App::new("pthread_attr_t"))
.subcommand(clap::App::new("glob64_t"))
.subcommand(clap::App::new("ff_effect"))
.subcommand(clap::App::new("sockaddr"))
.subcommand(clap::App::new("msgqnum_t"))
.subcommand(clap::App::new("arphdr"))
.subcommand(clap::App::new("ff_replay"))
.subcommand(clap::App::new("itimerspec"))
.subcommand(clap::App::new("fanotify_response"))
.subcommand(clap::App::new("size_t"))
.subcommand(clap::App::new("c_double"))
.subcommand(clap::App::new("suseconds_t"))
.subcommand(clap::App::new("c_ulong"))
.subcommand(clap::App::new("__u8"))
.subcommand(clap::App::new("ff_constant_effect"))
.subcommand(clap::App::new("off_t"))
.subcommand(clap::App::new("glob_t"))
.subcommand(clap::App::new("DIR"))
.subcommand(clap::App::new("_libc_fpxreg"))
.subcommand(clap::App::new("useconds_t"))
.subcommand(clap::App::new("Elf32_Word"))
.subcommand(clap::App::new("signalfd_siginfo"))
.subcommand(clap::App::new("ptrdiff_t"))
.subcommand(clap::App::new("ff_periodic_effect"))
.subcommand(clap::App::new("msginfo"))
.subcommand(clap::App::new("sockaddr_in6"))
.subcommand(clap::App::new("utsname"))
.subcommand(clap::App::new("key_t"))
.subcommand(clap::App::new("user"))
.subcommand(clap::App::new("gid_t"))
.subcommand(clap::App::new("Elf32_Off"))
.subcommand(clap::App::new("sock_extended_err"))
.subcommand(clap::App::new("rlimit"))
.subcommand(clap::App::new("clockid_t"))
.subcommand(clap::App::new("fpos64_t"))
.subcommand(clap::App::new("uint32_t"))
.subcommand(clap::App::new("in6_pktinfo"))
.subcommand(clap::App::new("in_port_t"))
.subcommand(clap::App::new("sigset_t"))
.subcommand(clap::App::new("sched_param"))
.subcommand(clap::App::new("loff_t"))
.subcommand(clap::App::new("locale_t"))
.subcommand(clap::App::new("blksize_t"))
.subcommand(clap::App::new("fanotify_event_metadata"))
.subcommand(clap::App::new("sockaddr_storage"))
.subcommand(clap::App::new("uintmax_t"))
.subcommand(clap::App::new("dl_phdr_info"))
.subcommand(clap::App::new("stack_t"))
.subcommand(clap::App::new("c_float"))
.subcommand(clap::App::new("arpreq"))
.subcommand(clap::App::new("dev_t"))
.subcommand(clap::App::new("Elf64_Word"))
.subcommand(clap::App::new("intmax_t"))
.subcommand(clap::App::new("statx_timestamp"))
.subcommand(clap::App::new("pthread_condattr_t"))
.subcommand(clap::App::new("stat"))
.subcommand(clap::App::new("timespec"))
.subcommand(clap::App::new("stat64"))
.subcommand(clap::App::new("nlattr"))
.subcommand(clap::App::new("mmsghdr"))
.subcommand(clap::App::new("fsid_t"))
.subcommand(clap::App::new("winsize"))
.subcommand(clap::App::new("ff_rumble_effect"))
.subcommand(clap::App::new("mallinfo"))
.subcommand(clap::App::new("Elf64_Phdr"))
.subcommand(clap::App::new("siginfo_t"))
.subcommand(clap::App::new("ff_condition_effect"))
.subcommand(clap::App::new("statfs"))
.subcommand(clap::App::new("termios"))
.subcommand(clap::App::new("socklen_t"))
.subcommand(clap::App::new("itimerval"))
.subcommand(clap::App::new("regex_t"))
.subcommand(clap::App::new("sockaddr_ll"))
.subcommand(clap::App::new("c_long"))
.subcommand(clap::App::new("ip_mreqn"))
.subcommand(clap::App::new("__u64"))
.subcommand(clap::App::new("sigval"))
.subcommand(clap::App::new("_libc_fpstate"))
.subcommand(clap::App::new("Elf32_Ehdr"))
.subcommand(clap::App::new("uint64_t"))
.subcommand(clap::App::new("pthread_mutex_t"))
.subcommand(clap::App::new("Elf64_Half"))
.subcommand(clap::App::new("msghdr"))
.subcommand(clap::App::new("sockaddr_alg"))
.subcommand(clap::App::new("in_addr_t"))
.subcommand(clap::App::new("pthread_t"))
.subcommand(clap::App::new("pid_t"))
.subcommand(clap::App::new("epoll_event"))
.subcommand(clap::App::new("fsfilcnt_t"))
.subcommand(clap::App::new("speed_t"))
.subcommand(clap::App::new("if_nameindex"))
.subcommand(clap::App::new("pthread_rwlockattr_t"))
.subcommand(clap::App::new("utmpx"))
.subcommand(clap::App::new("time_t"))
.subcommand(clap::App::new("__timeval"))
.subcommand(clap::App::new("int16_t"))
.subcommand(clap::App::new("Elf64_Sxword"))
.subcommand(clap::App::new("msglen_t"))
.subcommand(clap::App::new("hostent"))
.subcommand(clap::App::new("dirent64"))
.subcommand(clap::App::new("ff_ramp_effect"))
.subcommand(clap::App::new("linger"))
.subcommand(clap::App::new("Elf64_Ehdr"))
.subcommand(clap::App::new("flock64"))
.subcommand(clap::App::new("sockaddr_un"))
.subcommand(clap::App::new("lconv"))
.subcommand(clap::App::new("sockaddr_in"))
.subcommand(clap::App::new("mq_attr"))
.subcommand(clap::App::new("max_align_t"))
.subcommand(clap::App::new("nlmsghdr"))
.subcommand(clap::App::new("nl_pktinfo"))
.subcommand(clap::App::new("termios2"))
.subcommand(clap::App::new("statvfs64"))
.subcommand(clap::App::new("__s32"))
.subcommand(clap::App::new("in6_rtmsg"))
.subcommand(clap::App::new("nl_mmap_req"))
.subcommand(clap::App::new("blkcnt_t"))
.subcommand(clap::App::new("group"))
.subcommand(clap::App::new("rlim_t"))
.subcommand(clap::App::new("Elf64_Sym"))
.subcommand(clap::App::new("clock_t"))
.subcommand(clap::App::new("sysinfo"))
.subcommand(clap::App::new("fsblkcnt_t"))
.subcommand(clap::App::new("__exit_status"))
.subcommand(clap::App::new("c_void"))
.subcommand(clap::App::new("cpu_set_t"))
.subcommand(clap::App::new("ipv6_mreq"))
.subcommand(clap::App::new("c_schar"))
.subcommand(clap::App::new("user_fpregs_struct"))
.subcommand(clap::App::new("__priority_which_t"))
.subcommand(clap::App::new("nl_mmap_hdr"))
.subcommand(clap::App::new("input_absinfo"))
.subcommand(clap::App::new("genlmsghdr"))
.subcommand(clap::App::new("statvfs"))
.subcommand(clap::App::new("Elf64_Xword"))
.subcommand(clap::App::new("arpreq_old"))
.subcommand(clap::App::new("nl_item"))
.subcommand(clap::App::new("sem_t"))
.subcommand(clap::App::new("c_char"))
.subcommand(clap::App::new("timeval"))
.subcommand(clap::App::new("regoff_t"))
.subcommand(clap::App::new("inotify_event"))
.subcommand(clap::App::new("int64_t"))
.subcommand(clap::App::new("idtype_t"))
.subcommand(clap::App::new("Elf32_Shdr"))
.subcommand(clap::App::new("mode_t"))
.subcommand(clap::App::new("tm"))
.subcommand(clap::App::new("Elf32_Sym"))
.subcommand(clap::App::new("nlmsgerr"))
.subcommand(clap::App::new("Elf64_Section"))
.subcommand(clap::App::new("uintptr_t"))
.subcommand(clap::App::new("aiocb"))
.subcommand(clap::App::new("sockaddr_nl"))
.subcommand(clap::App::new("input_mask"))
.subcommand(clap::App::new("rlim64_t"))
.subcommand(clap::App::new("Elf32_Chdr"))
.subcommand(clap::App::new("uid_t"))
.subcommand(clap::App::new("in6_addr"))
.subcommand(clap::App::new("input_id"))
.subcommand(clap::App::new("c_uchar"))
.subcommand(clap::App::new("sa_family_t"))
.subcommand(clap::App::new("shmid_ds"))
.subcommand(clap::App::new("timex"))
.subcommand(clap::App::new("c_short"))
.subcommand(clap::App::new("shmatt_t"))
.subcommand(clap::App::new("iovec"))
.subcommand(clap::App::new("Elf32_Section"))
.subcommand(clap::App::new("nlink_t"))
.subcommand(clap::App::new("input_event"))
.subcommand(clap::App::new("c_ulonglong"))
.subcommand(clap::App::new("fpos_t"))
.subcommand(clap::App::new("Elf64_Shdr"))
.subcommand(clap::App::new("blkcnt64_t"))
.subcommand(clap::App::new("in_addr"))
.subcommand(clap::App::new("pthread_key_t"))
.subcommand(clap::App::new("__s16"))
.subcommand(clap::App::new("mntent"))
.subcommand(clap::App::new("dqblk"))
.subcommand(clap::App::new("int8_t"))
.subcommand(clap::App::new("sigevent"))
.subcommand(clap::App::new("af_alg_iv"))
.subcommand(clap::App::new("sockaddr_vm"))
.subcommand(clap::App::new("packet_mreq"))
.subcommand(clap::App::new("c_longlong"))
.subcommand(clap::App::new("Elf32_Half"))
.subcommand(clap::App::new("posix_spawnattr_t"))
.subcommand(clap::App::new("uint8_t"))
.subcommand(clap::App::new("nfds_t"))
.subcommand(clap::App::new("user_regs_struct"))
.subcommand(clap::App::new("greg_t"))
.subcommand(clap::App::new("c_ushort"))
.subcommand(clap::App::new("passwd"))
.subcommand(clap::App::new("off64_t"))
.subcommand(clap::App::new("ucred"))

			.get_matches();

			println!("{}", match args.subcommand_name().unwrap() {
			
"ff_trigger" => r#"(struct (size 4) (name "ff_trigger") (align 2) (field "button" (integral (signed #f) (endian little) (width 2))) (field "interval" (integral (signed #f) (endian little) (width 2))))"#,
"Elf32_Addr" => r#"(integral (signed #f) (endian little) (width 4))"#,
"Elf64_Chdr" => r#"(struct (size 24) (name "Elf64_Chdr") (align 8) (field "ch_type" (integral (signed #f) (endian little) (width 4))) (field "ch_reserved" (integral (signed #f) (endian little) (width 4))) (field "ch_size" (integral (signed #f) (endian little) (width 8))) (field "ch_addralign" (integral (signed #f) (endian little) (width 8))))"#,
"timezone" => r#"(opaque)"#,
"rtentry" => r#"(struct (size 120) (name "rtentry") (align 8) (field "rt_pad1" (integral (signed #f) (endian little) (width 8))) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))) (field "rt_flags" (integral (signed #f) (endian little) (width 2))) (field "rt_pad2" (integral (signed #t) (endian little) (width 2))) (field "rt_pad3" (integral (signed #f) (endian little) (width 8))) (field "rt_tos" (integral (signed #f) (endian little) (width 1))) (field "rt_class" (integral (signed #f) (endian little) (width 1))) (field "rt_pad4" (array (length 3) (name "rt_pad4") (integral (signed #t) (endian little) (width 2)))) (field "rt_metric" (integral (signed #t) (endian little) (width 2))) (field "rt_dev" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "rt_mtu" (integral (signed #f) (endian little) (width 8))) (field "rt_window" (integral (signed #f) (endian little) (width 8))) (field "rt_irtt" (integral (signed #f) (endian little) (width 2))))"#,
"_libc_xmmreg" => r#"(struct (size 16) (name "_libc_xmmreg") (align 4) (field "element" (array (length 4) (name "element") (integral (signed #f) (endian little) (width 4)))))"#,
"rlimit64" => r#"(struct (size 16) (name "rlimit64") (align 8) (field "rlim_cur" (integral (signed #f) (endian little) (width 8))) (field "rlim_max" (integral (signed #f) (endian little) (width 8))))"#,
"__u32" => r#"(integral (signed #f) (endian little) (width 4))"#,
"Elf32_Phdr" => r#"(struct (size 32) (name "Elf32_Phdr") (align 4) (field "p_type" (integral (signed #f) (endian little) (width 4))) (field "p_offset" (integral (signed #f) (endian little) (width 4))) (field "p_vaddr" (integral (signed #f) (endian little) (width 4))) (field "p_paddr" (integral (signed #f) (endian little) (width 4))) (field "p_filesz" (integral (signed #f) (endian little) (width 4))) (field "p_memsz" (integral (signed #f) (endian little) (width 4))) (field "p_flags" (integral (signed #f) (endian little) (width 4))) (field "p_align" (integral (signed #f) (endian little) (width 4))))"#,
"Elf64_Addr" => r#"(integral (signed #f) (endian little) (width 8))"#,
"ino_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"mcontext_t" => r#"(struct (size 192) (name "mcontext_t") (align 8) (field "gregs" (array (length 23) (name "gregs") (integral (signed #t) (endian little) (width 8)))) (field "fpregs" (pointer (endian little) (width 8) (mutable #t) (points-to (struct (size 368) (name "_libc_fpstate") (align 8) (field "cwd" (integral (signed #f) (endian little) (width 2))) (field "swd" (integral (signed #f) (endian little) (width 2))) (field "ftw" (integral (signed #f) (endian little) (width 2))) (field "fop" (integral (signed #f) (endian little) (width 2))) (field "rip" (integral (signed #f) (endian little) (width 8))) (field "rdp" (integral (signed #f) (endian little) (width 8))) (field "mxcsr" (integral (signed #f) (endian little) (width 4))) (field "mxcr_mask" (integral (signed #f) (endian little) (width 4))) (field "_st" (array (length 8) (name "_st") (struct (size 10) (name "_libc_fpxreg") (align 2) (field "significand" (array (length 4) (name "significand") (integral (signed #f) (endian little) (width 2)))) (field "exponent" (integral (signed #f) (endian little) (width 2)))))) (field "_xmm" (array (length 16) (name "_xmm") (struct (size 16) (name "_libc_xmmreg") (align 4) (field "element" (array (length 4) (name "element") (integral (signed #f) (endian little) (width 4))))))))) 0)))"#,
"cc_t" => r#"(integral (signed #f) (endian little) (width 1))"#,
"statfs64" => r#"(struct (size 112) (name "statfs64") (align 8) (field "f_type" (integral (signed #t) (endian little) (width 8))) (field "f_bsize" (integral (signed #t) (endian little) (width 8))) (field "f_blocks" (integral (signed #f) (endian little) (width 8))) (field "f_bfree" (integral (signed #f) (endian little) (width 8))) (field "f_bavail" (integral (signed #f) (endian little) (width 8))) (field "f_files" (integral (signed #f) (endian little) (width 8))) (field "f_ffree" (integral (signed #f) (endian little) (width 8))) (field "fsid_t" (struct (size 0) (name "fsid_t") (align 1))) (field "f_namelen" (integral (signed #t) (endian little) (width 8))) (field "f_frsize" (integral (signed #t) (endian little) (width 8))) (field "f_flags" (integral (signed #t) (endian little) (width 8))) (field "f_spare" (array (length 4) (name "f_spare") (integral (signed #t) (endian little) (width 8)))))"#,
"c_uint" => r#"(integral (signed #f) (endian little) (width 4))"#,
"__u16" => r#"(integral (signed #f) (endian little) (width 2))"#,
"__rlimit_resource_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"Dl_info" => r#"(struct (size 32) (name "Dl_info") (align 8) (field "dli_fname" (pointer (endian little) (width 8) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "dli_fbase" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "dli_sname" (pointer (endian little) (width 8) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "dli_saddr" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)))"#,
"pollfd" => r#"(struct (size 8) (name "pollfd") (align 4) (field "fd" (integral (signed #t) (endian little) (width 4))) (field "events" (integral (signed #t) (endian little) (width 2))) (field "revents" (integral (signed #t) (endian little) (width 2))))"#,
"id_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"sighandler_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"int32_t" => r#"(integral (signed #t) (endian little) (width 4))"#,
"intptr_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"utimbuf" => r#"(struct (size 16) (name "utimbuf") (align 8) (field "actime" (integral (signed #t) (endian little) (width 8))) (field "modtime" (integral (signed #t) (endian little) (width 8))))"#,
"__fsword_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"input_keymap_entry" => r#"(struct (size 40) (name "input_keymap_entry") (align 4) (field "flags" (integral (signed #f) (endian little) (width 1))) (field "len" (integral (signed #f) (endian little) (width 1))) (field "index" (integral (signed #f) (endian little) (width 2))) (field "keycode" (integral (signed #f) (endian little) (width 4))) (field "scancode" (array (length 32) (name "scancode") (integral (signed #f) (endian little) (width 1)))))"#,
"ino64_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"msqid_ds" => r#"(struct (size 72) (name "msqid_ds") (align 8) (field "ipc_perm" (struct (size 24) (name "ipc_perm") (align 4) (field "__key" (integral (signed #t) (endian little) (width 4))) (field "uid" (integral (signed #f) (endian little) (width 4))) (field "gid" (integral (signed #f) (endian little) (width 4))) (field "cuid" (integral (signed #f) (endian little) (width 4))) (field "cgid" (integral (signed #f) (endian little) (width 4))) (field "mode" (integral (signed #f) (endian little) (width 2))) (field "__seq" (integral (signed #f) (endian little) (width 2))))) (field "msg_stime" (integral (signed #t) (endian little) (width 8))) (field "msg_rtime" (integral (signed #t) (endian little) (width 8))) (field "msg_ctime" (integral (signed #t) (endian little) (width 8))) (field "msg_qnum" (integral (signed #f) (endian little) (width 8))) (field "msg_qbytes" (integral (signed #f) (endian little) (width 8))) (field "msg_lspid" (integral (signed #t) (endian little) (width 4))) (field "msg_lrpid" (integral (signed #t) (endian little) (width 4))))"#,
"tcflag_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"cmsghdr" => r#"(struct (size 16) (name "cmsghdr") (align 8) (field "cmsg_len" (integral (signed #f) (endian little) (width 8))) (field "cmsg_level" (integral (signed #t) (endian little) (width 4))) (field "cmsg_type" (integral (signed #t) (endian little) (width 4))))"#,
"tms" => r#"(struct (size 32) (name "tms") (align 8) (field "tms_utime" (integral (signed #t) (endian little) (width 8))) (field "tms_stime" (integral (signed #t) (endian little) (width 8))) (field "tms_cutime" (integral (signed #t) (endian little) (width 8))) (field "tms_cstime" (integral (signed #t) (endian little) (width 8))))"#,
"regmatch_t" => r#"(struct (size 8) (name "regmatch_t") (align 4) (field "rm_so" (integral (signed #t) (endian little) (width 4))) (field "rm_eo" (integral (signed #t) (endian little) (width 4))))"#,
"flock" => r#"(struct (size 32) (name "flock") (align 8) (field "l_type" (integral (signed #t) (endian little) (width 2))) (field "l_whence" (integral (signed #t) (endian little) (width 2))) (field "l_start" (integral (signed #t) (endian little) (width 8))) (field "l_len" (integral (signed #t) (endian little) (width 8))) (field "l_pid" (integral (signed #t) (endian little) (width 4))))"#,
"in_pktinfo" => r#"(struct (size 12) (name "in_pktinfo") (align 4) (field "ipi_ifindex" (integral (signed #t) (endian little) (width 4))) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))))"#,
"servent" => r#"(struct (size 32) (name "servent") (align 8) (field "s_name" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "s_aliases" (pointer (endian little) (width 8) (mutable #t) (points-to (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) 0)) (field "s_port" (integral (signed #t) (endian little) (width 4))) (field "s_proto" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)))"#,
"protoent" => r#"(struct (size 24) (name "protoent") (align 8) (field "p_name" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "p_aliases" (pointer (endian little) (width 8) (mutable #t) (points-to (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) 0)) (field "p_proto" (integral (signed #t) (endian little) (width 4))))"#,
"Lmid_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"dirent" => r#"(struct (size 280) (name "dirent") (align 8) (field "d_ino" (integral (signed #f) (endian little) (width 8))) (field "d_off" (integral (signed #t) (endian little) (width 8))) (field "d_reclen" (integral (signed #f) (endian little) (width 2))) (field "d_type" (integral (signed #f) (endian little) (width 1))) (field "d_name" (array (length 256) (name "d_name") (integral (signed #t) (endian little) (width 1)))))"#,
"fd_set" => r#"(struct (size 0) (name "fd_set") (align 1))"#,
"pthread_rwlock_t" => r#"(struct (size 0) (name "pthread_rwlock_t") (align 8))"#,
"FILE" => r#"(opaque)"#,
"wchar_t" => r#"(integral (signed #t) (endian little) (width 4))"#,
"spwd" => r#"(struct (size 72) (name "spwd") (align 8) (field "sp_namp" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "sp_pwdp" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "sp_lstchg" (integral (signed #t) (endian little) (width 8))) (field "sp_min" (integral (signed #t) (endian little) (width 8))) (field "sp_max" (integral (signed #t) (endian little) (width 8))) (field "sp_warn" (integral (signed #t) (endian little) (width 8))) (field "sp_inact" (integral (signed #t) (endian little) (width 8))) (field "sp_expire" (integral (signed #t) (endian little) (width 8))) (field "sp_flag" (integral (signed #f) (endian little) (width 8))))"#,
"ssize_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"pthread_cond_t" => r#"(struct (size 0) (name "pthread_cond_t") (align 8))"#,
"uint16_t" => r#"(integral (signed #f) (endian little) (width 2))"#,
"Elf64_Off" => r#"(integral (signed #f) (endian little) (width 8))"#,
"posix_spawn_file_actions_t" => r#"(struct (size 0) (name "posix_spawn_file_actions_t") (align 1))"#,
"ntptimeval" => r#"(struct (size 72) (name "ntptimeval") (align 8) (field "timeval" (struct (size 16) (name "timeval") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_usec" (integral (signed #t) (endian little) (width 8))))) (field "maxerror" (integral (signed #t) (endian little) (width 8))) (field "esterror" (integral (signed #t) (endian little) (width 8))) (field "tai" (integral (signed #t) (endian little) (width 8))) (field "__glibc_reserved1" (integral (signed #t) (endian little) (width 8))) (field "__glibc_reserved2" (integral (signed #t) (endian little) (width 8))) (field "__glibc_reserved3" (integral (signed #t) (endian little) (width 8))) (field "__glibc_reserved4" (integral (signed #t) (endian little) (width 8))))"#,
"arpd_request" => r#"(struct (size 40) (name "arpd_request") (align 8) (field "req" (integral (signed #f) (endian little) (width 2))) (field "ip" (integral (signed #f) (endian little) (width 4))) (field "dev" (integral (signed #f) (endian little) (width 8))) (field "stamp" (integral (signed #f) (endian little) (width 8))) (field "updated" (integral (signed #f) (endian little) (width 8))) (field "ha" (array (length 7) (name "ha") (integral (signed #f) (endian little) (width 1)))))"#,
"ip_mreq_source" => r#"(struct (size 12) (name "ip_mreq_source") (align 4) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))))"#,
"sembuf" => r#"(struct (size 6) (name "sembuf") (align 2) (field "sem_num" (integral (signed #f) (endian little) (width 2))) (field "sem_op" (integral (signed #t) (endian little) (width 2))) (field "sem_flg" (integral (signed #t) (endian little) (width 2))))"#,
"ff_envelope" => r#"(struct (size 8) (name "ff_envelope") (align 2) (field "attack_length" (integral (signed #f) (endian little) (width 2))) (field "attack_level" (integral (signed #f) (endian little) (width 2))) (field "fade_length" (integral (signed #f) (endian little) (width 2))) (field "fade_level" (integral (signed #f) (endian little) (width 2))))"#,
"statx" => r#"(struct (size 256) (name "statx") (align 8) (field "stx_mask" (integral (signed #f) (endian little) (width 4))) (field "stx_blksize" (integral (signed #f) (endian little) (width 4))) (field "stx_attributes" (integral (signed #f) (endian little) (width 8))) (field "stx_nlink" (integral (signed #f) (endian little) (width 4))) (field "stx_uid" (integral (signed #f) (endian little) (width 4))) (field "stx_gid" (integral (signed #f) (endian little) (width 4))) (field "stx_mode" (integral (signed #f) (endian little) (width 2))) (field "__statx_pad1" (array (length 1) (name "__statx_pad1") (integral (signed #f) (endian little) (width 2)))) (field "stx_ino" (integral (signed #f) (endian little) (width 8))) (field "stx_size" (integral (signed #f) (endian little) (width 8))) (field "stx_blocks" (integral (signed #f) (endian little) (width 8))) (field "stx_attributes_mask" (integral (signed #f) (endian little) (width 8))) (field "statx_timestamp" (struct (size 16) (name "statx_timestamp") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_nsec" (integral (signed #f) (endian little) (width 4))) (field "__statx_timestamp_pad1" (array (length 1) (name "__statx_timestamp_pad1") (integral (signed #t) (endian little) (width 4)))))) (field "statx_timestamp" (struct (size 16) (name "statx_timestamp") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_nsec" (integral (signed #f) (endian little) (width 4))) (field "__statx_timestamp_pad1" (array (length 1) (name "__statx_timestamp_pad1") (integral (signed #t) (endian little) (width 4)))))) (field "statx_timestamp" (struct (size 16) (name "statx_timestamp") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_nsec" (integral (signed #f) (endian little) (width 4))) (field "__statx_timestamp_pad1" (array (length 1) (name "__statx_timestamp_pad1") (integral (signed #t) (endian little) (width 4)))))) (field "statx_timestamp" (struct (size 16) (name "statx_timestamp") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_nsec" (integral (signed #f) (endian little) (width 4))) (field "__statx_timestamp_pad1" (array (length 1) (name "__statx_timestamp_pad1") (integral (signed #t) (endian little) (width 4)))))) (field "stx_rdev_major" (integral (signed #f) (endian little) (width 4))) (field "stx_rdev_minor" (integral (signed #f) (endian little) (width 4))) (field "stx_dev_major" (integral (signed #f) (endian little) (width 4))) (field "stx_dev_minor" (integral (signed #f) (endian little) (width 4))) (field "__statx_pad2" (array (length 14) (name "__statx_pad2") (integral (signed #f) (endian little) (width 8)))))"#,
"ipc_perm" => r#"(struct (size 24) (name "ipc_perm") (align 4) (field "__key" (integral (signed #t) (endian little) (width 4))) (field "uid" (integral (signed #f) (endian little) (width 4))) (field "gid" (integral (signed #f) (endian little) (width 4))) (field "cuid" (integral (signed #f) (endian little) (width 4))) (field "cgid" (integral (signed #f) (endian little) (width 4))) (field "mode" (integral (signed #f) (endian little) (width 2))) (field "__seq" (integral (signed #f) (endian little) (width 2))))"#,
"rusage" => r#"(struct (size 144) (name "rusage") (align 8) (field "timeval" (struct (size 16) (name "timeval") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_usec" (integral (signed #t) (endian little) (width 8))))) (field "timeval" (struct (size 16) (name "timeval") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_usec" (integral (signed #t) (endian little) (width 8))))) (field "ru_maxrss" (integral (signed #t) (endian little) (width 8))) (field "ru_ixrss" (integral (signed #t) (endian little) (width 8))) (field "ru_idrss" (integral (signed #t) (endian little) (width 8))) (field "ru_isrss" (integral (signed #t) (endian little) (width 8))) (field "ru_minflt" (integral (signed #t) (endian little) (width 8))) (field "ru_majflt" (integral (signed #t) (endian little) (width 8))) (field "ru_nswap" (integral (signed #t) (endian little) (width 8))) (field "ru_inblock" (integral (signed #t) (endian little) (width 8))) (field "ru_oublock" (integral (signed #t) (endian little) (width 8))) (field "ru_msgsnd" (integral (signed #t) (endian little) (width 8))) (field "ru_msgrcv" (integral (signed #t) (endian little) (width 8))) (field "ru_nsignals" (integral (signed #t) (endian little) (width 8))) (field "ru_nvcsw" (integral (signed #t) (endian little) (width 8))) (field "ru_nivcsw" (integral (signed #t) (endian little) (width 8))))"#,
"pthread_mutexattr_t" => r#"(struct (size 0) (name "pthread_mutexattr_t") (align 4))"#,
"ip_mreq" => r#"(struct (size 8) (name "ip_mreq") (align 4) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))))"#,
"c_int" => r#"(integral (signed #t) (endian little) (width 4))"#,
"mqd_t" => r#"(integral (signed #t) (endian little) (width 4))"#,
"pthread_attr_t" => r#"(struct (size 0) (name "pthread_attr_t") (align 1))"#,
"glob64_t" => r#"(struct (size 32) (name "glob64_t") (align 8) (field "gl_pathc" (integral (signed #f) (endian little) (width 8))) (field "gl_pathv" (pointer (endian little) (width 8) (mutable #t) (points-to (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) 0)) (field "gl_offs" (integral (signed #f) (endian little) (width 8))) (field "gl_flags" (integral (signed #t) (endian little) (width 4))))"#,
"ff_effect" => r#"(struct (size 48) (name "ff_effect") (align 8) (field "type_" (integral (signed #f) (endian little) (width 2))) (field "id" (integral (signed #t) (endian little) (width 2))) (field "direction" (integral (signed #f) (endian little) (width 2))) (field "ff_trigger" (struct (size 4) (name "ff_trigger") (align 2) (field "button" (integral (signed #f) (endian little) (width 2))) (field "interval" (integral (signed #f) (endian little) (width 2))))) (field "ff_replay" (struct (size 4) (name "ff_replay") (align 2) (field "length" (integral (signed #f) (endian little) (width 2))) (field "delay" (integral (signed #f) (endian little) (width 2))))) (field "u" (array (length 4) (name "u") (integral (signed #f) (endian little) (width 8)))))"#,
"sockaddr" => r#"(struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))"#,
"msgqnum_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"arphdr" => r#"(struct (size 8) (name "arphdr") (align 2) (field "ar_hrd" (integral (signed #f) (endian little) (width 2))) (field "ar_pro" (integral (signed #f) (endian little) (width 2))) (field "ar_hln" (integral (signed #f) (endian little) (width 1))) (field "ar_pln" (integral (signed #f) (endian little) (width 1))) (field "ar_op" (integral (signed #f) (endian little) (width 2))))"#,
"ff_replay" => r#"(struct (size 4) (name "ff_replay") (align 2) (field "length" (integral (signed #f) (endian little) (width 2))) (field "delay" (integral (signed #f) (endian little) (width 2))))"#,
"itimerspec" => r#"(struct (size 32) (name "itimerspec") (align 8) (field "timespec" (struct (size 16) (name "timespec") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_nsec" (integral (signed #t) (endian little) (width 8))))) (field "timespec" (struct (size 16) (name "timespec") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_nsec" (integral (signed #t) (endian little) (width 8))))))"#,
"fanotify_response" => r#"(struct (size 8) (name "fanotify_response") (align 4) (field "fd" (integral (signed #t) (endian little) (width 4))) (field "response" (integral (signed #f) (endian little) (width 4))))"#,
"size_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"c_double" => r#"(float (format binary-64) (endian little))"#,
"suseconds_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"c_ulong" => r#"(integral (signed #f) (endian little) (width 8))"#,
"__u8" => r#"(integral (signed #f) (endian little) (width 1))"#,
"ff_constant_effect" => r#"(struct (size 10) (name "ff_constant_effect") (align 2) (field "level" (integral (signed #t) (endian little) (width 2))) (field "ff_envelope" (struct (size 8) (name "ff_envelope") (align 2) (field "attack_length" (integral (signed #f) (endian little) (width 2))) (field "attack_level" (integral (signed #f) (endian little) (width 2))) (field "fade_length" (integral (signed #f) (endian little) (width 2))) (field "fade_level" (integral (signed #f) (endian little) (width 2))))))"#,
"off_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"glob_t" => r#"(struct (size 32) (name "glob_t") (align 8) (field "gl_pathc" (integral (signed #f) (endian little) (width 8))) (field "gl_pathv" (pointer (endian little) (width 8) (mutable #t) (points-to (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) 0)) (field "gl_offs" (integral (signed #f) (endian little) (width 8))) (field "gl_flags" (integral (signed #t) (endian little) (width 4))))"#,
"DIR" => r#"(opaque)"#,
"_libc_fpxreg" => r#"(struct (size 10) (name "_libc_fpxreg") (align 2) (field "significand" (array (length 4) (name "significand") (integral (signed #f) (endian little) (width 2)))) (field "exponent" (integral (signed #f) (endian little) (width 2))))"#,
"useconds_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"Elf32_Word" => r#"(integral (signed #f) (endian little) (width 4))"#,
"signalfd_siginfo" => r#"(struct (size 104) (name "signalfd_siginfo") (align 8) (field "ssi_signo" (integral (signed #f) (endian little) (width 4))) (field "ssi_errno" (integral (signed #t) (endian little) (width 4))) (field "ssi_code" (integral (signed #t) (endian little) (width 4))) (field "ssi_pid" (integral (signed #f) (endian little) (width 4))) (field "ssi_uid" (integral (signed #f) (endian little) (width 4))) (field "ssi_fd" (integral (signed #t) (endian little) (width 4))) (field "ssi_tid" (integral (signed #f) (endian little) (width 4))) (field "ssi_band" (integral (signed #f) (endian little) (width 4))) (field "ssi_overrun" (integral (signed #f) (endian little) (width 4))) (field "ssi_trapno" (integral (signed #f) (endian little) (width 4))) (field "ssi_status" (integral (signed #t) (endian little) (width 4))) (field "ssi_int" (integral (signed #t) (endian little) (width 4))) (field "ssi_ptr" (integral (signed #f) (endian little) (width 8))) (field "ssi_utime" (integral (signed #f) (endian little) (width 8))) (field "ssi_stime" (integral (signed #f) (endian little) (width 8))) (field "ssi_addr" (integral (signed #f) (endian little) (width 8))) (field "ssi_addr_lsb" (integral (signed #f) (endian little) (width 2))) (field "ssi_syscall" (integral (signed #t) (endian little) (width 4))) (field "ssi_call_addr" (integral (signed #f) (endian little) (width 8))) (field "ssi_arch" (integral (signed #f) (endian little) (width 4))))"#,
"ptrdiff_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"ff_periodic_effect" => r#"(struct (size 32) (name "ff_periodic_effect") (align 8) (field "waveform" (integral (signed #f) (endian little) (width 2))) (field "period" (integral (signed #f) (endian little) (width 2))) (field "magnitude" (integral (signed #t) (endian little) (width 2))) (field "offset" (integral (signed #t) (endian little) (width 2))) (field "phase" (integral (signed #f) (endian little) (width 2))) (field "ff_envelope" (struct (size 8) (name "ff_envelope") (align 2) (field "attack_length" (integral (signed #f) (endian little) (width 2))) (field "attack_level" (integral (signed #f) (endian little) (width 2))) (field "fade_length" (integral (signed #f) (endian little) (width 2))) (field "fade_level" (integral (signed #f) (endian little) (width 2))))) (field "custom_len" (integral (signed #f) (endian little) (width 4))) (field "custom_data" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 2))) 0)))"#,
"msginfo" => r#"(struct (size 32) (name "msginfo") (align 4) (field "msgpool" (integral (signed #t) (endian little) (width 4))) (field "msgmap" (integral (signed #t) (endian little) (width 4))) (field "msgmax" (integral (signed #t) (endian little) (width 4))) (field "msgmnb" (integral (signed #t) (endian little) (width 4))) (field "msgmni" (integral (signed #t) (endian little) (width 4))) (field "msgssz" (integral (signed #t) (endian little) (width 4))) (field "msgtql" (integral (signed #t) (endian little) (width 4))) (field "msgseg" (integral (signed #f) (endian little) (width 2))))"#,
"sockaddr_in6" => r#"(struct (size 28) (name "sockaddr_in6") (align 4) (field "sin6_family" (integral (signed #f) (endian little) (width 2))) (field "sin6_port" (integral (signed #f) (endian little) (width 2))) (field "sin6_flowinfo" (integral (signed #f) (endian little) (width 4))) (field "in6_addr" (struct (size 16) (name "in6_addr") (align 4) (field "s6_addr" (array (length 16) (name "s6_addr") (integral (signed #f) (endian little) (width 1)))))) (field "sin6_scope_id" (integral (signed #f) (endian little) (width 4))))"#,
"utsname" => r#"(struct (size 390) (name "utsname") (align 1) (field "sysname" (array (length 65) (name "sysname") (integral (signed #t) (endian little) (width 1)))) (field "nodename" (array (length 65) (name "nodename") (integral (signed #t) (endian little) (width 1)))) (field "release" (array (length 65) (name "release") (integral (signed #t) (endian little) (width 1)))) (field "version" (array (length 65) (name "version") (integral (signed #t) (endian little) (width 1)))) (field "machine" (array (length 65) (name "machine") (integral (signed #t) (endian little) (width 1)))) (field "domainname" (array (length 65) (name "domainname") (integral (signed #t) (endian little) (width 1)))))"#,
"key_t" => r#"(integral (signed #t) (endian little) (width 4))"#,
"user" => r#"(struct (size 808) (name "user") (align 8) (field "user_regs_struct" (struct (size 216) (name "user_regs_struct") (align 8) (field "r15" (integral (signed #f) (endian little) (width 8))) (field "r14" (integral (signed #f) (endian little) (width 8))) (field "r13" (integral (signed #f) (endian little) (width 8))) (field "r12" (integral (signed #f) (endian little) (width 8))) (field "rbp" (integral (signed #f) (endian little) (width 8))) (field "rbx" (integral (signed #f) (endian little) (width 8))) (field "r11" (integral (signed #f) (endian little) (width 8))) (field "r10" (integral (signed #f) (endian little) (width 8))) (field "r9" (integral (signed #f) (endian little) (width 8))) (field "r8" (integral (signed #f) (endian little) (width 8))) (field "rax" (integral (signed #f) (endian little) (width 8))) (field "rcx" (integral (signed #f) (endian little) (width 8))) (field "rdx" (integral (signed #f) (endian little) (width 8))) (field "rsi" (integral (signed #f) (endian little) (width 8))) (field "rdi" (integral (signed #f) (endian little) (width 8))) (field "orig_rax" (integral (signed #f) (endian little) (width 8))) (field "rip" (integral (signed #f) (endian little) (width 8))) (field "cs" (integral (signed #f) (endian little) (width 8))) (field "eflags" (integral (signed #f) (endian little) (width 8))) (field "rsp" (integral (signed #f) (endian little) (width 8))) (field "ss" (integral (signed #f) (endian little) (width 8))) (field "fs_base" (integral (signed #f) (endian little) (width 8))) (field "gs_base" (integral (signed #f) (endian little) (width 8))) (field "ds" (integral (signed #f) (endian little) (width 8))) (field "es" (integral (signed #f) (endian little) (width 8))) (field "fs" (integral (signed #f) (endian little) (width 8))) (field "gs" (integral (signed #f) (endian little) (width 8))))) (field "u_fpvalid" (integral (signed #t) (endian little) (width 4))) (field "user_fpregs_struct" (struct (size 416) (name "user_fpregs_struct") (align 8) (field "cwd" (integral (signed #f) (endian little) (width 2))) (field "swd" (integral (signed #f) (endian little) (width 2))) (field "ftw" (integral (signed #f) (endian little) (width 2))) (field "fop" (integral (signed #f) (endian little) (width 2))) (field "rip" (integral (signed #f) (endian little) (width 8))) (field "rdp" (integral (signed #f) (endian little) (width 8))) (field "mxcsr" (integral (signed #f) (endian little) (width 4))) (field "mxcr_mask" (integral (signed #f) (endian little) (width 4))) (field "st_space" (array (length 32) (name "st_space") (integral (signed #f) (endian little) (width 4)))) (field "xmm_space" (array (length 64) (name "xmm_space") (integral (signed #f) (endian little) (width 4)))))) (field "u_tsize" (integral (signed #f) (endian little) (width 8))) (field "u_dsize" (integral (signed #f) (endian little) (width 8))) (field "u_ssize" (integral (signed #f) (endian little) (width 8))) (field "start_code" (integral (signed #f) (endian little) (width 8))) (field "start_stack" (integral (signed #f) (endian little) (width 8))) (field "signal" (integral (signed #t) (endian little) (width 8))) (field "u_ar0" (pointer (endian little) (width 8) (mutable #t) (points-to (struct (size 216) (name "user_regs_struct") (align 8) (field "r15" (integral (signed #f) (endian little) (width 8))) (field "r14" (integral (signed #f) (endian little) (width 8))) (field "r13" (integral (signed #f) (endian little) (width 8))) (field "r12" (integral (signed #f) (endian little) (width 8))) (field "rbp" (integral (signed #f) (endian little) (width 8))) (field "rbx" (integral (signed #f) (endian little) (width 8))) (field "r11" (integral (signed #f) (endian little) (width 8))) (field "r10" (integral (signed #f) (endian little) (width 8))) (field "r9" (integral (signed #f) (endian little) (width 8))) (field "r8" (integral (signed #f) (endian little) (width 8))) (field "rax" (integral (signed #f) (endian little) (width 8))) (field "rcx" (integral (signed #f) (endian little) (width 8))) (field "rdx" (integral (signed #f) (endian little) (width 8))) (field "rsi" (integral (signed #f) (endian little) (width 8))) (field "rdi" (integral (signed #f) (endian little) (width 8))) (field "orig_rax" (integral (signed #f) (endian little) (width 8))) (field "rip" (integral (signed #f) (endian little) (width 8))) (field "cs" (integral (signed #f) (endian little) (width 8))) (field "eflags" (integral (signed #f) (endian little) (width 8))) (field "rsp" (integral (signed #f) (endian little) (width 8))) (field "ss" (integral (signed #f) (endian little) (width 8))) (field "fs_base" (integral (signed #f) (endian little) (width 8))) (field "gs_base" (integral (signed #f) (endian little) (width 8))) (field "ds" (integral (signed #f) (endian little) (width 8))) (field "es" (integral (signed #f) (endian little) (width 8))) (field "fs" (integral (signed #f) (endian little) (width 8))) (field "gs" (integral (signed #f) (endian little) (width 8))))) 0)) (field "u_fpstate" (pointer (endian little) (width 8) (mutable #t) (points-to (struct (size 416) (name "user_fpregs_struct") (align 8) (field "cwd" (integral (signed #f) (endian little) (width 2))) (field "swd" (integral (signed #f) (endian little) (width 2))) (field "ftw" (integral (signed #f) (endian little) (width 2))) (field "fop" (integral (signed #f) (endian little) (width 2))) (field "rip" (integral (signed #f) (endian little) (width 8))) (field "rdp" (integral (signed #f) (endian little) (width 8))) (field "mxcsr" (integral (signed #f) (endian little) (width 4))) (field "mxcr_mask" (integral (signed #f) (endian little) (width 4))) (field "st_space" (array (length 32) (name "st_space") (integral (signed #f) (endian little) (width 4)))) (field "xmm_space" (array (length 64) (name "xmm_space") (integral (signed #f) (endian little) (width 4)))))) 0)) (field "magic" (integral (signed #f) (endian little) (width 8))) (field "u_comm" (array (length 32) (name "u_comm") (integral (signed #t) (endian little) (width 1)))) (field "u_debugreg" (array (length 8) (name "u_debugreg") (integral (signed #f) (endian little) (width 8)))))"#,
"gid_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"Elf32_Off" => r#"(integral (signed #f) (endian little) (width 4))"#,
"sock_extended_err" => r#"(struct (size 16) (name "sock_extended_err") (align 4) (field "ee_errno" (integral (signed #f) (endian little) (width 4))) (field "ee_origin" (integral (signed #f) (endian little) (width 1))) (field "ee_type" (integral (signed #f) (endian little) (width 1))) (field "ee_code" (integral (signed #f) (endian little) (width 1))) (field "ee_pad" (integral (signed #f) (endian little) (width 1))) (field "ee_info" (integral (signed #f) (endian little) (width 4))) (field "ee_data" (integral (signed #f) (endian little) (width 4))))"#,
"rlimit" => r#"(struct (size 16) (name "rlimit") (align 8) (field "rlim_cur" (integral (signed #f) (endian little) (width 8))) (field "rlim_max" (integral (signed #f) (endian little) (width 8))))"#,
"clockid_t" => r#"(integral (signed #t) (endian little) (width 4))"#,
"fpos64_t" => r#"(opaque)"#,
"uint32_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"in6_pktinfo" => r#"(struct (size 20) (name "in6_pktinfo") (align 4) (field "in6_addr" (struct (size 16) (name "in6_addr") (align 4) (field "s6_addr" (array (length 16) (name "s6_addr") (integral (signed #f) (endian little) (width 1)))))) (field "ipi6_ifindex" (integral (signed #f) (endian little) (width 4))))"#,
"in_port_t" => r#"(integral (signed #f) (endian little) (width 2))"#,
"sigset_t" => r#"(struct (size 0) (name "sigset_t") (align 1))"#,
"sched_param" => r#"(struct (size 4) (name "sched_param") (align 4) (field "sched_priority" (integral (signed #t) (endian little) (width 4))))"#,
"loff_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"locale_t" => r#"(pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)"#,
"blksize_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"fanotify_event_metadata" => r#"(struct (size 24) (name "fanotify_event_metadata") (align 8) (field "event_len" (integral (signed #f) (endian little) (width 4))) (field "vers" (integral (signed #f) (endian little) (width 1))) (field "reserved" (integral (signed #f) (endian little) (width 1))) (field "metadata_len" (integral (signed #f) (endian little) (width 2))) (field "mask" (integral (signed #f) (endian little) (width 8))) (field "fd" (integral (signed #t) (endian little) (width 4))) (field "pid" (integral (signed #t) (endian little) (width 4))))"#,
"sockaddr_storage" => r#"(struct (size 2) (name "sockaddr_storage") (align 2) (field "ss_family" (integral (signed #f) (endian little) (width 2))))"#,
"uintmax_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"dl_phdr_info" => r#"(struct (size 64) (name "dl_phdr_info") (align 8) (field "dlpi_addr" (integral (signed #f) (endian little) (width 8))) (field "dlpi_name" (pointer (endian little) (width 8) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "dlpi_phdr" (pointer (endian little) (width 8) (points-to (struct (size 56) (name "Elf64_Phdr") (align 8) (field "p_type" (integral (signed #f) (endian little) (width 4))) (field "p_flags" (integral (signed #f) (endian little) (width 4))) (field "p_offset" (integral (signed #f) (endian little) (width 8))) (field "p_vaddr" (integral (signed #f) (endian little) (width 8))) (field "p_paddr" (integral (signed #f) (endian little) (width 8))) (field "p_filesz" (integral (signed #f) (endian little) (width 8))) (field "p_memsz" (integral (signed #f) (endian little) (width 8))) (field "p_align" (integral (signed #f) (endian little) (width 8))))) 0)) (field "dlpi_phnum" (integral (signed #f) (endian little) (width 2))) (field "dlpi_adds" (integral (signed #f) (endian little) (width 8))) (field "dlpi_subs" (integral (signed #f) (endian little) (width 8))) (field "dlpi_tls_modid" (integral (signed #f) (endian little) (width 8))) (field "dlpi_tls_data" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)))"#,
"stack_t" => r#"(struct (size 24) (name "stack_t") (align 8) (field "ss_sp" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "ss_flags" (integral (signed #t) (endian little) (width 4))) (field "ss_size" (integral (signed #f) (endian little) (width 8))))"#,
"c_float" => r#"(float (format binary-32) (endian little))"#,
"arpreq" => r#"(struct (size 68) (name "arpreq") (align 4) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))) (field "arp_flags" (integral (signed #t) (endian little) (width 4))) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))) (field "arp_dev" (array (length 16) (name "arp_dev") (integral (signed #t) (endian little) (width 1)))))"#,
"dev_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"Elf64_Word" => r#"(integral (signed #f) (endian little) (width 4))"#,
"intmax_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"statx_timestamp" => r#"(struct (size 16) (name "statx_timestamp") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_nsec" (integral (signed #f) (endian little) (width 4))) (field "__statx_timestamp_pad1" (array (length 1) (name "__statx_timestamp_pad1") (integral (signed #t) (endian little) (width 4)))))"#,
"pthread_condattr_t" => r#"(struct (size 0) (name "pthread_condattr_t") (align 4))"#,
"stat" => r#"(struct (size 120) (name "stat") (align 8) (field "st_dev" (integral (signed #f) (endian little) (width 8))) (field "st_ino" (integral (signed #f) (endian little) (width 8))) (field "st_nlink" (integral (signed #f) (endian little) (width 8))) (field "st_mode" (integral (signed #f) (endian little) (width 4))) (field "st_uid" (integral (signed #f) (endian little) (width 4))) (field "st_gid" (integral (signed #f) (endian little) (width 4))) (field "st_rdev" (integral (signed #f) (endian little) (width 8))) (field "st_size" (integral (signed #t) (endian little) (width 8))) (field "st_blksize" (integral (signed #t) (endian little) (width 8))) (field "st_blocks" (integral (signed #t) (endian little) (width 8))) (field "st_atime" (integral (signed #t) (endian little) (width 8))) (field "st_atime_nsec" (integral (signed #t) (endian little) (width 8))) (field "st_mtime" (integral (signed #t) (endian little) (width 8))) (field "st_mtime_nsec" (integral (signed #t) (endian little) (width 8))) (field "st_ctime" (integral (signed #t) (endian little) (width 8))) (field "st_ctime_nsec" (integral (signed #t) (endian little) (width 8))))"#,
"timespec" => r#"(struct (size 16) (name "timespec") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_nsec" (integral (signed #t) (endian little) (width 8))))"#,
"stat64" => r#"(struct (size 120) (name "stat64") (align 8) (field "st_dev" (integral (signed #f) (endian little) (width 8))) (field "st_ino" (integral (signed #f) (endian little) (width 8))) (field "st_nlink" (integral (signed #f) (endian little) (width 8))) (field "st_mode" (integral (signed #f) (endian little) (width 4))) (field "st_uid" (integral (signed #f) (endian little) (width 4))) (field "st_gid" (integral (signed #f) (endian little) (width 4))) (field "st_rdev" (integral (signed #f) (endian little) (width 8))) (field "st_size" (integral (signed #t) (endian little) (width 8))) (field "st_blksize" (integral (signed #t) (endian little) (width 8))) (field "st_blocks" (integral (signed #t) (endian little) (width 8))) (field "st_atime" (integral (signed #t) (endian little) (width 8))) (field "st_atime_nsec" (integral (signed #t) (endian little) (width 8))) (field "st_mtime" (integral (signed #t) (endian little) (width 8))) (field "st_mtime_nsec" (integral (signed #t) (endian little) (width 8))) (field "st_ctime" (integral (signed #t) (endian little) (width 8))) (field "st_ctime_nsec" (integral (signed #t) (endian little) (width 8))))"#,
"nlattr" => r#"(struct (size 4) (name "nlattr") (align 2) (field "nla_len" (integral (signed #f) (endian little) (width 2))) (field "nla_type" (integral (signed #f) (endian little) (width 2))))"#,
"mmsghdr" => r#"(struct (size 64) (name "mmsghdr") (align 8) (field "msghdr" (struct (size 56) (name "msghdr") (align 8) (field "msg_name" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "msg_namelen" (integral (signed #f) (endian little) (width 4))) (field "msg_iov" (pointer (endian little) (width 8) (mutable #t) (points-to (struct (size 16) (name "iovec") (align 8) (field "iov_base" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "iov_len" (integral (signed #f) (endian little) (width 8))))) 0)) (field "msg_iovlen" (integral (signed #f) (endian little) (width 8))) (field "msg_control" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "msg_controllen" (integral (signed #f) (endian little) (width 8))) (field "msg_flags" (integral (signed #t) (endian little) (width 4))))) (field "msg_len" (integral (signed #f) (endian little) (width 4))))"#,
"fsid_t" => r#"(struct (size 0) (name "fsid_t") (align 1))"#,
"winsize" => r#"(struct (size 8) (name "winsize") (align 2) (field "ws_row" (integral (signed #f) (endian little) (width 2))) (field "ws_col" (integral (signed #f) (endian little) (width 2))) (field "ws_xpixel" (integral (signed #f) (endian little) (width 2))) (field "ws_ypixel" (integral (signed #f) (endian little) (width 2))))"#,
"ff_rumble_effect" => r#"(struct (size 4) (name "ff_rumble_effect") (align 2) (field "strong_magnitude" (integral (signed #f) (endian little) (width 2))) (field "weak_magnitude" (integral (signed #f) (endian little) (width 2))))"#,
"mallinfo" => r#"(struct (size 40) (name "mallinfo") (align 4) (field "arena" (integral (signed #t) (endian little) (width 4))) (field "ordblks" (integral (signed #t) (endian little) (width 4))) (field "smblks" (integral (signed #t) (endian little) (width 4))) (field "hblks" (integral (signed #t) (endian little) (width 4))) (field "hblkhd" (integral (signed #t) (endian little) (width 4))) (field "usmblks" (integral (signed #t) (endian little) (width 4))) (field "fsmblks" (integral (signed #t) (endian little) (width 4))) (field "uordblks" (integral (signed #t) (endian little) (width 4))) (field "fordblks" (integral (signed #t) (endian little) (width 4))) (field "keepcost" (integral (signed #t) (endian little) (width 4))))"#,
"Elf64_Phdr" => r#"(struct (size 56) (name "Elf64_Phdr") (align 8) (field "p_type" (integral (signed #f) (endian little) (width 4))) (field "p_flags" (integral (signed #f) (endian little) (width 4))) (field "p_offset" (integral (signed #f) (endian little) (width 8))) (field "p_vaddr" (integral (signed #f) (endian little) (width 8))) (field "p_paddr" (integral (signed #f) (endian little) (width 8))) (field "p_filesz" (integral (signed #f) (endian little) (width 8))) (field "p_memsz" (integral (signed #f) (endian little) (width 8))) (field "p_align" (integral (signed #f) (endian little) (width 8))))"#,
"siginfo_t" => r#"(struct (size 12) (name "siginfo_t") (align 4) (field "si_signo" (integral (signed #t) (endian little) (width 4))) (field "si_errno" (integral (signed #t) (endian little) (width 4))) (field "si_code" (integral (signed #t) (endian little) (width 4))))"#,
"ff_condition_effect" => r#"(struct (size 12) (name "ff_condition_effect") (align 2) (field "right_saturation" (integral (signed #f) (endian little) (width 2))) (field "left_saturation" (integral (signed #f) (endian little) (width 2))) (field "right_coeff" (integral (signed #t) (endian little) (width 2))) (field "left_coeff" (integral (signed #t) (endian little) (width 2))) (field "deadband" (integral (signed #f) (endian little) (width 2))) (field "center" (integral (signed #t) (endian little) (width 2))))"#,
"statfs" => r#"(struct (size 72) (name "statfs") (align 8) (field "f_type" (integral (signed #t) (endian little) (width 8))) (field "f_bsize" (integral (signed #t) (endian little) (width 8))) (field "f_blocks" (integral (signed #f) (endian little) (width 8))) (field "f_bfree" (integral (signed #f) (endian little) (width 8))) (field "f_bavail" (integral (signed #f) (endian little) (width 8))) (field "f_files" (integral (signed #f) (endian little) (width 8))) (field "f_ffree" (integral (signed #f) (endian little) (width 8))) (field "fsid_t" (struct (size 0) (name "fsid_t") (align 1))) (field "f_namelen" (integral (signed #t) (endian little) (width 8))) (field "f_frsize" (integral (signed #t) (endian little) (width 8))))"#,
"termios" => r#"(struct (size 60) (name "termios") (align 4) (field "c_iflag" (integral (signed #f) (endian little) (width 4))) (field "c_oflag" (integral (signed #f) (endian little) (width 4))) (field "c_cflag" (integral (signed #f) (endian little) (width 4))) (field "c_lflag" (integral (signed #f) (endian little) (width 4))) (field "c_line" (integral (signed #f) (endian little) (width 1))) (field "c_cc" (array (length 32) (name "c_cc") (integral (signed #f) (endian little) (width 1)))) (field "c_ispeed" (integral (signed #f) (endian little) (width 4))) (field "c_ospeed" (integral (signed #f) (endian little) (width 4))))"#,
"socklen_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"itimerval" => r#"(struct (size 32) (name "itimerval") (align 8) (field "timeval" (struct (size 16) (name "timeval") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_usec" (integral (signed #t) (endian little) (width 8))))) (field "timeval" (struct (size 16) (name "timeval") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_usec" (integral (signed #t) (endian little) (width 8))))))"#,
"regex_t" => r#"(struct (size 0) (name "regex_t") (align 1))"#,
"sockaddr_ll" => r#"(struct (size 20) (name "sockaddr_ll") (align 4) (field "sll_family" (integral (signed #f) (endian little) (width 2))) (field "sll_protocol" (integral (signed #f) (endian little) (width 2))) (field "sll_ifindex" (integral (signed #t) (endian little) (width 4))) (field "sll_hatype" (integral (signed #f) (endian little) (width 2))) (field "sll_pkttype" (integral (signed #f) (endian little) (width 1))) (field "sll_halen" (integral (signed #f) (endian little) (width 1))) (field "sll_addr" (array (length 8) (name "sll_addr") (integral (signed #f) (endian little) (width 1)))))"#,
"c_long" => r#"(integral (signed #t) (endian little) (width 8))"#,
"ip_mreqn" => r#"(struct (size 12) (name "ip_mreqn") (align 4) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))) (field "imr_ifindex" (integral (signed #t) (endian little) (width 4))))"#,
"__u64" => r#"(integral (signed #f) (endian little) (width 8))"#,
"sigval" => r#"(struct (size 8) (name "sigval") (align 8) (field "sival_ptr" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)))"#,
"_libc_fpstate" => r#"(struct (size 368) (name "_libc_fpstate") (align 8) (field "cwd" (integral (signed #f) (endian little) (width 2))) (field "swd" (integral (signed #f) (endian little) (width 2))) (field "ftw" (integral (signed #f) (endian little) (width 2))) (field "fop" (integral (signed #f) (endian little) (width 2))) (field "rip" (integral (signed #f) (endian little) (width 8))) (field "rdp" (integral (signed #f) (endian little) (width 8))) (field "mxcsr" (integral (signed #f) (endian little) (width 4))) (field "mxcr_mask" (integral (signed #f) (endian little) (width 4))) (field "_st" (array (length 8) (name "_st") (struct (size 10) (name "_libc_fpxreg") (align 2) (field "significand" (array (length 4) (name "significand") (integral (signed #f) (endian little) (width 2)))) (field "exponent" (integral (signed #f) (endian little) (width 2)))))) (field "_xmm" (array (length 16) (name "_xmm") (struct (size 16) (name "_libc_xmmreg") (align 4) (field "element" (array (length 4) (name "element") (integral (signed #f) (endian little) (width 4))))))))"#,
"Elf32_Ehdr" => r#"(struct (size 52) (name "Elf32_Ehdr") (align 4) (field "e_ident" (array (length 16) (name "e_ident") (integral (signed #f) (endian little) (width 1)))) (field "e_type" (integral (signed #f) (endian little) (width 2))) (field "e_machine" (integral (signed #f) (endian little) (width 2))) (field "e_version" (integral (signed #f) (endian little) (width 4))) (field "e_entry" (integral (signed #f) (endian little) (width 4))) (field "e_phoff" (integral (signed #f) (endian little) (width 4))) (field "e_shoff" (integral (signed #f) (endian little) (width 4))) (field "e_flags" (integral (signed #f) (endian little) (width 4))) (field "e_ehsize" (integral (signed #f) (endian little) (width 2))) (field "e_phentsize" (integral (signed #f) (endian little) (width 2))) (field "e_phnum" (integral (signed #f) (endian little) (width 2))) (field "e_shentsize" (integral (signed #f) (endian little) (width 2))) (field "e_shnum" (integral (signed #f) (endian little) (width 2))) (field "e_shstrndx" (integral (signed #f) (endian little) (width 2))))"#,
"uint64_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"pthread_mutex_t" => r#"(struct (size 0) (name "pthread_mutex_t") (align 8))"#,
"Elf64_Half" => r#"(integral (signed #f) (endian little) (width 2))"#,
"msghdr" => r#"(struct (size 56) (name "msghdr") (align 8) (field "msg_name" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "msg_namelen" (integral (signed #f) (endian little) (width 4))) (field "msg_iov" (pointer (endian little) (width 8) (mutable #t) (points-to (struct (size 16) (name "iovec") (align 8) (field "iov_base" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "iov_len" (integral (signed #f) (endian little) (width 8))))) 0)) (field "msg_iovlen" (integral (signed #f) (endian little) (width 8))) (field "msg_control" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "msg_controllen" (integral (signed #f) (endian little) (width 8))) (field "msg_flags" (integral (signed #t) (endian little) (width 4))))"#,
"sockaddr_alg" => r#"(struct (size 88) (name "sockaddr_alg") (align 4) (field "salg_family" (integral (signed #f) (endian little) (width 2))) (field "salg_type" (array (length 14) (name "salg_type") (integral (signed #f) (endian little) (width 1)))) (field "salg_feat" (integral (signed #f) (endian little) (width 4))) (field "salg_mask" (integral (signed #f) (endian little) (width 4))) (field "salg_name" (array (length 64) (name "salg_name") (integral (signed #f) (endian little) (width 1)))))"#,
"in_addr_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"pthread_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"pid_t" => r#"(integral (signed #t) (endian little) (width 4))"#,
"epoll_event" => r#"(struct (size 16) (name "epoll_event") (align 8) (field "events" (integral (signed #f) (endian little) (width 4))) (field "u64" (integral (signed #f) (endian little) (width 8))))"#,
"fsfilcnt_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"speed_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"if_nameindex" => r#"(struct (size 16) (name "if_nameindex") (align 8) (field "if_index" (integral (signed #f) (endian little) (width 4))) (field "if_name" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)))"#,
"pthread_rwlockattr_t" => r#"(struct (size 0) (name "pthread_rwlockattr_t") (align 8))"#,
"utmpx" => r#"(struct (size 364) (name "utmpx") (align 4) (field "ut_type" (integral (signed #t) (endian little) (width 2))) (field "ut_pid" (integral (signed #t) (endian little) (width 4))) (field "ut_line" (array (length 32) (name "ut_line") (integral (signed #t) (endian little) (width 1)))) (field "ut_id" (array (length 4) (name "ut_id") (integral (signed #t) (endian little) (width 1)))) (field "ut_user" (array (length 32) (name "ut_user") (integral (signed #t) (endian little) (width 1)))) (field "ut_host" (array (length 256) (name "ut_host") (integral (signed #t) (endian little) (width 1)))) (field "__exit_status" (struct (size 4) (name "__exit_status") (align 2) (field "e_termination" (integral (signed #t) (endian little) (width 2))) (field "e_exit" (integral (signed #t) (endian little) (width 2))))) (field "ut_session" (integral (signed #t) (endian little) (width 4))) (field "__timeval" (struct (size 8) (name "__timeval") (align 4) (field "tv_sec" (integral (signed #t) (endian little) (width 4))) (field "tv_usec" (integral (signed #t) (endian little) (width 4))))) (field "ut_addr_v6" (array (length 4) (name "ut_addr_v6") (integral (signed #t) (endian little) (width 4)))))"#,
"time_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"__timeval" => r#"(struct (size 8) (name "__timeval") (align 4) (field "tv_sec" (integral (signed #t) (endian little) (width 4))) (field "tv_usec" (integral (signed #t) (endian little) (width 4))))"#,
"int16_t" => r#"(integral (signed #t) (endian little) (width 2))"#,
"Elf64_Sxword" => r#"(integral (signed #t) (endian little) (width 8))"#,
"msglen_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"hostent" => r#"(struct (size 32) (name "hostent") (align 8) (field "h_name" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "h_aliases" (pointer (endian little) (width 8) (mutable #t) (points-to (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) 0)) (field "h_addrtype" (integral (signed #t) (endian little) (width 4))) (field "h_length" (integral (signed #t) (endian little) (width 4))) (field "h_addr_list" (pointer (endian little) (width 8) (mutable #t) (points-to (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) 0)))"#,
"dirent64" => r#"(struct (size 280) (name "dirent64") (align 8) (field "d_ino" (integral (signed #f) (endian little) (width 8))) (field "d_off" (integral (signed #t) (endian little) (width 8))) (field "d_reclen" (integral (signed #f) (endian little) (width 2))) (field "d_type" (integral (signed #f) (endian little) (width 1))) (field "d_name" (array (length 256) (name "d_name") (integral (signed #t) (endian little) (width 1)))))"#,
"ff_ramp_effect" => r#"(struct (size 12) (name "ff_ramp_effect") (align 2) (field "start_level" (integral (signed #t) (endian little) (width 2))) (field "end_level" (integral (signed #t) (endian little) (width 2))) (field "ff_envelope" (struct (size 8) (name "ff_envelope") (align 2) (field "attack_length" (integral (signed #f) (endian little) (width 2))) (field "attack_level" (integral (signed #f) (endian little) (width 2))) (field "fade_length" (integral (signed #f) (endian little) (width 2))) (field "fade_level" (integral (signed #f) (endian little) (width 2))))))"#,
"linger" => r#"(struct (size 8) (name "linger") (align 4) (field "l_onoff" (integral (signed #t) (endian little) (width 4))) (field "l_linger" (integral (signed #t) (endian little) (width 4))))"#,
"Elf64_Ehdr" => r#"(struct (size 64) (name "Elf64_Ehdr") (align 8) (field "e_ident" (array (length 16) (name "e_ident") (integral (signed #f) (endian little) (width 1)))) (field "e_type" (integral (signed #f) (endian little) (width 2))) (field "e_machine" (integral (signed #f) (endian little) (width 2))) (field "e_version" (integral (signed #f) (endian little) (width 4))) (field "e_entry" (integral (signed #f) (endian little) (width 8))) (field "e_phoff" (integral (signed #f) (endian little) (width 8))) (field "e_shoff" (integral (signed #f) (endian little) (width 8))) (field "e_flags" (integral (signed #f) (endian little) (width 4))) (field "e_ehsize" (integral (signed #f) (endian little) (width 2))) (field "e_phentsize" (integral (signed #f) (endian little) (width 2))) (field "e_phnum" (integral (signed #f) (endian little) (width 2))) (field "e_shentsize" (integral (signed #f) (endian little) (width 2))) (field "e_shnum" (integral (signed #f) (endian little) (width 2))) (field "e_shstrndx" (integral (signed #f) (endian little) (width 2))))"#,
"flock64" => r#"(struct (size 32) (name "flock64") (align 8) (field "l_type" (integral (signed #t) (endian little) (width 2))) (field "l_whence" (integral (signed #t) (endian little) (width 2))) (field "l_start" (integral (signed #t) (endian little) (width 8))) (field "l_len" (integral (signed #t) (endian little) (width 8))) (field "l_pid" (integral (signed #t) (endian little) (width 4))))"#,
"sockaddr_un" => r#"(struct (size 110) (name "sockaddr_un") (align 2) (field "sun_family" (integral (signed #f) (endian little) (width 2))) (field "sun_path" (array (length 108) (name "sun_path") (integral (signed #t) (endian little) (width 1)))))"#,
"lconv" => r#"(struct (size 96) (name "lconv") (align 8) (field "decimal_point" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "thousands_sep" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "grouping" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "int_curr_symbol" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "currency_symbol" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "mon_decimal_point" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "mon_thousands_sep" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "mon_grouping" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "positive_sign" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "negative_sign" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "int_frac_digits" (integral (signed #t) (endian little) (width 1))) (field "frac_digits" (integral (signed #t) (endian little) (width 1))) (field "p_cs_precedes" (integral (signed #t) (endian little) (width 1))) (field "p_sep_by_space" (integral (signed #t) (endian little) (width 1))) (field "n_cs_precedes" (integral (signed #t) (endian little) (width 1))) (field "n_sep_by_space" (integral (signed #t) (endian little) (width 1))) (field "p_sign_posn" (integral (signed #t) (endian little) (width 1))) (field "n_sign_posn" (integral (signed #t) (endian little) (width 1))) (field "int_p_cs_precedes" (integral (signed #t) (endian little) (width 1))) (field "int_p_sep_by_space" (integral (signed #t) (endian little) (width 1))) (field "int_n_cs_precedes" (integral (signed #t) (endian little) (width 1))) (field "int_n_sep_by_space" (integral (signed #t) (endian little) (width 1))) (field "int_p_sign_posn" (integral (signed #t) (endian little) (width 1))) (field "int_n_sign_posn" (integral (signed #t) (endian little) (width 1))))"#,
"sockaddr_in" => r#"(struct (size 16) (name "sockaddr_in") (align 4) (field "sin_family" (integral (signed #f) (endian little) (width 2))) (field "sin_port" (integral (signed #f) (endian little) (width 2))) (field "in_addr" (struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))) (field "sin_zero" (array (length 8) (name "sin_zero") (integral (signed #f) (endian little) (width 1)))))"#,
"mq_attr" => r#"(struct (size 32) (name "mq_attr") (align 8) (field "mq_flags" (integral (signed #t) (endian little) (width 8))) (field "mq_maxmsg" (integral (signed #t) (endian little) (width 8))) (field "mq_msgsize" (integral (signed #t) (endian little) (width 8))) (field "mq_curmsgs" (integral (signed #t) (endian little) (width 8))))"#,
"max_align_t" => r#"(struct (size 0) (name "max_align_t") (align 16))"#,
"nlmsghdr" => r#"(struct (size 16) (name "nlmsghdr") (align 4) (field "nlmsg_len" (integral (signed #f) (endian little) (width 4))) (field "nlmsg_type" (integral (signed #f) (endian little) (width 2))) (field "nlmsg_flags" (integral (signed #f) (endian little) (width 2))) (field "nlmsg_seq" (integral (signed #f) (endian little) (width 4))) (field "nlmsg_pid" (integral (signed #f) (endian little) (width 4))))"#,
"nl_pktinfo" => r#"(struct (size 4) (name "nl_pktinfo") (align 4) (field "group" (integral (signed #f) (endian little) (width 4))))"#,
"termios2" => r#"(struct (size 44) (name "termios2") (align 4) (field "c_iflag" (integral (signed #f) (endian little) (width 4))) (field "c_oflag" (integral (signed #f) (endian little) (width 4))) (field "c_cflag" (integral (signed #f) (endian little) (width 4))) (field "c_lflag" (integral (signed #f) (endian little) (width 4))) (field "c_line" (integral (signed #f) (endian little) (width 1))) (field "c_cc" (array (length 19) (name "c_cc") (integral (signed #f) (endian little) (width 1)))) (field "c_ispeed" (integral (signed #f) (endian little) (width 4))) (field "c_ospeed" (integral (signed #f) (endian little) (width 4))))"#,
"statvfs64" => r#"(struct (size 88) (name "statvfs64") (align 8) (field "f_bsize" (integral (signed #f) (endian little) (width 8))) (field "f_frsize" (integral (signed #f) (endian little) (width 8))) (field "f_blocks" (integral (signed #f) (endian little) (width 8))) (field "f_bfree" (integral (signed #f) (endian little) (width 8))) (field "f_bavail" (integral (signed #f) (endian little) (width 8))) (field "f_files" (integral (signed #f) (endian little) (width 8))) (field "f_ffree" (integral (signed #f) (endian little) (width 8))) (field "f_favail" (integral (signed #f) (endian little) (width 8))) (field "f_fsid" (integral (signed #f) (endian little) (width 8))) (field "f_flag" (integral (signed #f) (endian little) (width 8))) (field "f_namemax" (integral (signed #f) (endian little) (width 8))))"#,
"__s32" => r#"(integral (signed #t) (endian little) (width 4))"#,
"in6_rtmsg" => r#"(struct (size 0) (name "in6_rtmsg") (align 1))"#,
"nl_mmap_req" => r#"(struct (size 16) (name "nl_mmap_req") (align 4) (field "nm_block_size" (integral (signed #f) (endian little) (width 4))) (field "nm_block_nr" (integral (signed #f) (endian little) (width 4))) (field "nm_frame_size" (integral (signed #f) (endian little) (width 4))) (field "nm_frame_nr" (integral (signed #f) (endian little) (width 4))))"#,
"blkcnt_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"group" => r#"(struct (size 32) (name "group") (align 8) (field "gr_name" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "gr_passwd" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "gr_gid" (integral (signed #f) (endian little) (width 4))) (field "gr_mem" (pointer (endian little) (width 8) (mutable #t) (points-to (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) 0)))"#,
"rlim_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"Elf64_Sym" => r#"(struct (size 24) (name "Elf64_Sym") (align 8) (field "st_name" (integral (signed #f) (endian little) (width 4))) (field "st_info" (integral (signed #f) (endian little) (width 1))) (field "st_other" (integral (signed #f) (endian little) (width 1))) (field "st_shndx" (integral (signed #f) (endian little) (width 2))) (field "st_value" (integral (signed #f) (endian little) (width 8))) (field "st_size" (integral (signed #f) (endian little) (width 8))))"#,
"clock_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"sysinfo" => r#"(struct (size 112) (name "sysinfo") (align 8) (field "uptime" (integral (signed #t) (endian little) (width 8))) (field "loads" (array (length 3) (name "loads") (integral (signed #f) (endian little) (width 8)))) (field "totalram" (integral (signed #f) (endian little) (width 8))) (field "freeram" (integral (signed #f) (endian little) (width 8))) (field "sharedram" (integral (signed #f) (endian little) (width 8))) (field "bufferram" (integral (signed #f) (endian little) (width 8))) (field "totalswap" (integral (signed #f) (endian little) (width 8))) (field "freeswap" (integral (signed #f) (endian little) (width 8))) (field "procs" (integral (signed #f) (endian little) (width 2))) (field "pad" (integral (signed #f) (endian little) (width 2))) (field "totalhigh" (integral (signed #f) (endian little) (width 8))) (field "freehigh" (integral (signed #f) (endian little) (width 8))) (field "mem_unit" (integral (signed #f) (endian little) (width 4))) (field "_f" (array (name "_f") (integral (signed #t) (endian little) (width 1)))))"#,
"fsblkcnt_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"__exit_status" => r#"(struct (size 4) (name "__exit_status") (align 2) (field "e_termination" (integral (signed #t) (endian little) (width 2))) (field "e_exit" (integral (signed #t) (endian little) (width 2))))"#,
"c_void" => r#"(opaque)"#,
"cpu_set_t" => r#"(struct (size 0) (name "cpu_set_t") (align 1))"#,
"ipv6_mreq" => r#"(struct (size 20) (name "ipv6_mreq") (align 4) (field "in6_addr" (struct (size 16) (name "in6_addr") (align 4) (field "s6_addr" (array (length 16) (name "s6_addr") (integral (signed #f) (endian little) (width 1)))))) (field "ipv6mr_interface" (integral (signed #f) (endian little) (width 4))))"#,
"c_schar" => r#"(integral (signed #t) (endian little) (width 1))"#,
"user_fpregs_struct" => r#"(struct (size 416) (name "user_fpregs_struct") (align 8) (field "cwd" (integral (signed #f) (endian little) (width 2))) (field "swd" (integral (signed #f) (endian little) (width 2))) (field "ftw" (integral (signed #f) (endian little) (width 2))) (field "fop" (integral (signed #f) (endian little) (width 2))) (field "rip" (integral (signed #f) (endian little) (width 8))) (field "rdp" (integral (signed #f) (endian little) (width 8))) (field "mxcsr" (integral (signed #f) (endian little) (width 4))) (field "mxcr_mask" (integral (signed #f) (endian little) (width 4))) (field "st_space" (array (length 32) (name "st_space") (integral (signed #f) (endian little) (width 4)))) (field "xmm_space" (array (length 64) (name "xmm_space") (integral (signed #f) (endian little) (width 4)))))"#,
"__priority_which_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"nl_mmap_hdr" => r#"(struct (size 24) (name "nl_mmap_hdr") (align 4) (field "nm_status" (integral (signed #f) (endian little) (width 4))) (field "nm_len" (integral (signed #f) (endian little) (width 4))) (field "nm_group" (integral (signed #f) (endian little) (width 4))) (field "nm_pid" (integral (signed #f) (endian little) (width 4))) (field "nm_uid" (integral (signed #f) (endian little) (width 4))) (field "nm_gid" (integral (signed #f) (endian little) (width 4))))"#,
"input_absinfo" => r#"(struct (size 24) (name "input_absinfo") (align 4) (field "value" (integral (signed #t) (endian little) (width 4))) (field "minimum" (integral (signed #t) (endian little) (width 4))) (field "maximum" (integral (signed #t) (endian little) (width 4))) (field "fuzz" (integral (signed #t) (endian little) (width 4))) (field "flat" (integral (signed #t) (endian little) (width 4))) (field "resolution" (integral (signed #t) (endian little) (width 4))))"#,
"genlmsghdr" => r#"(struct (size 4) (name "genlmsghdr") (align 2) (field "cmd" (integral (signed #f) (endian little) (width 1))) (field "version" (integral (signed #f) (endian little) (width 1))) (field "reserved" (integral (signed #f) (endian little) (width 2))))"#,
"statvfs" => r#"(struct (size 88) (name "statvfs") (align 8) (field "f_bsize" (integral (signed #f) (endian little) (width 8))) (field "f_frsize" (integral (signed #f) (endian little) (width 8))) (field "f_blocks" (integral (signed #f) (endian little) (width 8))) (field "f_bfree" (integral (signed #f) (endian little) (width 8))) (field "f_bavail" (integral (signed #f) (endian little) (width 8))) (field "f_files" (integral (signed #f) (endian little) (width 8))) (field "f_ffree" (integral (signed #f) (endian little) (width 8))) (field "f_favail" (integral (signed #f) (endian little) (width 8))) (field "f_fsid" (integral (signed #f) (endian little) (width 8))) (field "f_flag" (integral (signed #f) (endian little) (width 8))) (field "f_namemax" (integral (signed #f) (endian little) (width 8))))"#,
"Elf64_Xword" => r#"(integral (signed #f) (endian little) (width 8))"#,
"arpreq_old" => r#"(struct (size 52) (name "arpreq_old") (align 4) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))) (field "arp_flags" (integral (signed #t) (endian little) (width 4))) (field "sockaddr" (struct (size 16) (name "sockaddr") (align 2) (field "sa_family" (integral (signed #f) (endian little) (width 2))) (field "sa_data" (array (length 14) (name "sa_data") (integral (signed #t) (endian little) (width 1)))))))"#,
"nl_item" => r#"(integral (signed #t) (endian little) (width 4))"#,
"sem_t" => r#"(struct (size 0) (name "sem_t") (align 8))"#,
"c_char" => r#"(integral (signed #t) (endian little) (width 1))"#,
"timeval" => r#"(struct (size 16) (name "timeval") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_usec" (integral (signed #t) (endian little) (width 8))))"#,
"regoff_t" => r#"(integral (signed #t) (endian little) (width 4))"#,
"inotify_event" => r#"(struct (size 16) (name "inotify_event") (align 4) (field "wd" (integral (signed #t) (endian little) (width 4))) (field "mask" (integral (signed #f) (endian little) (width 4))) (field "cookie" (integral (signed #f) (endian little) (width 4))) (field "len" (integral (signed #f) (endian little) (width 4))))"#,
"int64_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"idtype_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"Elf32_Shdr" => r#"(struct (size 40) (name "Elf32_Shdr") (align 4) (field "sh_name" (integral (signed #f) (endian little) (width 4))) (field "sh_type" (integral (signed #f) (endian little) (width 4))) (field "sh_flags" (integral (signed #f) (endian little) (width 4))) (field "sh_addr" (integral (signed #f) (endian little) (width 4))) (field "sh_offset" (integral (signed #f) (endian little) (width 4))) (field "sh_size" (integral (signed #f) (endian little) (width 4))) (field "sh_link" (integral (signed #f) (endian little) (width 4))) (field "sh_info" (integral (signed #f) (endian little) (width 4))) (field "sh_addralign" (integral (signed #f) (endian little) (width 4))) (field "sh_entsize" (integral (signed #f) (endian little) (width 4))))"#,
"mode_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"tm" => r#"(struct (size 56) (name "tm") (align 8) (field "tm_sec" (integral (signed #t) (endian little) (width 4))) (field "tm_min" (integral (signed #t) (endian little) (width 4))) (field "tm_hour" (integral (signed #t) (endian little) (width 4))) (field "tm_mday" (integral (signed #t) (endian little) (width 4))) (field "tm_mon" (integral (signed #t) (endian little) (width 4))) (field "tm_year" (integral (signed #t) (endian little) (width 4))) (field "tm_wday" (integral (signed #t) (endian little) (width 4))) (field "tm_yday" (integral (signed #t) (endian little) (width 4))) (field "tm_isdst" (integral (signed #t) (endian little) (width 4))) (field "tm_gmtoff" (integral (signed #t) (endian little) (width 8))) (field "tm_zone" (pointer (endian little) (width 8) (points-to (integral (signed #t) (endian little) (width 1))) 0)))"#,
"Elf32_Sym" => r#"(struct (size 16) (name "Elf32_Sym") (align 4) (field "st_name" (integral (signed #f) (endian little) (width 4))) (field "st_value" (integral (signed #f) (endian little) (width 4))) (field "st_size" (integral (signed #f) (endian little) (width 4))) (field "st_info" (integral (signed #f) (endian little) (width 1))) (field "st_other" (integral (signed #f) (endian little) (width 1))) (field "st_shndx" (integral (signed #f) (endian little) (width 2))))"#,
"nlmsgerr" => r#"(struct (size 20) (name "nlmsgerr") (align 4) (field "error" (integral (signed #t) (endian little) (width 4))) (field "nlmsghdr" (struct (size 16) (name "nlmsghdr") (align 4) (field "nlmsg_len" (integral (signed #f) (endian little) (width 4))) (field "nlmsg_type" (integral (signed #f) (endian little) (width 2))) (field "nlmsg_flags" (integral (signed #f) (endian little) (width 2))) (field "nlmsg_seq" (integral (signed #f) (endian little) (width 4))) (field "nlmsg_pid" (integral (signed #f) (endian little) (width 4))))))"#,
"Elf64_Section" => r#"(integral (signed #f) (endian little) (width 2))"#,
"uintptr_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"aiocb" => r#"(struct (size 64) (name "aiocb") (align 8) (field "aio_fildes" (integral (signed #t) (endian little) (width 4))) (field "aio_lio_opcode" (integral (signed #t) (endian little) (width 4))) (field "aio_reqprio" (integral (signed #t) (endian little) (width 4))) (field "aio_buf" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "aio_nbytes" (integral (signed #f) (endian little) (width 8))) (field "sigevent" (struct (size 24) (name "sigevent") (align 8) (field "sigval" (struct (size 8) (name "sigval") (align 8) (field "sival_ptr" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)))) (field "sigev_signo" (integral (signed #t) (endian little) (width 4))) (field "sigev_notify" (integral (signed #t) (endian little) (width 4))) (field "sigev_notify_thread_id" (integral (signed #t) (endian little) (width 4))))) (field "aio_offset" (integral (signed #t) (endian little) (width 8))))"#,
"sockaddr_nl" => r#"(struct (size 12) (name "sockaddr_nl") (align 4) (field "nl_family" (integral (signed #f) (endian little) (width 2))) (field "nl_pid" (integral (signed #f) (endian little) (width 4))) (field "nl_groups" (integral (signed #f) (endian little) (width 4))))"#,
"input_mask" => r#"(struct (size 16) (name "input_mask") (align 8) (field "type_" (integral (signed #f) (endian little) (width 4))) (field "codes_size" (integral (signed #f) (endian little) (width 4))) (field "codes_ptr" (integral (signed #f) (endian little) (width 8))))"#,
"rlim64_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"Elf32_Chdr" => r#"(struct (size 12) (name "Elf32_Chdr") (align 4) (field "ch_type" (integral (signed #f) (endian little) (width 4))) (field "ch_size" (integral (signed #f) (endian little) (width 4))) (field "ch_addralign" (integral (signed #f) (endian little) (width 4))))"#,
"uid_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"in6_addr" => r#"(struct (size 16) (name "in6_addr") (align 4) (field "s6_addr" (array (length 16) (name "s6_addr") (integral (signed #f) (endian little) (width 1)))))"#,
"input_id" => r#"(struct (size 8) (name "input_id") (align 2) (field "bustype" (integral (signed #f) (endian little) (width 2))) (field "vendor" (integral (signed #f) (endian little) (width 2))) (field "product" (integral (signed #f) (endian little) (width 2))) (field "version" (integral (signed #f) (endian little) (width 2))))"#,
"c_uchar" => r#"(integral (signed #f) (endian little) (width 1))"#,
"sa_family_t" => r#"(integral (signed #f) (endian little) (width 2))"#,
"shmid_ds" => r#"(struct (size 72) (name "shmid_ds") (align 8) (field "ipc_perm" (struct (size 24) (name "ipc_perm") (align 4) (field "__key" (integral (signed #t) (endian little) (width 4))) (field "uid" (integral (signed #f) (endian little) (width 4))) (field "gid" (integral (signed #f) (endian little) (width 4))) (field "cuid" (integral (signed #f) (endian little) (width 4))) (field "cgid" (integral (signed #f) (endian little) (width 4))) (field "mode" (integral (signed #f) (endian little) (width 2))) (field "__seq" (integral (signed #f) (endian little) (width 2))))) (field "shm_segsz" (integral (signed #f) (endian little) (width 8))) (field "shm_atime" (integral (signed #t) (endian little) (width 8))) (field "shm_dtime" (integral (signed #t) (endian little) (width 8))) (field "shm_ctime" (integral (signed #t) (endian little) (width 8))) (field "shm_cpid" (integral (signed #t) (endian little) (width 4))) (field "shm_lpid" (integral (signed #t) (endian little) (width 4))) (field "shm_nattch" (integral (signed #f) (endian little) (width 8))))"#,
"timex" => r#"(struct (size 208) (name "timex") (align 8) (field "modes" (integral (signed #f) (endian little) (width 4))) (field "offset" (integral (signed #t) (endian little) (width 8))) (field "freq" (integral (signed #t) (endian little) (width 8))) (field "maxerror" (integral (signed #t) (endian little) (width 8))) (field "esterror" (integral (signed #t) (endian little) (width 8))) (field "status" (integral (signed #t) (endian little) (width 4))) (field "constant" (integral (signed #t) (endian little) (width 8))) (field "precision" (integral (signed #t) (endian little) (width 8))) (field "tolerance" (integral (signed #t) (endian little) (width 8))) (field "timeval" (struct (size 16) (name "timeval") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_usec" (integral (signed #t) (endian little) (width 8))))) (field "tick" (integral (signed #t) (endian little) (width 8))) (field "ppsfreq" (integral (signed #t) (endian little) (width 8))) (field "jitter" (integral (signed #t) (endian little) (width 8))) (field "shift" (integral (signed #t) (endian little) (width 4))) (field "stabil" (integral (signed #t) (endian little) (width 8))) (field "jitcnt" (integral (signed #t) (endian little) (width 8))) (field "calcnt" (integral (signed #t) (endian little) (width 8))) (field "errcnt" (integral (signed #t) (endian little) (width 8))) (field "stbcnt" (integral (signed #t) (endian little) (width 8))) (field "tai" (integral (signed #t) (endian little) (width 4))) (field "__unused1" (integral (signed #t) (endian little) (width 4))) (field "__unused2" (integral (signed #t) (endian little) (width 4))) (field "__unused3" (integral (signed #t) (endian little) (width 4))) (field "__unused4" (integral (signed #t) (endian little) (width 4))) (field "__unused5" (integral (signed #t) (endian little) (width 4))) (field "__unused6" (integral (signed #t) (endian little) (width 4))) (field "__unused7" (integral (signed #t) (endian little) (width 4))) (field "__unused8" (integral (signed #t) (endian little) (width 4))) (field "__unused9" (integral (signed #t) (endian little) (width 4))) (field "__unused10" (integral (signed #t) (endian little) (width 4))) (field "__unused11" (integral (signed #t) (endian little) (width 4))))"#,
"c_short" => r#"(integral (signed #t) (endian little) (width 2))"#,
"shmatt_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"iovec" => r#"(struct (size 16) (name "iovec") (align 8) (field "iov_base" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)) (field "iov_len" (integral (signed #f) (endian little) (width 8))))"#,
"Elf32_Section" => r#"(integral (signed #f) (endian little) (width 2))"#,
"nlink_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"input_event" => r#"(struct (size 24) (name "input_event") (align 8) (field "timeval" (struct (size 16) (name "timeval") (align 8) (field "tv_sec" (integral (signed #t) (endian little) (width 8))) (field "tv_usec" (integral (signed #t) (endian little) (width 8))))) (field "type_" (integral (signed #f) (endian little) (width 2))) (field "code" (integral (signed #f) (endian little) (width 2))) (field "value" (integral (signed #t) (endian little) (width 4))))"#,
"c_ulonglong" => r#"(integral (signed #f) (endian little) (width 8))"#,
"fpos_t" => r#"(opaque)"#,
"Elf64_Shdr" => r#"(struct (size 64) (name "Elf64_Shdr") (align 8) (field "sh_name" (integral (signed #f) (endian little) (width 4))) (field "sh_type" (integral (signed #f) (endian little) (width 4))) (field "sh_flags" (integral (signed #f) (endian little) (width 8))) (field "sh_addr" (integral (signed #f) (endian little) (width 8))) (field "sh_offset" (integral (signed #f) (endian little) (width 8))) (field "sh_size" (integral (signed #f) (endian little) (width 8))) (field "sh_link" (integral (signed #f) (endian little) (width 4))) (field "sh_info" (integral (signed #f) (endian little) (width 4))) (field "sh_addralign" (integral (signed #f) (endian little) (width 8))) (field "sh_entsize" (integral (signed #f) (endian little) (width 8))))"#,
"blkcnt64_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"in_addr" => r#"(struct (size 4) (name "in_addr") (align 4) (field "s_addr" (integral (signed #f) (endian little) (width 4))))"#,
"pthread_key_t" => r#"(integral (signed #f) (endian little) (width 4))"#,
"__s16" => r#"(integral (signed #t) (endian little) (width 2))"#,
"mntent" => r#"(struct (size 40) (name "mntent") (align 8) (field "mnt_fsname" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "mnt_dir" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "mnt_type" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "mnt_opts" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "mnt_freq" (integral (signed #t) (endian little) (width 4))) (field "mnt_passno" (integral (signed #t) (endian little) (width 4))))"#,
"dqblk" => r#"(struct (size 72) (name "dqblk") (align 8) (field "dqb_bhardlimit" (integral (signed #f) (endian little) (width 8))) (field "dqb_bsoftlimit" (integral (signed #f) (endian little) (width 8))) (field "dqb_curspace" (integral (signed #f) (endian little) (width 8))) (field "dqb_ihardlimit" (integral (signed #f) (endian little) (width 8))) (field "dqb_isoftlimit" (integral (signed #f) (endian little) (width 8))) (field "dqb_curinodes" (integral (signed #f) (endian little) (width 8))) (field "dqb_btime" (integral (signed #f) (endian little) (width 8))) (field "dqb_itime" (integral (signed #f) (endian little) (width 8))) (field "dqb_valid" (integral (signed #f) (endian little) (width 4))))"#,
"int8_t" => r#"(integral (signed #t) (endian little) (width 1))"#,
"sigevent" => r#"(struct (size 24) (name "sigevent") (align 8) (field "sigval" (struct (size 8) (name "sigval") (align 8) (field "sival_ptr" (pointer (endian little) (width 8) (mutable #t) (points-to (opaque)) 0)))) (field "sigev_signo" (integral (signed #t) (endian little) (width 4))) (field "sigev_notify" (integral (signed #t) (endian little) (width 4))) (field "sigev_notify_thread_id" (integral (signed #t) (endian little) (width 4))))"#,
"af_alg_iv" => r#"(struct (size 4) (name "af_alg_iv") (align 4) (field "ivlen" (integral (signed #f) (endian little) (width 4))) (field "iv" (array (name "iv") (integral (signed #f) (endian little) (width 1)))))"#,
"sockaddr_vm" => r#"(struct (size 16) (name "sockaddr_vm") (align 4) (field "svm_family" (integral (signed #f) (endian little) (width 2))) (field "svm_reserved1" (integral (signed #f) (endian little) (width 2))) (field "svm_port" (integral (signed #f) (endian little) (width 4))) (field "svm_cid" (integral (signed #f) (endian little) (width 4))) (field "svm_zero" (array (length 4) (name "svm_zero") (integral (signed #f) (endian little) (width 1)))))"#,
"packet_mreq" => r#"(struct (size 16) (name "packet_mreq") (align 4) (field "mr_ifindex" (integral (signed #t) (endian little) (width 4))) (field "mr_type" (integral (signed #f) (endian little) (width 2))) (field "mr_alen" (integral (signed #f) (endian little) (width 2))) (field "mr_address" (array (length 8) (name "mr_address") (integral (signed #f) (endian little) (width 1)))))"#,
"c_longlong" => r#"(integral (signed #t) (endian little) (width 8))"#,
"Elf32_Half" => r#"(integral (signed #f) (endian little) (width 2))"#,
"posix_spawnattr_t" => r#"(struct (size 0) (name "posix_spawnattr_t") (align 1))"#,
"uint8_t" => r#"(integral (signed #f) (endian little) (width 1))"#,
"nfds_t" => r#"(integral (signed #f) (endian little) (width 8))"#,
"user_regs_struct" => r#"(struct (size 216) (name "user_regs_struct") (align 8) (field "r15" (integral (signed #f) (endian little) (width 8))) (field "r14" (integral (signed #f) (endian little) (width 8))) (field "r13" (integral (signed #f) (endian little) (width 8))) (field "r12" (integral (signed #f) (endian little) (width 8))) (field "rbp" (integral (signed #f) (endian little) (width 8))) (field "rbx" (integral (signed #f) (endian little) (width 8))) (field "r11" (integral (signed #f) (endian little) (width 8))) (field "r10" (integral (signed #f) (endian little) (width 8))) (field "r9" (integral (signed #f) (endian little) (width 8))) (field "r8" (integral (signed #f) (endian little) (width 8))) (field "rax" (integral (signed #f) (endian little) (width 8))) (field "rcx" (integral (signed #f) (endian little) (width 8))) (field "rdx" (integral (signed #f) (endian little) (width 8))) (field "rsi" (integral (signed #f) (endian little) (width 8))) (field "rdi" (integral (signed #f) (endian little) (width 8))) (field "orig_rax" (integral (signed #f) (endian little) (width 8))) (field "rip" (integral (signed #f) (endian little) (width 8))) (field "cs" (integral (signed #f) (endian little) (width 8))) (field "eflags" (integral (signed #f) (endian little) (width 8))) (field "rsp" (integral (signed #f) (endian little) (width 8))) (field "ss" (integral (signed #f) (endian little) (width 8))) (field "fs_base" (integral (signed #f) (endian little) (width 8))) (field "gs_base" (integral (signed #f) (endian little) (width 8))) (field "ds" (integral (signed #f) (endian little) (width 8))) (field "es" (integral (signed #f) (endian little) (width 8))) (field "fs" (integral (signed #f) (endian little) (width 8))) (field "gs" (integral (signed #f) (endian little) (width 8))))"#,
"greg_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"c_ushort" => r#"(integral (signed #f) (endian little) (width 2))"#,
"passwd" => r#"(struct (size 48) (name "passwd") (align 8) (field "pw_name" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "pw_passwd" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "pw_uid" (integral (signed #f) (endian little) (width 4))) (field "pw_gid" (integral (signed #f) (endian little) (width 4))) (field "pw_gecos" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "pw_dir" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)) (field "pw_shell" (pointer (endian little) (width 8) (mutable #t) (points-to (integral (signed #t) (endian little) (width 1))) 0)))"#,
"off64_t" => r#"(integral (signed #t) (endian little) (width 8))"#,
"ucred" => r#"(struct (size 12) (name "ucred") (align 4) (field "pid" (integral (signed #t) (endian little) (width 4))) (field "uid" (integral (signed #f) (endian little) (width 4))) (field "gid" (integral (signed #f) (endian little) (width 4))))"#,

				_ => unreachable!("unknown command")
			});
		}
