# Finding the caller to __request_module

~~~sh
/ # grep request_module /proc/kallsyms
ffffffff81076fc0 T __request_module
ffffffff81258960 T blk_request_module
ffffffff8160065f t __request_module.cold
~~~

~~~gdb
pwndbg> p $rip
$2 = (void (*)()) 0xffffffff81076fc0
pwndbg> backtrace
#0  0xffffffff81076fc0 in ?? ()
#1  0xffffffff81151443 in ?? ()  <-- bprm_execve
#2  0x0000004900477ec8 in ?? ()
#3  0x0000000600000000 in ?? ()
#4  0xffff8880031282a8 in ?? ()
#5  0xffff8880031283a8 in ?? ()
#6  0x0000000000000005 in ?? ()
#7  0x0000000000000000 in ?? ()
~~~

~~~sh
/ # grep ffffffff81151 /proc/kallsyms
ffffffff81151120 T open_exec
ffffffff81151170 t bprm_execve         <--
ffffffff81151700 t do_execveat_common
...
~~~

~~~gdb
pwndbg> p $rip
$2 = (void (*)()) 0xffffffff81151170
pwndbg>
#0  0xffffffff81151170 in ?? ()
#1  0xffffffff81151845 in ?? ()
#2  0x0000000000000000 in ?? ()
~~~

~~~sh
/ # grep ffffffff811518 /proc/kallsyms
ffffffff811518b0 T path_noexec
ffffffff811518d0 T __set_task_comm
/ # grep ffffffff811517 /proc/kallsyms
ffffffff81151700 t do_execveat_common  <---
~~~

# Kernel trying to load a kernel module

~~~c
File: kernel/kmod.c

124  int __request_module(bool wait, const char *fmt, ...)
125  {
126     va_list args;
127     char module_name[MODULE_NAME_LEN];
128     int ret;
...
138     if (!modprobe_path[0])
139         return -ENOENT;
140  
141     va_start(args, fmt);
142     ret = vsnprintf(module_name, MODULE_NAME_LEN, fmt, args);
143     va_end(args);
...
147     ret = security_kernel_module_request(module_name);
148     if (ret)
149         return ret;
...
170     ret = call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC);
...
~~~

~~~c
File: kernel/kmod.c

69  static int call_modprobe(char *module_name, int wait)
70  {
71  	struct subprocess_info *info;
72  	static char *envp[] = {
73  		"HOME=/",
74  		"TERM=linux",
75  		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
76  		NULL
77  	};
78  
79  	char **argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);
...
83  	module_name = kstrdup(module_name, GFP_KERNEL);
84  	if (!module_name)
85  		goto free_argv;
86  
87  	argv[0] = modprobe_path;                        <--- target
88  	argv[1] = "-q";
89  	argv[2] = "--";
90  	argv[3] = module_name;	/* check free_modprobe_argv() */
91  	argv[4] = NULL;
92  
93  	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
94  					 NULL, free_modprobe_argv, NULL);
...
98  	return call_usermodehelper_exec(info, wait | UMH_KILLABLE);
...
~~~

~~~c
File: include/linux/umh.h

19  struct subprocess_info {
20  	struct work_struct work;
21  	struct completion *complete;
22  	const char *path;
23  	char **argv;
24  	char **envp;
25  	int wait;
26  	int retval;
27  	int (*init)(struct subprocess_info *info, struct cred *new);
28  	void (*cleanup)(struct subprocess_info *info);
29  	void *data;
30  } __randomize_layout;
~~~

~~~c
File: kernel/umh.c

358  struct subprocess_info *call_usermodehelper_setup(const char *path, char **argv,
359  		char **envp, gfp_t gfp_mask,
360  		int (*init)(struct subprocess_info *info, struct cred *new),
361  		void (*cleanup)(struct subprocess_info *info),
362  		void *data)
363  {
364  	struct subprocess_info *sub_info;
365  	sub_info = kzalloc(sizeof(struct subprocess_info), gfp_mask);
...
369  	INIT_WORK(&sub_info->work, call_usermodehelper_exec_work);
370  
371  #ifdef CONFIG_STATIC_USERMODEHELPER
372  	sub_info->path = CONFIG_STATIC_USERMODEHELPER_PATH;
373  #else
374  	sub_info->path = path;
375  #endif
376  	sub_info->argv = argv;
377  	sub_info->envp = envp;
378  
379  	sub_info->cleanup = cleanup;
380  	sub_info->init = init;
381  	sub_info->data = data;
382    out:
383  	return sub_info;
384  }
~~~

~~~c
File: kernel/umh.c

404  int call_usermodehelper_exec(struct subprocess_info *sub_info, int wait)
405  {
...
433     sub_info->wait = wait;
...
435  	queue_work(system_unbound_wq, &sub_info->work);
...
450  	wait_for_completion(&done);
451  wait_done:
452  	retval = sub_info->retval;
...
457  	return retval;
458  }
~~~

~~~c
File: kernel/umh.c

160  static void call_usermodehelper_exec_work(struct work_struct *work)
161  {
162  	struct subprocess_info *sub_info =
163  		container_of(work, struct subprocess_info, work);
164  
165  	if (sub_info->wait & UMH_WAIT_PROC) {
166  		call_usermodehelper_exec_sync(sub_info);
167  	} else {
168  		pid_t pid;
169  		/*
170  		 * Use CLONE_PARENT to reparent it to kthreadd; we do not
171  		 * want to pollute current->children, and we need a parent
172  		 * that always ignores SIGCHLD to ensure auto-reaping.
173  		 */
174  		pid = user_mode_thread(call_usermodehelper_exec_async, sub_info,
175  				       CLONE_PARENT | SIGCHLD);
176  		if (pid < 0) {
177  			sub_info->retval = pid;
178  			umh_complete(sub_info);
179  		}
180  	}
181  }
~~~

~~~c
File: kernel/umh.c

63  /*
64   * This is the task which runs the usermode application
65   */
66  static int call_usermodehelper_exec_async(void *data)
67  {
68      struct subprocess_info *sub_info = data;
69      struct cred *new;
70      int retval;
...
91      new = prepare_kernel_cred(current);
96      new->cap_bset = cap_intersect(usermodehelper_bset, new->cap_bset);
97      new->cap_inheritable = cap_intersect(usermodehelper_inheritable,
98                           new->cap_inheritable);
...
109     commit_creds(new);
...
112     retval = kernel_execve(sub_info->path,
113                    (const char *const *)sub_info->argv,
114                    (const char *const *)sub_info->envp);
...
~~~
