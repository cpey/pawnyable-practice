## run_cmd()

~~~c
File: kernel/reboot.c

795  static int run_cmd(const char *cmd)
796  {
797  	char **argv;
798  	static char *envp[] = {
799  		"HOME=/",
800  		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
801  		NULL
802  	};
803  	int ret;
804  	argv = argv_split(GFP_KERNEL, cmd, NULL);
805  	if (argv) {
806  		ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
807  		argv_free(argv);
808  	} else {
809  		ret = -ENOMEM;
810  	}
811  
812  	return ret;
813  }
~~~

## orderly_reboot()

> **_NOTE:_** `reboot_cmd` string is declared constant, which results on a page
> fault when trying to overwrite.

~~~c
File: kernel/reboot.c

793  static const char reboot_cmd[] = "/sbin/reboot";
...
815  static int __orderly_reboot(void)
816  {
817  	int ret;
818  
819  	ret = run_cmd(reboot_cmd);
820  
821  	if (ret) {
822  		pr_warn("Failed to start orderly reboot: forcing the issue\n");
823  		emergency_sync();
824  		kernel_restart(NULL);
825  	}
826  
827  	return ret;
828  }
...
875  static void reboot_work_func(struct work_struct *work)
876  {
877  	__orderly_reboot();
878  }
879  
880  static DECLARE_WORK(reboot_work, reboot_work_func);
...
888  void orderly_reboot(void)
889  {
890  	schedule_work(&reboot_work);
891  }
892  EXPORT_SYMBOL_GPL(orderly_reboot);
~~~


## orderly_poweroff()

~~~c
File: kernel/reboot.c

792  static char poweroff_cmd[POWEROFF_CMD_PATH_LEN] = "/sbin/poweroff";
...
830  static int __orderly_poweroff(bool force)
831  {
832     int ret;
833  
834     ret = run_cmd(poweroff_cmd);
835  
836     if (ret && force) {
837         pr_warn("Failed to start orderly shutdown: forcing the issue\n");
...
844         emergency_sync();
845         kernel_power_off();
846     }
847  
848     return ret;
849  }
...
853  static void poweroff_work_func(struct work_struct *work)
854  {
855     __orderly_poweroff(poweroff_force);
856  }
857
858  static DECLARE_WORK(poweroff_work, poweroff_work_func);
...
867  void orderly_poweroff(bool force)
868  {
869     if (force) /* do not override the pending "true" */
870         poweroff_force = true;
871     schedule_work(&poweroff_work);
872  }
~~~
