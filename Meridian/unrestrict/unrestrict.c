#import <sys/param.h>
#import <mach/mach.h>
#import <sys/stat.h>
#import <os/log.h>
#import <dirent.h>
#import "kern_utils.h"
#import "common.h"

FILE *log_file = NULL;
#define PROC_PIDPATHINFO_MAXSIZE  (4 * MAXPATHLEN)

#define JAILBREAKD_COMMAND_ENTITLE 1
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT 2
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY 3
#define JAILBREAKD_COMMAND_FIXUP_SETUID 4

#define FLAG_PLATFORMIZE (1 << 1)

const char *blacklist[] = {
    "diagnosticd",    // syslog
    "logd",   	// logd - things that log when this is starting end badly so...
    "jailbreakd",               // gotta call to this
    NULL
};

bool is_blacklisted(const char *proc) {
	for (const char **entry = blacklist; *entry; entry++) {
		if (strstr(proc, *entry)) {
			DEBUGLOG("blacklisted");
			return true;
		}
	}
	DEBUGLOG("not blacklisted");
	return false;
}

bool MSunrestrict0(mach_port_t task) {
	bool do_sandbox = false;
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	bzero(pathbuf, sizeof(pathbuf));

	pid_t ourpid;
	if ( (pid_for_task(task, &ourpid) != 0) || ourpid <= 1) {
		return true;
	}
	proc_pidpath(ourpid, pathbuf, sizeof(pathbuf));

	if (strcmp(pathbuf, "/usr/libexec/xpcproxy")==0) {
		return true;
	}

	if (!is_blacklisted(pathbuf)) {
		DEBUGLOG("%s: (%d) platformizing", pathbuf, ourpid);
		platformize(ourpid);
		DEBUGLOG("%s: (%d) fixing setuid", pathbuf, ourpid);
		fixupsetuid(ourpid);
		DEBUGLOG("%s: (%d) complete", pathbuf, ourpid);
	} else {
		DEBUGLOG("%s: blacklisted", pathbuf);
	}
	return true;
}
