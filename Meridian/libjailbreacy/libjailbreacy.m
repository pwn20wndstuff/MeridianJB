#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <sys/stat.h>
#import <os/log.h>
#import <dirent.h>
#import "jailbreak_daemonUser.h"
#import "libjailbreak/libjailbreak.h"

#define PROC_PIDPATHINFO_MAXSIZE  (4 * MAXPATHLEN)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

#ifdef DEBUG
#define DEBUGLOG(fmt, args...) os_log(OS_LOG_DEFAULT, "libjailbreacy: " fmt, ##args)
#else
#define DEBUGLOG(fmt, args...) do {} while (0)
#endif // ifdef DEBUG

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

kern_return_t bootstrap_look_up(mach_port_t port, const char *service, mach_port_t *server_port);

mach_port_t jbd_port = MACH_PORT_NULL;

__attribute__ ((constructor))
static void ctor(int argc, char **argv) {
	bool do_sandbox = false;
	bool do_setuid = false;
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	bzero(pathbuf, sizeof(pathbuf));

	pid_t ourpid = getpid();
	proc_pidpath(getpid(), pathbuf, sizeof(pathbuf));

	if (strcmp(pathbuf, "/usr/libexec/xpcproxy")==0) {
		if (argc>1)
			DEBUGLOG("(%d) xpcproxy %{public}s", ourpid, argv[1]);
		return;
	}

	struct stat st;
	if (stat(pathbuf, &st)) {
		DEBUGLOG("Unable to stat myself at %{public}s falling back to calling jbd", pathbuf);
		do_setuid = true;
	} else {
		if ( (st.st_mode & S_ISUID) || (st.st_mode & S_ISGID) ) {
			DEBUGLOG("%{public}s is setuid or setgid", pathbuf);
			do_setuid = true;
		}
	}

	if (!is_blacklisted(pathbuf)) {
		DIR *dh = opendir("/Library");
		if (dh==NULL) {
			DEBUGLOG("unable to opendir /Library");
			do_sandbox = true;
		} else {
			DEBUGLOG("successfully opendir /Library");
			do_sandbox = false;
			closedir(dh);
		}
	} else {
		DEBUGLOG("%{public}s blacklisted", pathbuf);
	}

	if (do_sandbox || do_setuid) {
		DEBUGLOG("(%d) starting (%{public}s)", ourpid, argv[0]);
		jb_connection_t conn = jb_connect();
		if (conn == NULL) {
			DEBUGLOG("(%d) unable to connect to jbd", ourpid);
			return;
		}
		DEBUGLOG("(%d) connected", ourpid);

		if (ourpid > 1) {
			if (do_sandbox) {
				DEBUGLOG("(%d) Entitling", ourpid);
				jb_entitle_now(conn, ourpid, FLAG_SANDBOX);
			}
			if (do_setuid) {
				DEBUGLOG("(%d) fixing setuid", ourpid);
				jb_fix_setuid_now(conn, ourpid);
			}
		}
		DEBUGLOG("(%d) disconnecting", ourpid);
		jb_disconnect(conn);
		DEBUGLOG("(%d) complete", ourpid);
	}
	return;
}
