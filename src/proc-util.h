/** @file proc-util.h */
#pragma once

#include <limits.h>
#include <signal.h>
#include <sys/types.h>

/**
 * Check if the process with given PID is still alive and not in the
 * process of exiting (e.g. dumping core).
 *
 * @return 1 if alive, 0 if exited/exiting, -1 on error
 */
int df_proc_is_alive(pid_t pid);

/**
 * Get the name/path of the process with given PID.
 *
 * @param pid Process ID
 * @param buf Buffer to store the process name/path
 * @param bufsz Size of the buffer
 * @return 0 on success, -1 on error
 */
int df_proc_get_name(pid_t pid, char *buf, size_t bufsz);

/**
 * Verify that the process tracking backend is functional.
 *
 * On Linux this checks that procfs is mounted. On OpenBSD this is a no-op
 * since kvm/kill don't require any special filesystem.
 *
 * @return 0 on success, -1 on error
 */
int df_check_proc_available(void);
