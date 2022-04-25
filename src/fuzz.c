/** @file fuzz.c */
/*
 * dfuzzer - tool for fuzz testing processes communicating through D-Bus.
 *
 * Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>
 *                                   Miroslav Vadkerti <mvadkert@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <ffi.h>        // dynamic function call construction

#include "fuzz.h"
#include "dfuzzer.h"
#include "rand.h"
#include "util.h"


/** Pointer on D-Bus interface proxy for calling methods. */
static GDBusProxy *df_dproxy;
/** Structure containing information about the linked list. */
static struct df_sig_list df_list;
/** Pointer on the last item of the linked list in the global var. df_list. */
static struct df_signature *df_last;
/** Initial memory size of process is saved into this variable; value -2
  * indicates that initial memory was not loaded so far */
static long df_initial_mem = -2;
/** Memory limit for tested process in kB - if tested process exceeds this
  * limit it will be noted into log file; if set to -1 memory limit will
  * be reloaded in df_fuzz_init() */
static long df_mem_limit = -1;
/** If memory limit passed to function df_fuzz_init() is non-zero, this flag
  * is set to 1 */
static int df_mlflg;
/** Flag for unsupported method signature, 1 means signature is unsupported */
static int df_unsupported_sig;
/** Pointer on unsupported signature string (do not free it) */
static char *df_unsupported_sig_str;
/** Exceptions counter; if MAX_EXCEPTIONS is reached testing continues
  * with a next method */
static char df_except_counter = 0;


/* Module static functions */
static long df_fuzz_get_proc_mem_size(const int statfd);
static int df_fuzz_write_log(void);
static int df_exec_cmd_check(const char *cmd);
static GVariant *df_fuzz_create_variant(void);
static int df_fuzz_create_list_variants(void);
static int df_fuzz_create_fmt_string(char **fmt, const int n);
static int df_fuzz_call_method(GVariant *value, const int void_method);


/**
 * @function Saves pointer on D-Bus interface proxy for this module to be
 * able to call methods through this proxy during fuzz testing. Also saves
 * process initial memory size to global var. df_initial_mem from file
 * described by statfd.
 * @param dproxy Pointer on D-Bus interface proxy
 * @param statfd FD of process status file
 * @param pid PID of tested process
 * @param mem_limit Memory limit in kB - if tested process exceeds this limit
 * it will be noted into log file
 * @return 0 on success, -1 on error
 */
int df_fuzz_init(GDBusProxy *dproxy, const int statfd,
                const int pid, const long mem_limit)
{
        if (dproxy == NULL) {
                df_debug("Passing NULL argument to function.\n");
                return -1;
        }
        df_dproxy = dproxy;

        // load initial memory only on the beginning
        if (df_initial_mem == -2)
                df_initial_mem = df_fuzz_get_proc_mem_size(statfd);
        if (df_initial_mem == -1) {
                df_fail("Error: Unable to get memory size of [PID:%d].\n", pid);
                df_debug("Error in df_fuzz_get_proc_mem_size()\n");
                return -1;
        }

        // on crash, df_mem_limit is always set to -1 in df_fuzz_test_method()
        if (df_mem_limit == -1) {
                if (mem_limit != 0) {   // user specified memory limit
                        df_mlflg = 1;
                        if (mem_limit <= df_initial_mem)
                                df_mem_limit = 3 * df_initial_mem;
                        else
                                df_mem_limit = mem_limit;
                } else
                        df_mem_limit = 3 * df_initial_mem;
        }

        return 0;
}

/**
 * @function Initializes the global variable df_list (struct df_sig_list)
 * including allocationg memory for method name inside df_list.
 * @param name Name of method which will be tested
 * @return 0 on success, -1 on error
 */
int df_fuzz_add_method(const char *name)
{
        if (!name) {
                df_debug("Passing NULL argument to function.\n");
                return -1;
        }

        df_list.df_method_name = strdup(name);
        if (!df_list.df_method_name) {
                df_fail("Error: Could not allocate memory for method name.\n");
                return -1;
        }

        // must be initialized because after df_fuzz_clean_method() memory
        // of df_list contains junk
        df_list.list = NULL;    // no arguments so far
        df_list.args = 0;
        df_list.fuzz_on_str_len = 0;

        return 0;
}

/**
 * @function Adds item (struct df_signature) at the end of the linked list
 * in the global variable df_list (struct df_sig_list). This includes
 * allocating memory for item and for signature string.
 * @param signature D-Bus signature of the argument
 * @return 0 on success, -1 on error
 */
int df_fuzz_add_method_arg(const char *signature)
{
        struct df_signature *s;

        if (!signature)
                return 0;

        s = malloc(sizeof(*s));
        if (!s) {
                df_fail("Error: Could not allocate memory for struct df_signature.\n");
                return -1;
        }

        df_list.args++;
        s->next = NULL;
        s->var = NULL;
        s->sig = strdup(signature);
        if (!s->sig) {
                df_fail("Error: Could not allocate memory for argument signature.\n");
                free(s);
                return -1;
        }

        // fuzzing controlled by generated random strings lengths
        if (strstr(s->sig, "s") || strstr(s->sig, "v"))
                df_list.fuzz_on_str_len = 1;

        if (!df_list.list) {
                df_list.list = s;
                df_last = s;
        } else {
                df_last->next = s;
                df_last = s;
        }

        return 0;
}

/**
 * @return Number of arguments of tested method
 */
int df_list_args_count(void)
{
        return df_list.args;
}

/**
 * @function Parses VmRSS (Resident Set Size) value from statfd and returns it
 * as process memory size.
 * @param statfd FD of process status file
 * @return Process memory size on success, 0 when statfd is not readable (that
 * means process exited: errno set to ESRCH - no such process) or -1 on error
 */
static long df_fuzz_get_proc_mem_size(const int statfd)
{
        long mem_size = -1;
        char buf[MAXLINE];  // buffer for reading from file
        char *ptr;          // pointer into buf
        char *mem;          // pointer into buf, on VmRSS line
        int stopr;
        off_t ret;
        ssize_t n;
        ssize_t count;      // total count of bytes read from file

        // rewinds file position to the beginning
        ret = lseek(statfd, 0L, SEEK_SET);
        if (ret == ((off_t) -1) && errno == ESRCH)  // process exited
                return 0;
        else if (ret == -1)
                return -1;


        stopr = 0;
        ret = 0;
        n = 0;
        count = 0;
        ptr = buf;
        while (!stopr) {
                n = read(statfd, ptr, (MAXLINE - 1 - count));
                if (n == -1 && errno == ESRCH)  // process exited
                        return 0;
                else if (n == -1)
                        return -1;
                else if (n == 0)
                        stopr++;
                ptr += n;
                count += n;
                *ptr = '\0';

                if ((mem = strstr(buf, "VmRSS:")) != NULL) {
                        // check for new line (that whole memory size number is in buffer)
                        char *nl = mem;
                        while (*nl != '\0') {
                                if (*nl == '\n') {
                                        stopr++;
                                        ret = 1;
                                        break;
                                }
                                nl++;
                        }
                } else {
                        // if no VmRSS in buffer, we can flush it
                        ptr = buf;
                        count = 0;
                        ret = 0;
                }
        }

        if (ret == 0)
                return ret;

        // now mem points to "VmRSS:" and we are sure that number with memory
        // size is in buf too
        while (isdigit(*mem) == 0)
                mem++;

        mem_size = strtol(mem, NULL, 10);
        if (errno == ERANGE || errno == EINVAL) {
                df_debug("Error on conversion of process memory to a long integer\n");
                return -1;
        }
        return mem_size;
}

/**
 * @function Prints all method signatures and their values on the output.
 * @return 0 on success, -1 on error
 */
static int df_fuzz_write_log(void)
{
        struct df_signature *s = df_list.list;  // pointer on first signature
        int len = 0;
        int str_len = 0;

        FULL_LOG("%s;", df_list.df_method_name);

        while (s != NULL) {
                len = strlen(s->sig);
                if (len <= 0) {
                        df_fail("No argument signature\n");
                        FULL_LOG("\n");
                        return -1;
                } else if (len == 1) {  // one character argument
                        df_fail("    --");
                        df_fail("%s", s->sig);
                        FULL_LOG("%s;", s->sig);

                        switch (s->sig[0]) {
                                case 'y':
                                        ;
                                        guint8 tmp;
                                        g_variant_get(s->var, s->sig, &tmp);
                                        df_fail("-- '%u'\n", tmp);
                                        FULL_LOG("%u;", tmp);
                                        break;
                                case 'b':
                                        ;
                                        gboolean tmp1;
                                        g_variant_get(s->var, s->sig, &tmp1);
                                        df_fail("-- '%s'\n", ((tmp1 == 1) ? "true" : "false"));
                                        FULL_LOG("%s", tmp1 ? "true" : "false");
                                        break;
                                case 'n':
                                        ;
                                        gint16 tmp2;
                                        g_variant_get(s->var, s->sig, &tmp2);
                                        df_fail("-- '%d'\n", tmp2);
                                        FULL_LOG("%d;", tmp2);
                                        break;
                                case 'q':
                                        ;
                                        guint16 tmp3;
                                        g_variant_get(s->var, s->sig, &tmp3);
                                        df_fail("-- '%u'\n", tmp3);
                                        FULL_LOG("%u;", tmp3);
                                        break;
                                case 'i':
                                        ;
                                        gint32 tmp4;
                                        g_variant_get(s->var, s->sig, &tmp4);
                                        df_fail("-- '%d'\n", tmp4);
                                        FULL_LOG("%d;", tmp4);
                                        break;
                                case 'u':
                                        ;
                                        guint32 tmp5;
                                        g_variant_get(s->var, s->sig, &tmp5);
                                        df_fail("-- '%u'\n", tmp5);
                                        FULL_LOG("%u;", tmp5);
                                        break;
                                case 'x':
                                        ;
                                        gint64 tmp6;
                                        g_variant_get(s->var, s->sig, &tmp6);
                                        df_fail("-- '%" G_GINT64_FORMAT "'\n", tmp6);
                                        FULL_LOG("%" G_GINT64_FORMAT, tmp6);
                                        break;
                                case 't':
                                        ;
                                        guint64 tmp7;
                                        g_variant_get(s->var, s->sig, &tmp7);
                                        df_fail("-- '%" G_GUINT64_FORMAT "'\n", tmp7);
                                        FULL_LOG("%" G_GUINT64_FORMAT, tmp7);
                                        break;
                                case 'd':
                                        ;
                                        gdouble tmp8;
                                        g_variant_get(s->var, s->sig, &tmp8);
                                        df_fail("-- '%lg'\n", tmp8);
                                        FULL_LOG("%lg;", tmp8);
                                        break;
                                case 's':
                                        ;
                                        gchar *tmp9 = NULL, *tmp9cpy = NULL;
                                        g_variant_get(s->var, s->sig, &tmp9);
                                        str_len = strlen(tmp9);
                                        tmp9cpy = tmp9;
                                        if (tmp9 != NULL)
                                                df_fail(" [length: %d B]-- '%s'\n", str_len, tmp9);
                                        if (logfile) {
                                                while((tmp9 != NULL) && (*tmp9)){
                                                        FULL_LOG("%02x", *tmp9++ & 0xff);
                                                }
                                        }
                                        FULL_LOG(";");
                                        free(tmp9cpy);
                                        break;
                                case 'o':
                                        ;
                                        gchar *tmp10 = NULL, *tmp10cpy = NULL;
                                        g_variant_get(s->var, s->sig, &tmp10);
                                        str_len = strlen(tmp10);
                                        tmp10cpy = tmp10;
                                        if (tmp10 != NULL)
                                                df_fail(" [length: %d B]-- '%s'\n", str_len, tmp10);
                                        if (logfile) {
                                                while((tmp10 != NULL) && (*tmp10)){
                                                        FULL_LOG("%02x", *tmp10++ & 0xff);
                                                }
                                        }
                                        FULL_LOG(";");
                                        free(tmp10cpy);
                                        break;
                                case 'g':
                                        ;
                                        gchar *tmp11 = NULL, *tmp11cpy;
                                        g_variant_get(s->var, s->sig, &tmp11);
                                        str_len = strlen(tmp11);
                                        tmp11cpy = tmp11;
                                        if (tmp11 != NULL)
                                                df_fail(" [length: %d B]-- '%s'\n", str_len, tmp11);
                                        if (logfile) {
                                                while((tmp11 != NULL) && (*tmp11)){
                                                        FULL_LOG("%02x", *tmp11++ & 0xff);
                                                }
                                        }
                                        FULL_LOG(";");
                                        free(tmp11cpy);
                                        break;
                                case 'v':
                                        ;
                                        GVariant *var = NULL;
                                        gchar *tmp12 = NULL, *tmp12cpy = NULL;
                                        g_variant_get(s->var, s->sig, var);
                                        if (var != NULL &&
                                                        g_variant_check_format_string(var, "s", FALSE)) {
                                                g_variant_get(var, "s", &tmp12);
                                                str_len = strlen(tmp12);
                                                tmp12cpy = tmp12;
                                                if (tmp12 != NULL)
                                                        df_fail(" [length: %d B]-- '%s'\n", str_len, tmp12);
                                                if (logfile) {
                                                        while((tmp12 != NULL) && (*tmp12)){
                                                                FULL_LOG("%02x", *tmp12++ & 0xff);
                                                        }
                                                }
                                                FULL_LOG(";");
                                                free(tmp12cpy);
                                        } else {
                                                df_fail("-- 'unable to deconstruct GVariant instance'\n");
                                        }
                                        break;
                                case 'h':
                                        ;
                                        gint32 tmp13;
                                        g_variant_get(s->var, s->sig, &tmp13);
                                        FULL_LOG("%d;", tmp13);
                                        df_fail("-- '%d'\n", tmp13);
                                        break;
                                default:
                                        df_fail("Unknown argument signature '%s'\n", s->sig);
                                        return -1;
                        }
                } else {    // advanced argument (array of something, dictionary, ...)
                        df_debug("Not yet implemented in df_fuzz_write_log()\n");
                        return 0;
                }

                s = s->next;
        }

        return 0;
}

/**
 * @function Executes command/script cmd.
 * @param cmd Command/Script to execute
 * @return 0 on successful completition of cmd or when cmd is NULL, value
 * higher than 0 on unsuccessful completition of cmd or -1 on error
 */
static int df_exec_cmd_check(const char *cmd)
{
        if (cmd == NULL)
                return 0;

        const char *fn = "/dev/null";
        _cleanup_(closep) int stdoutcpy = -1, stderrcpy = -1, fd = -1;
        int status = 0;

        fd = open(fn, O_RDWR, S_IRUSR | S_IWUSR);
        if (fd == -1) {
                perror("open");
                return -1;
        }

        // backup std descriptors
        stdoutcpy = dup(1);
        if (stdoutcpy < 0)
                return -1;
        stderrcpy = dup(2);
        if (stderrcpy < 0)
                return -1;

        // make stdout and stderr go to fd
        if (dup2(fd, 1) < 0)
                return -1;
        if (dup2(fd, 2) < 0)
                return -1;
        fd = safe_close(fd);      // fd no longer needed

        // execute cmd
        status = system(cmd);

        // restore std descriptors
        if (dup2(stdoutcpy, 1) < 0)
                return -1;
        stdoutcpy = safe_close(stdoutcpy);
        if (dup2(stderrcpy, 2) < 0)
                return -1;
        stderrcpy = safe_close(stderrcpy);


        if (status == -1)
                return status;
        return WEXITSTATUS(status);
}

/**
 * @function Function is testing a method in a cycle, each cycle generates
 * data for function arguments, calls method and waits for result.
 * @param statfd FD of process status file
 * @param buf_size Maximum buffer size for generated strings
 * by rand module (in Bytes)
 * @param name D-Bus name
 * @param obj D-Bus object path
 * @param intf D-Bus interface
 * @param pid PID of tested process
 * @param void_method If method has out args 1, 0 otherwise
 * @param execute_cmd Command/Script to execute after each method call.
 * @return 0 on success, -1 on error, 1 on tested process crash, 2 on void
 * function returning non-void value, 3 on warnings and 4 when executed
 * command finished unsuccessfuly
 */
int df_fuzz_test_method(const int statfd, long buf_size, const char *name,
                const char *obj, const char *intf, const int pid,
                const int void_method, const char *execute_cmd)
{
        // methods with no arguments are not tested
        if (df_list.args == 0)
                return 0;

        struct df_signature *s = df_list.list;  // pointer on the first signature
        int ret = 0;            // return value from df_fuzz_call_method()
        int execr = 0;          // return value from execution of execute_cmd
        int leaking_mem_flg = 0;            // if set to 1, leaks were detected
        int buf_size_flg = 0;               // if set to 1, buf_size was specified
        // by option -b
        long used_memory = 0;               // memory size used by process in kB
        long prev_memory = 0;               // last known memory size

        // DEBUG:
        int j = 0;
        df_debug("  Method: %s%s", ansi_bold(), df_list.df_method_name);
        df_debug("(");
        for (; j < df_list.args; j++, s = s->next)
                df_debug(((j < df_list.args - 1) ? "%s, " : "%s"), s->sig);
        df_debug(")%s\n", ansi_normal());


        if (buf_size != 0)
                buf_size_flg = 1;
        if (buf_size < MINLEN)
                buf_size = MAX_BUF_LEN;
        // initialization of random module
        df_rand_init(buf_size);


        df_verbose("  %s...", df_list.df_method_name);

        while (df_rand_continue(df_list.fuzz_on_str_len)) {
                _cleanup_(g_variant_unrefp) GVariant *value = NULL;

                // parsing proces memory size from its status file described by statfd
                used_memory = df_fuzz_get_proc_mem_size(statfd);
                if (used_memory == -1) {
                        df_fail("Error: Unable to get memory size of [PID:%d].\n", pid);
                        df_debug("Error in df_fuzz_get_proc_mem_size()\n");
                        return -1;
                }
                prev_memory = used_memory;


                // creates variant containing all (fuzzed) method arguments
                value = df_fuzz_create_variant();
                if (!value) {
                        if (df_unsupported_sig) {
                                df_unsupported_sig = 0;
                                df_debug("  unsupported argument by dfuzzer: ");
                                df_debug("%s\n", df_unsupported_sig_str);
                                df_unsupported_sig_str = NULL;
                                df_verbose("%s  %sSKIP%s %s - advanced signatures not yet implemented\n",
                                           ansi_cr(), ansi_blue(), ansi_normal(), df_list.df_method_name);
                                return 0;
                        }

                        df_debug("Call of df_fuzz_create_variant() returned NULL pointer\n");
                        return -1;
                }


                ret = df_fuzz_call_method(value, void_method);
                execr = df_exec_cmd_check(execute_cmd);
                if (execr == -1)
                        return -1;
                if (ret == -1) {
                        // Here we look at process status file to be sure it really
                        // exited. If file is readable it means process is
                        // processing long string(s) and that is the reason it
                        // didn't respond so we continue.
                        used_memory = df_fuzz_get_proc_mem_size(statfd);
                        if (used_memory == 0) {         // process exited
                                df_fail("%s  %sFAIL%s %s - process exited\n"
                                        "   [PID: %d], [MEM: %ld kB]\n",
                                        ansi_cr(), ansi_red(), ansi_normal(),
                                        df_list.df_method_name, pid, prev_memory);
                                if (execr > 0)
                                        df_fail("%s   '%s' returned %s%d%s\n",
                                                ansi_cr(), execute_cmd, ansi_red(), execr, ansi_normal());
                                goto fail_label;
                        } else if (used_memory == -1) { // error on reading process status
                                df_fail("Error: Unable to get memory size of [PID:%d].\n", pid);
                                df_debug("Error in df_fuzz_get_proc_mem_size()\n");
                                if (execr > 0)
                                        df_fail("%s   '%s' returned %s%d%s\n",
                                                ansi_cr(), execute_cmd, ansi_red(), execr, ansi_normal());
                                return -1;
                        }
                        // else continue, we managed to get process memory size
                        prev_memory = used_memory;
                } else if (ret == 1) {
                        // method returning void is returning illegal value
                        if (execr > 0)
                                df_fail("%s   '%s' returned %s%d%s\n",
                                        ansi_cr(), execute_cmd, ansi_red(), execr, ansi_normal());
                        goto fail_label;
                } else if (ret == 2) {
                        // tested method returned exception
                        used_memory = df_fuzz_get_proc_mem_size(statfd);
                        if (used_memory == 0) {         // process exited
                                df_fail("%s  %sFAIL%s %s - process exited\n"
                                        "   [PID: %d], [MEM: %ld kB]\n",
                                        ansi_cr(), ansi_red(), ansi_normal(),
                                        df_list.df_method_name, pid, prev_memory);
                                goto fail_label;
                        } else if (used_memory == -1) { // error on reading process status
                                df_fail("Error: Unable to get memory size of [PID:%d].\n", pid);
                                df_debug("Error in df_fuzz_get_proc_mem_size()\n");
                                if (execr > 0)
                                        df_fail("%s   '%s' returned %s%d%s\n",
                                                ansi_cr(), execute_cmd, ansi_red(), execr, ansi_normal());
                                return -1;
                        }
                        if (execr > 0)
                                df_fail("%s   '%s' returned %s%d%s\n",
                                        ansi_cr(), execute_cmd, ansi_red(), execr, ansi_normal());
                        return 0;
                }

                if (execr > 0) {
                        df_fail("%s  %sFAIL%s %s - '%s' returned %s%d%s\n",
                                ansi_cr(), ansi_red(), ansi_normal(), df_list.df_method_name,
                                execute_cmd, ansi_red(), execr, ansi_normal());
                        goto fail_label;
                }


                // process memory size exceeded maximum normal memory size
                // (this is just a warning message)
                if (used_memory >= df_mem_limit) {
                        df_fail("%s  %sWARN%s %s - memory usage %.1fx more "
                                "than initial memory\n   (%ld -> %ld [kB])\n",
                                ansi_cr(), ansi_magenta(), ansi_normal(),
                                df_list.df_method_name, (((float) used_memory)/df_initial_mem),
                                df_initial_mem, used_memory);
                        df_mem_limit = used_memory * 2;
                        leaking_mem_flg = 1;
                }


                // Here we look at process status file to find out status of process.
                used_memory = df_fuzz_get_proc_mem_size(statfd);
                if (used_memory == 0) {         // process exited
                        df_fail("%s  %sFAIL%s %s - process exited\n"
                                "   [PID: %d], [MEM: %ld kB]\n",
                                ansi_cr(), ansi_red(), ansi_normal(),
                                df_list.df_method_name, pid, prev_memory);
                        if (execr > 0)
                                df_fail("%s   '%s' returned %s%d%s\n",
                                        ansi_cr(), execute_cmd, ansi_red(), execr, ansi_normal());
                        goto fail_label;
                } else if (used_memory == -1) { // error on reading process status
                        df_fail("Error: Unable to get memory size of [PID:%d].\n", pid);
                        df_debug("Error in df_fuzz_get_proc_mem_size()\n");
                        if (execr > 0)
                                df_fail("%s   '%s' returned %s%d%s\n",
                                        ansi_cr(), execute_cmd, ansi_red(), execr, ansi_normal());
                        return -1;
                }
                // else continue, we managed to get process memory size
                prev_memory = used_memory;

                FULL_LOG("%s;%s;", intf, obj);

                if(logfile) df_fuzz_write_log();
                FULL_LOG("Success\n");
                if (df_except_counter == MAX_EXCEPTIONS) {
                        df_except_counter = 0;
                        break;
                }
        }


        // test passed
        if (leaking_mem_flg)    // warning
                return 3;
        df_verbose("%s  %sPASS%s %s\n",
                   ansi_cr(), ansi_green(), ansi_normal(), df_list.df_method_name);
        return 0;


fail_label:
        df_mem_limit = -1;      // set to -1 to reload memory limit
        if (ret != 1) {
                df_fail("   on input:\n");
                FULL_LOG("%s;%s;", intf, obj);
                df_fuzz_write_log();
        }

        df_fail("   reproducer: %sdfuzzer -v -n %s -o %s -i %s -t %s",
                ansi_yellow(), name, obj, intf, df_list.df_method_name);
        if (df_mlflg)
                df_fail(" -m %ld", df_mem_limit);
        if (buf_size_flg)
                df_fail(" -b %ld", buf_size);
        if (execute_cmd != NULL)
                df_fail(" -e '%s'", execute_cmd);
        df_fail("%s\n", ansi_normal());

        if (ret == 1){  // method returning void is returning illegal value
                return 2;
        }
        if (execr > 0){ // command/script execution ended with error
                FULL_LOG("Command execution error\n");
                return 4;
        }
        FULL_LOG("Crash\n");

        return 1;
}

/**
 * @function Creates GVariant tuple variable which contains all the signatures
 * of method arguments including their values. This tuple is constructed
 * from each signature of method argument by one call of g_variant_new()
 * function. This call is constructed dynamically (using libffi) as we don't
 * know number of function parameters on compile time.
 * @return Pointer on a new GVariant variable containing tuple with method
 * arguments
 */
static GVariant *df_fuzz_create_variant(void)
{
        struct df_signature *s = df_list.list;  // pointer on first signature
        // libffi part, to construct dynamic call of g_variant_new() on runtime
        GVariant *val = NULL;
        ffi_cif cif;
        // MAXSIG = max. amount of D-Bus signatures + 1 (format string)
        ffi_type *args[MAXSIG + 1];
        void *values[MAXSIG + 1];
        _cleanup_free_ char *fmt = NULL;
        int ret;

        // creates GVariant for every item signature in linked list
        ret = df_fuzz_create_list_variants();
        if (ret == -1) {
                df_debug("Error in df_fuzz_create_list_variants()\n");
                return NULL;
        } else if (ret == 1) {      // unsupported method signature
                df_unsupported_sig++;
                return NULL;
        }

        fmt = malloc(MAXFMT + 1);
        if (!fmt) {
                df_fail("Error: Could not allocate memory for format string.\n");
                return NULL;
        }
        // creates the format string for g_variant_new() function call
        if (df_fuzz_create_fmt_string(&fmt, MAXFMT + 1) == -1) {
                df_fail("Error: Unable to create format string.\n");
                df_debug("Error in df_fuzz_create_fmt_string()\n");
                return NULL;
        }

        // Initialize the argument info vectors
        args[0] = &ffi_type_pointer;
        values[0] = &fmt;
        for (int i = 1; i <= df_list.args && s; i++) {
                args[i] = &ffi_type_pointer;
                values[i] = &(s->var);
                s = s->next;
        }

        // Initialize the cif
        if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, df_list.args + 1,
                                &ffi_type_pointer, args) == FFI_OK) {
                ffi_call(&cif, FFI_FN(g_variant_new), &val, values);
                // val now holds the result of the call to g_variant_new().
                // When val will be freed, all the floating Gvariants which
                // was used to create it will be freed too, because val is
                // their owner
        } else {
                df_fail("ffi_prep_cif() failed on initializing cif.\n");
                return NULL;
        }

        // GVariant containing method parameters must not be floating, because
        // it would be consumed by g_dbus_proxy_call_sync() function and as
        // result we couldn't have get GVariant values from items of linked list
        // (needed for loging)
        val = g_variant_ref_sink(val);  // converts floating to normal reference
        // so val cannot be consumed
        // by g_dbus_proxy_call_sync() function
        if (g_variant_is_floating(val)) {
                df_fail("Error: Unable to convert GVariant from floating to normal"
                        " reference\n(for method '%s()'.\n", df_list.df_method_name);
                return NULL;
        }

        return val;
}

/**
 * @function Generates data for each method argument according to argument
 * signature and stores it into Gvariant variable in items of linked list.
 * @return 0 on success, 1 on unsupported method signature, -1 on error
 */
static int df_fuzz_create_list_variants(void)
{
        struct df_signature *s = df_list.list;  // pointer on first signature
        int len;

        while (s != NULL) {
                len = strlen(s->sig);
                if (len <= 0) {
                        df_debug("df_fuzz_create_list_variants(): No argument signature\n");
                        return -1;
                } else if (len == 1) {      // one character argument
                        switch (s->sig[0]) {
                                case 'y':
                                        s->var = g_variant_new(s->sig, df_rand_guint8());
                                        break;
                                case 'b':
                                        s->var = g_variant_new(s->sig, df_rand_gboolean());
                                        break;
                                case 'n':
                                        s->var = g_variant_new(s->sig, df_rand_gint16());
                                        break;
                                case 'q':
                                        s->var = g_variant_new(s->sig, df_rand_guint16());
                                        break;
                                case 'i':
                                        s->var = g_variant_new(s->sig, df_rand_gint32());
                                        break;
                                case 'u':
                                        s->var = g_variant_new(s->sig, df_rand_guint32());
                                        break;
                                case 'x':
                                        s->var = g_variant_new(s->sig, df_rand_gint64());
                                        break;
                                case 't':
                                        s->var = g_variant_new(s->sig, df_rand_guint64());
                                        break;
                                case 'd':
                                        s->var =
                                                g_variant_new(s->sig, df_rand_gdouble());
                                        break;
                                case 's': {
                                        _cleanup_(g_freep) gchar *buf = NULL;
                                        if (df_rand_string(&buf) == -1) {
                                                df_debug("In df_rand_string()\n");
                                                return -1;
                                        }
                                        s->var = g_variant_new(s->sig, buf);
                                        break;
                                }
                                case 'o': {
                                        _cleanup_(g_freep) gchar *obj = NULL;
                                        if (df_rand_dbus_objpath_string(&obj) == -1) {
                                                df_debug("In df_rand_dbus_objpath_string()\n");
                                                return -1;
                                        }
                                        s->var = g_variant_new(s->sig, obj);
                                        break;
                                }
                                case 'g': {
                                        _cleanup_(g_freep) gchar *sig = NULL;
                                        if (df_rand_dbus_signature_string(&sig) == -1) {
                                                df_debug("In df_rand_dbus_signature_string()\n");
                                                return -1;
                                        }
                                        s->var = g_variant_new(s->sig, sig);
                                        break;
                                }
                                case 'v': {
                                        GVariant *var;
                                        if (df_rand_GVariant(&var) == -1) {
                                                df_debug("In df_rand_GVariant()\n");
                                                return -1;
                                        }
                                        s->var = g_variant_new(s->sig, var);
                                        break;
                                }
                                case 'h':
                                        s->var = g_variant_new(s->sig, df_rand_unixFD());
                                        break;
                                default:
                                        df_debug("Unknown argument signature '%s'\n", s->sig);
                                        return -1;
                        }
                } else {    // advanced argument (array of something, dictionary, ...)
                        // fprintf(stderr, "Advanced signatures not yet implemented\n");
                        df_unsupported_sig_str = s->sig;
                        for (s = df_list.list; s && s->var; s = s->next) {
                                g_variant_unref(s->var);
                                s->var = NULL;
                        }
                        return 1;   // unsupported method signature
                }

                if (s->var == NULL) {
                        df_fail("Error: Failed to construct GVariant for '%s' signature"
                                "of method '%s'\n", s->sig, df_list.df_method_name);
                        return -1;
                }
                s = s->next;
        }

        return 0;
}

/**
 * @function Creates format string (tuple) from method arguments signatures
 * with maximum length of n-1. The final string is saved in parameter fmt.
 * @param fmt Pointer on buffer where format string should be stored
 * @param n Size of buffer
 * @return 0 on success, -1 on error
 */
static int df_fuzz_create_fmt_string(char **fmt, const int n)
{
        struct df_signature *s = df_list.list;  // pointer on first signature
        int total_len = 0;
        int len = 0;
        char *ptr = *fmt;

        // final fmt string, for example may look like this: "(@s@i)"
        *ptr = '(';
        total_len++;
        ptr++;

        while (s != NULL) {
                len = strlen(s->sig);
                total_len += len + 1;   // including '@' character
                if (total_len > (n - 3)) {
                        df_debug("Format string is too small to consume all signatures\n");
                        return -1;
                }
                *ptr = '@';
                ptr++;
                memcpy(ptr, s->sig, len);
                ptr += len;
                len = 0;
                s = s->next;
        }

        if (total_len > (n - 3)) {
                df_debug("Format string is too small to consume all signatures\n");
                return -1;
        }
        *ptr = ')';
        ptr++;
        *ptr = '\0';

        return 0;
}

/**
 * @function Calls method from df_list (using its name) with its arguments.
 * @param value GVariant tuple containing all method arguments signatures and
 * their values
 * @param void_method If method has out args 1, 0 otherwise
 * @return 0 on success, -1 on error, 1 if void method returned non-void
 * value or 2 when tested method raised exception (so it should be skipped)
 */
static int df_fuzz_call_method(GVariant *value, const int void_method)
{
        _cleanup_(g_error_freep) GError *error = NULL;
        _cleanup_(g_variant_unrefp) GVariant *response = NULL;
        _cleanup_(g_freep) gchar *dbus_error = NULL;
        const gchar *fmt;

        // Synchronously invokes method with arguments stored in value (GVariant *)
        // on df_dproxy.
        response = g_dbus_proxy_call_sync(
                        df_dproxy,
                        df_list.df_method_name,
                        value,
                        G_DBUS_CALL_FLAGS_NONE,
                        -1,
                        NULL,
                        &error);
        if (!response) {
                // D-Bus exceptions are accepted
                dbus_error = g_dbus_error_get_remote_error(error);
                if (dbus_error) {
                        // if process does not respond
                        if (strcmp(dbus_error, "org.freedesktop.DBus.Error.NoReply") == 0)
                                return -1;
                        else if (strcmp(dbus_error, "org.freedesktop.DBus.Error.Timeout") == 0) {
                                sleep(10);      // wait for tested process; processing
                                // of longer inputs may take a longer time
                                return -1;
                        } else if ((strcmp(dbus_error, "org.freedesktop.DBus.Error.AccessDenied") == 0) ||
                                   (strcmp(dbus_error, "org.freedesktop.DBus.Error.AuthFailed") == 0)) {
                                df_verbose("%s  %sSKIP%s %s - raised exception '%s'\n",
                                           ansi_cr(), ansi_blue(), ansi_normal(),
                                           df_list.df_method_name, dbus_error);
                                return 2;
                        }
                }

                g_dbus_error_strip_remote_error(error);
                if (strstr(error->message, "Timeout")) {
                        df_verbose("%s  %sSKIP%s %s - timeout reached\n",
                                   ansi_cr(), ansi_blue(), ansi_normal(), df_list.df_method_name);
                        return 2;
                }

                df_debug("%s  EXCE %s - D-Bus exception thrown: %.60s\n",
                         ansi_cr(), df_list.df_method_name, error->message);
                df_except_counter++;
                return 0;
        } else {
                if (void_method) {
                        // fmt points to GVariant, do not free it
                        fmt = g_variant_get_type_string(response);
                        // void function can only return empty tuple
                        if (strcmp(fmt, "()") != 0) {
                                df_fail("%s  %sFAIL%s %s - void method returns '%s' instead of '()'\n",
                                        ansi_cr(), ansi_red(), ansi_normal(), df_list.df_method_name, fmt);
                                return 1;
                        }
                }
        }

        return 0;
}

/**
 * @function Releases memory used by this module. This function must be called
 * after df_fuzz_add_method() and df_fuzz_add_method_arg() functions calls
 * after the end of fuzz testing of each method.
 */
void df_fuzz_clean_method(void)
{
        free(df_list.df_method_name);

        // frees the linked list
        struct df_signature *tmp;
        while (df_list.list != NULL) {
                tmp = df_list.list->next;
                free(df_list.list->sig);
                free(df_list.list);
                df_list.list = tmp;
        }
}
