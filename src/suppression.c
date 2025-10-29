#include <glib.h>
#include <stdlib.h>
#include <stdio.h>

#include "suppression.h"
#include "log.h"
#include "util.h"

/** Suppression file #1 */
#define SUPPRESSION_FILE_CWD "./dfuzzer.conf"
/** Suppression file #2 (home dir) */
#define SUPPRESSION_FILE_HOME ".dfuzzer.conf"
/** Suppression file #3 (mandatory) */
#define SUPPRESSION_FILE_SYSTEM "/etc/dfuzzer.conf"

typedef struct suppression_item {
        char *object;
        char *interface;
        char *method;
        char *description;
} suppression_item_t;

static void suppression_item_free(gpointer data)
{
        suppression_item_t *item = data;

        if (item) {
                free(item->object);
                free(item->interface);
                free(item->method);
                free(item->description);
                free(item);
        }
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(suppression_item_t, suppression_item_free)

void df_suppression_free(GList **suppressions)
{
        g_list_free_full(*suppressions, suppression_item_free);
        *suppressions = NULL;
}

int df_suppression_load(GList **suppressions, const char *service_name)
{
        g_autoptr(FILE) f = NULL;
        g_autoptr(char) line = NULL, home_supp = NULL;
        char *env = NULL;
        int name_found = 0;
        size_t len = 0;
        ssize_t n;

        g_assert(service_name);
        g_assert(suppressions);

        env = getenv("HOME");
        if (env) {
                home_supp = strjoin(env, "/", SUPPRESSION_FILE_HOME);
                if (!home_supp)
                        return df_oom();
        }

        char *paths[3] = { SUPPRESSION_FILE_CWD, home_supp, SUPPRESSION_FILE_SYSTEM };

        for (size_t i = 0; i < G_N_ELEMENTS(paths); i++) {
                if (!paths[i])
                        continue;

                f = fopen(paths[i], "r");
                if (f) {
                        df_verbose("Loading suppressions from file '%s'\n", paths[i]);
                        break;
                }

                df_verbose("Cannot open suppression file '%s'\n", paths[i]);
        }

        if (!f) {
                df_fail("Cannot open any pre-defined suppression file\n");
                return -1;
        }

        // determines if currently tested bus name is in suppression file
        while (getline(&line, &len, f) > 0) {
                if (strstr(line, service_name)) {
                        name_found++;
                        break;
                }
        }

        if (ferror(f)) {
                df_fail("Error while reading from the suppression file: %m\n");
                return -1;
        }

        // no suppressions for tested bus name
        if (!name_found)
                return 0;

        df_verbose("Found suppressions for bus: '%s'\n", service_name);

        while ((n = getline(&line, &len, f)) > 0) {
                g_auto(GStrv) tokens = NULL;
                g_autoptr(char) suppression = NULL, description = NULL;
                g_autoptr(suppression_item_t) item = NULL;
                int token_count;
                char *p;

                /* Strip leading and trailing whitespaces and check if the line is empty after the stripping -
                 * if so, skip it */
                g_strstrip(line);
                if (line[0] == '\0')
                        continue;

                /* Beginning of the next section, stop here */
                if (line[0] == '[')
                        break;

                /* Split the line into either '<suppression> <description>' or just '<suppression>' */
                tokens = g_strsplit_set(line, " \t\r\n", 2);
                token_count = g_strv_length(tokens);
                if (token_count < 1)
                        return df_fail_ret(-1, "Failed to parse line '%s'\n", line);

                suppression = g_strdup(tokens[0]);
                if (token_count > 1)
                        description = g_strdup(g_strstrip(tokens[1]));

                item = calloc(1, sizeof(*item));
                if (!item)
                        return df_oom();

                /* Break down the suppression string, which should be in format:
                 *      [object_path]:[interface_name]:method_name
                 * where everything except 'method_name' is optional
                 */

                /* Extract method name */
                p = strrchr(suppression, ':');
                if (!p)
                        item->method = g_steal_pointer(&suppression);
                else {
                        item->method = strdup(p + 1);
                        *p = 0;
                }

                if (!item->method)
                        return df_oom();

                /* Extract interface name */
                if (p) {
                        p = strrchr(suppression, ':');
                        if (!p)
                                item->interface = strdup(suppression);
                        else {
                                item->interface = strdup(p + 1);
                                *p = 0;
                        }

                        if (!item->interface)
                                return df_oom();
                }

                /* Extract object name */
                if (p) {
                        p = strrchr(suppression, ':');
                        if (!p)
                                item->object = strdup(suppression);
                        else
                                /* Found another ':'? Bail out! */
                                return df_fail_ret(-1, "Invalid suppression string '%s'\n", line);

                        if (!item->object)
                                return df_oom();
                }

                item->description = g_steal_pointer(&description);
                df_verbose("Loaded suppression for method: %s:%s:%s (%s)\n",
                           isempty(item->object) ? "*" : item->object,
                           isempty(item->interface) ? "*" : item->interface,
                           item->method,
                           item->description ?: "n/a");

                *suppressions = g_list_append(*suppressions, g_steal_pointer(&item));
        }

        if (ferror(f)) {
                df_fail("Error while reading from the suppression file: %m\n");
                return -1;
        }

        df_verbose("Loaded %d suppression(s)\n", g_list_length(*suppressions));

        return 0;
}

int df_suppression_check(GList *suppressions, const char *object, const char *interface,
                         const char *method, char **ret_description_ptr)
{
        g_assert(ret_description_ptr);

        for (GList *i = suppressions; i; i = i->next) {
                suppression_item_t *item = i->data;

                g_assert(item);

                /* If the method name is set but doesn't match, continue */
                if (!isempty(method) && !isempty(item->method) && !g_str_equal(method, item->method))
                        continue;
                /* If the interface name is set but doesn't match, continue */
                if (!isempty(interface) && !isempty(item->interface) && !g_str_equal(interface, item->interface))
                        continue;
                /* If the object name is set but doesn't match, continue */
                if (!isempty(object) && !isempty(item->object) && !g_str_equal(object, item->object))
                        continue;
                /* Everything that should match matches, so the method is suppressed */
                *ret_description_ptr = item->description;
                return 1;
        }

        return 0;
}

