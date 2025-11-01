#include <gio/gio.h>
#include <glib.h>
#include <stdio.h>

#include "util.h"
#include "log.h"

static void test_df_execute_external_command(void)
{
        for (guint8 i = 0; i < 2; i++) {
                gboolean show_output = i == 0 ? FALSE : TRUE;
                g_test_message("show_output: %s", show_output ? "TRUE" : "FALSE");

                g_assert_true(df_execute_external_command("true", show_output) == 0);
                g_assert_true(df_execute_external_command("true; echo hello world; cat /proc/$$/status", show_output) == 0);
                g_assert_true(df_execute_external_command("true; echo hello world; false /proc/$$/status", show_output) > 0);
                g_assert_true(df_execute_external_command("exit 66", show_output) == 66);
                g_assert_true(df_execute_external_command("this-should-not-exist", show_output) > 0);
                g_assert_true(df_execute_external_command("kill -SEGV $$", show_output) > 0);
        }
}

int main(int argc, char *argv[])
{
        g_test_init(&argc, &argv, NULL);

        g_test_add_func("/df_util/df_execute_external_command", test_df_execute_external_command);

        return g_test_run();
}
