#include <gio/gio.h>
#include <glib.h>
#include <stdio.h>

#include "rand.h"
#include "util.h"

#define RAND_TEST_ITERATIONS 5000

static void test_df_rand_unichar(void)
{
        guint16 width;
        gunichar uc;

        /* Test if the function asserts on invalid width */
        if (g_test_subprocess()) {
                /* This section runs in a subprocess */
                width = 5;

                (void) df_rand_unichar(&width);
        }

        /* Respawn the current test in a subprocess */
        g_test_trap_subprocess (NULL, 0, 0);
        /* The forked process above should have failed */
        g_test_trap_assert_failed();

        /* Test explicit (and valid) 1 - 4 B wide characters */
        for (guint16 i = 1; i < 5; i++) {
                uc = 0;
                width = i;

                uc = df_rand_unichar(&width);

                /* The returned unichar should be in an UTF-8 range */
                g_assert_true(uc <= 0x10FFFF);
                /* And the width should remain unchanged */
                g_assert_true(i == width);
        }

        /* Test width == 0, which should give us a pseudo-random 1 - 4 B wide unichar */
        for (guint32 i = 0; i < RAND_TEST_ITERATIONS; i++) {
                width = uc = 0;

                uc = df_rand_unichar(&width);

                /* The returned unichar should be in an UTF-8 range */
                g_assert_true(uc <= 0x10FFFF);
                /* And the width should be in a valid range */
                g_assert_true(width > 0 && width < 5);
        }
}

static void test_df_rand_string(void)
{
        for (guint32 i = 0; i < RAND_TEST_ITERATIONS; i++) {
                g_autoptr(gchar) str = NULL;
                /* Test the "upper" guint64 interval in the second half of the iterations */
                guint64 iteration = i < RAND_TEST_ITERATIONS / 2 ? i : (guint64) g_test_rand_int_range(0, G_MAXINT32) + G_MAXINT32;

                g_assert_true(df_rand_string(&str, iteration) == 0);
                g_assert_nonnull(str);
        }
}

static void test_df_rand_dbus_objpath_string(void)
{
        for (guint32 i = 0; i < RAND_TEST_ITERATIONS; i++) {
                g_autoptr(gchar) str = NULL;
                /* Test the "upper" guint64 interval in the second half of the iterations */
                guint64 iteration = i < RAND_TEST_ITERATIONS / 2 ? i : (guint64) g_test_rand_int_range(0, G_MAXINT32) + G_MAXINT32;

                g_assert_true(df_rand_dbus_objpath_string(&str, iteration) == 0);
                g_assert_nonnull(str);
        }

        /* Test certain specific/problematic cases */
        g_autoptr(gchar) str = NULL;

        g_assert_true(df_rand_dbus_objpath_string(&str, df_fuzz_get_buffer_length() - 2) == 0);
        g_assert_nonnull(str);
}

static void test_df_rand_dbus_signature_string(void)
{
        for (guint32 i = 0; i < RAND_TEST_ITERATIONS; i++) {
                g_autoptr(gchar) str = NULL;
                /* Test the "upper" guint64 interval in the second half of the iterations */
                guint64 iteration = i < RAND_TEST_ITERATIONS / 2 ? i : (guint64) g_test_rand_int_range(0, G_MAXINT32) + G_MAXINT32;

                g_assert_true(df_rand_dbus_signature_string(&str, iteration) == 0);
                g_assert_true(g_variant_is_signature(str));
                g_assert_nonnull(str);
        }
}

static void test_df_rand_GVariant(void)
{
        for (guint32 i = 0; i < RAND_TEST_ITERATIONS; i++) {
                g_autoptr(GVariant) variant = NULL;
                /* Test the "upper" guint64 interval in the second half of the iterations */
                guint64 iteration = i < RAND_TEST_ITERATIONS / 2 ? i : (guint64) g_test_rand_int_range(0, G_MAXINT32) + G_MAXINT32;

                g_assert_true(df_rand_GVariant(&variant, iteration) == 0);
                g_assert_nonnull(variant);
        }
}

int main(int argc, char *argv[])
{
        g_test_init(&argc, &argv, NULL);
        /* Init our internal pseudo-random number generators */
        df_rand_init();

        g_test_add_func("/df_rand/df_rand_unichar", test_df_rand_unichar);
        g_test_add_func("/df_rand/df_rand_string", test_df_rand_string);
        g_test_add_func("/df_rand/df_rand_dbus_objpath_string", test_df_rand_dbus_objpath_string);
        g_test_add_func("/df_rand/df_rand_dbus_signature_string", test_df_rand_dbus_signature_string);
        g_test_add_func("/df_rand/df_rand_GVariant", test_df_rand_GVariant);

        return g_test_run();
}
