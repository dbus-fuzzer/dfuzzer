#pragma once

void df_suppression_free(GList **suppressions);
int df_suppression_load(GList **suppressions, const char *service_name);
int df_suppression_check(GList *suppressions, const char *object, const char *interface,
                         const char *method, char **ret_description_ptr);
