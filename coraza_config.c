#include "mod_coraza.h"
#include "coraza_config.h"
#include "coraza_filters.h"

const command_rec module_directives[] =
    {
        AP_INIT_TAKE1(
            "coraza",
            coraza_config_modsec_state,
            NULL,
            RSRC_CONF | ACCESS_CONF,
            "The argument must be either 'On' or 'Off'"),

        AP_INIT_TAKE1(
            "coraza_rules_file",
            coraza_config_load_rules_file,
            NULL,
            RSRC_CONF | ACCESS_CONF,
            "Load Coraza rules from a file"),

        {NULL}};

static const char *coraza_config_modsec_state(cmd_parms *cmd, void *_cnf,
                                           const char *p1)
{
    coraza_conf_t *cnf = (coraza_conf_t *)_cnf;

    if (strcasecmp(p1, "On") == 0)
    {
        cnf->coraza_state = 1;
    }
    else if (strcasecmp(p1, "Off") == 0)
    {
        cnf->coraza_state = 0;
    }
    else
    {
        return "Coraza state must be either 'On' or 'Off'";
    }

    return NULL;
}

static const char *coraza_config_load_rules_file(cmd_parms *cmd, void *_cnf,
                                              const char *p1)
{
    coraza_conf_t *cnf = (coraza_conf_t *)_cnf;
    const char *error = NULL;
    int ret;

    ret = coraza_rules_add_file(cnf->waf, p1, &error);

    if (ret < 0)
    {
        return error;
    }

    return NULL;
}

void *coraza_hook_create_config_directory(apr_pool_t *mp, char *path)
{
    coraza_conf_t *cnf = NULL;

    cnf = apr_pcalloc(mp, sizeof(coraza_conf_t));
    if (cnf == NULL)
    {
        goto end;
    }
#if 0
    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Created directory config for path: %s [%pp]", path, cnf);
#endif

    cnf->waf = coraza_new_waf();
    if (path != NULL)
    {
        cnf->name_for_debug = strdup(path);
    }
#if 0
    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Config for path: %s is at: %pp", path, cnf);
#endif

end:
    return cnf;
}

void *coraza_hook_merge_config_directory(apr_pool_t *mp, void *parent,
                                      void *child)
{
    coraza_conf_t *cnf_p = parent;
    coraza_conf_t *cnf_c = child;
    coraza_conf_t *cnf_new = (coraza_conf_t *)coraza_hook_create_config_directory(mp, cnf_c->name_for_debug);

    if (cnf_p && cnf_c)
    {
        const char *error = NULL;
        int ret;
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent %pp [%s] child %pp [%s]" \
            "into: %pp", cnf_p,
            cnf_p->name_for_debug,
            child, cnf_c->name_for_debug, cnf_new);
#endif
        cnf_new->name_for_debug = cnf_c->name_for_debug;
/*
        ret = coraza_rules_merge(cnf_new->waf, cnf_c->waf, &error);
        if (ret < 0)
        {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, mp,
                          "ModSecurity: Rule merge failed: %s", error);
            return NULL;
        }

        ret = coraza_rules_merge(cnf_new->rules_set, cnf_p->rules_set, &error);
        if (ret < 0)
        {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, mp,
                          "ModSecurity: Rule merge failed: %s", error);
            return NULL;
        }
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Merge OK");
#endif
    }
    else if (cnf_c && !cnf_p)
    {
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent -NULL- [-NULL-] child %pp [%s]",
            cnf_c, cnf_c->name_for_debug);
#endif
    }
    else if (cnf_p && !cnf_c)
    {
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent %pp [%s] child -NULL- [-NULL-]",
            cnf_p, cnf_p->name_for_debug);
#endif
    }
*/
    }
    return cnf_new;
}