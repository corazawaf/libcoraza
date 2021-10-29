
#ifndef _SRC_CORAZA_CONFIG__
#define _SRC_CORAZA_CONFIG__

static const char *coraza_config_modsec_state(cmd_parms *cmd, void *_dcfg,
                                           const char *p1);

static const char *coraza_config_load_rules(cmd_parms *cmd, void *_dcfg,
                                            const char *p1);

static const char *coraza_config_load_rules_file(cmd_parms *cmd, void *_dcfg,
                                                 const char *p1);

static const char *coraza_config_load_rules_remote(cmd_parms *cmd, void *_dcfg,
                                                   const char *p1, const char *p2);

void *coraza_hook_create_config_directory(apr_pool_t *mp, char *path);

void *coraza_hook_merge_config_directory(apr_pool_t *mp, void *parent,
                                         void *child);

#endif /* _SRC_CORAZA_CONFIG__ */