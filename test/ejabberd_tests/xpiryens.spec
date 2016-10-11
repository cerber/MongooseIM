%% Xpiryens tests suites

{suites, "tests", mongoose_sanity_checks_SUITE}.

{suites, "tests", mod_ping_SUITE}.
{suites, "tests", mod_http_upload_SUITE}.

{config, ["xpiryens.config"]}.
{logdir, "ct_report"}.

{ct_hooks, [ct_tty_hook,
            {ct_mongoose_hook, [print_group, print_case]},
            ct_progress_hook]}.
