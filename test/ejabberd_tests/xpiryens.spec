%% Xpiryens spec

{suites, "tests", mongoose_sanity_checks_SUITE}.

{suites, "tests", mod_http_upload_SUITE}.

{config, ["test_xpiryens.config"]}.
{logdir, "ct_report"}.

{ct_hooks, [ct_tty_hook, ct_mongoose_hook, ct_progress_hook]}.
