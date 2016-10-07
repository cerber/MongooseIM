%%%-------------------------------------------------------------------
%%% @author cerber
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 11. Sep 2016 1:02 PM
%%%-------------------------------------------------------------------
-module(mod_http_upload_SUITE).
-author("dmytro@xpyriens.com").
-compile(export_all).

-include_lib("escalus/include/escalus.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("escalus/include/escalus_xmlns.hrl").
-include_lib("exml/include/exml.hrl").

-define(NS_HTTP_UPLOAD, <<"urn:xmpp:http:upload">>).

%%--------------------------------------------------------------------
%% Suite configuration
%%--------------------------------------------------------------------

all() ->
    [{group, http_upload}].

groups() ->
    [{http_upload, [], [http_upload_service_discovery]}].

suite() ->
    escalus:suite().

%%--------------------------------------------------------------------
%% Init & teardown
%%--------------------------------------------------------------------
init_per_suite(Config) ->
    escalus:init_per_suite(Config).

end_per_suite(Config) ->
    escalus:end_per_suite(Config).

init_per_group(http_upload, Config) ->
    %%    dynamic_modules:start(<<"localhost">>, mod_http_upload, []),
    escalus:create_users(Config, escalus:get_users([alice])).

end_per_group(_Group, Config) ->
    %%  dynamic_modules:stop(<<"localhost">>, mod_http_upload),
    escalus:delete_users(Config, escalus_users:get_users([alice])).

init_per_testcase(CaseName, Config) ->
    escalus:init_per_testcase(CaseName, Config).

end_per_testcase(CaseName, Config) ->
    escalus:end_per_testcase(CaseName, Config).

%%--------------------------------------------------------------------
%% Service discovery test
%%--------------------------------------------------------------------
http_upload_service_discovery(Config) ->
    escalus:story(
      Config, [{alice, 1}],
      fun(Client) ->
              JID = escalus_client:server(Client),
              Result = escalus:send_and_wait(Client,
                                             escalus_stanza:disco_info(JID)),
              escalus:assert(is_iq_result, Result),
              escalus:assert(has_feature, [?NS_HTTP_UPLOAD], Result)
      end).
