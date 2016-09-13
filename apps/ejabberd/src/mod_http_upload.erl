%%%-------------------------------------------------------------------
%%% @author Dmytro Nezhynskyi <dmytro@xpyriens.com>
%%% @copyright (C) 2016, Dmytro Nezhynskyi
%%% @doc XEP-0363: HTTP File Upload
%%% @end
%%%-------------------------------------------------------------------

-module(mod_http_upload).
-author('dmytro@xpyriens.com').

-behavior(gen_mod).
-behavior(gen_server).

-xep([{xep, 363}, {version, "0.2.3"}]).

-include("ejabberd.hrl").
-include("jlib.hrl").

-define(NS_HTTP_UPLOAD, <<"urn:xmpp:http:upload">>).
-define(SUPERVISOR, ejabberd_sup).
-define(DICT, dict).
-define(URL_ENC(URL), binary_to_list(ejabberd_http:url_encode(URL))).
-define(ADDR_TO_STR(IP), jlib:ip_to_list(IP)).
-define(STR_TO_INT(Str, B), jlib:binary_to_integer(iolist_to_binary(Str), B)).
-define(DEFAULT_CONTENT_TYPE, <<"application/octet-stream">>).
-define(CONTENT_TYPES,
        [{<<".avi">>, <<"video/avi">>},
         {<<".bmp">>, <<"image/bmp">>},
         {<<".bz2">>, <<"application/x-bzip2">>},
         {<<".gif">>, <<"image/gif">>},
         {<<".gz">>, <<"application/x-gzip">>},
         {<<".html">>, <<"text/html">>},
         {<<".jpeg">>, <<"image/jpeg">>},
         {<<".jpg">>, <<"image/jpeg">>},
         {<<".mp3">>, <<"audio/mpeg">>},
         {<<".mp4">>, <<"video/mp4">>},
         {<<".mpeg">>, <<"video/mpeg">>},
         {<<".mpg">>, <<"video/mpeg">>},
         {<<".ogg">>, <<"application/ogg">>},
         {<<".pdf">>, <<"application/pdf">>},
         {<<".png">>, <<"image/png">>},
         {<<".rtf">>, <<"application/rtf">>},
         {<<".svg">>, <<"image/svg+xml">>},
         {<<".tiff">>, <<"image/tiff">>},
         {<<".txt">>, <<"text/plain">>},
         {<<".wav">>, <<"audio/wav">>},
         {<<".webp">>, <<"image/webp">>},
         {<<".xz">>, <<"application/x-xz">>},
         {<<".zip">>, <<"application/zip">>}]).

%% API
-export([start_link/2]).

%% gen_mod callbacks
-export([start/2, stop/1]).

%% gen_server callbacks
-export([init/1, terminate/2, handle_call/3, handle_cast/2,
         handle_info/2, code_change/3]).

%% Hook callbacks
-export([iq_http_upload/3]).

%% ejabberd_hooks callback.
-export([remove_user/2]).

-record(state, {host :: binary(),
                upload_host :: binary(),
                name :: binary(),
                access :: atom(),
                max_size :: pos_integer() | infinity,
                secret_length :: pos_integer(),
                jid_in_url :: sha1 | node,
                file_mode :: integer() | undefined,
                dir_mode :: integer() | undefined,
                docroot :: binary(),
                put_url :: binary(),
                get_url :: binary(),
                service_url :: binary() | undefined,
                slots = dict:new() :: term(),
                timers = dict:new() :: term()}). % dict:dict() requires Erlang 17.

-type state() :: #state{}.
-type slot() :: [binary()].

%%====================================================================
%% API
%%====================================================================
-spec start_link(binary(), gen_mod:opts())
                -> {ok, pid()} | ignore | {error, _}.
start_link(Host, Opts) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    gen_server:start_link({local, Proc}, ?MODULE, [Host, Opts], []).

%%====================================================================
%% gen_mod callbacks
%%====================================================================
start(Host, Opts) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    %%  HttpUploadSpec = {Proc, {?MODULE, start_link, [Host, Opts]},
    %%    transient, 2000, worker, [?MODULE]},
    HttpUploadSpec = {Proc, {?MODULE, start_link, [Host, Opts]},
                      permanent, 3000, worker, [?MODULE]},
    supervisor:start_child(?SUPERVISOR, HttpUploadSpec).

stop(Host) ->
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    Pid = erlang:whereis(Proc),
    gen_server:call(Proc, stop),
    wait_for_process_to_stop(Pid),
    supervisor:delete_child(?SUPERVISOR, Proc).

%%====================================================================
%% gen_server callbacks
%%====================================================================
init([Host, Opts]) ->
    process_flag(trap_exit, true),
    IQDisc = gen_mod:get_opt(iqdisc, Opts, no_queue), %% May be used one_queue
    mod_disco:register_feature(Host, ?NS_HTTP_UPLOAD),
    gen_iq_handler:add_iq_handler(ejabberd_sm, Host, ?NS_HTTP_UPLOAD,
                                  ?MODULE, iq_http_upload, IQDisc),
    gen_iq_handler:add_iq_handler(ejabberd_local, Host, ?NS_HTTP_UPLOAD,
                                  ?MODULE, iq_http_upload, IQDisc),
    add_hooks_handlers(Host),
    {ok, #state{host = Host,
                timers = ?DICT:new()}}.

terminate(_Reason, #state{host = Host}) ->
    remove_hooks_handlers(Host),
    gen_iq_handler:remove_iq_handler(ejabberd_local, Host, ?NS_HTTP_UPLOAD),
    gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, ?NS_HTTP_UPLOAD),
    mod_disco:unregister_feature(Host, ?NS_HTTP_UPLOAD).

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Req, _From, State) ->
    {reply, {error, badarg}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Hook callbacks
%%====================================================================
iq_http_upload(_From, _To, #iq{type = Type, sub_el = SubEl} = IQ) ->
    case {Type, SubEl} of
        {get, #xmlel{name = <<"http_upload">>}} ->
            IQ#iq{type = result, sub_el = 
		      []};
        _ ->
            IQ#iq{type = error, sub_el = 
		      [SubEl, ?ERR_FEATURE_NOT_IMPLEMENTED]}
    end.

-spec remove_user(binary(), binary()) -> ok.
remove_user(User, Server) ->
    LUser = jlib:nodeprep(User),
    LServer = jlib:nameprep(Server),
    DocRoot = gen_mod:get_module_opt(LServer, ?MODULE, docroot, 
				     fun iolist_to_binary/1, <<"@HOME@/upload">>),
    JIDinURL = gen_mod:get_module_opt(LServer, ?MODULE, jid_in_url,
				      fun (sha1) -> sha1; (node) -> node end, sha1),
    UserStr = make_user_string(<<LUser/binary, $@, LServer/binary>>, JIDinURL),
    UserDir = str:join([expand_home(DocRoot), UserStr], <<$/>>),
    case del_tree(UserDir) of
        ok ->
            ?INFO_MSG("Removed HTTP upload directory of ~s@~s", [User, Server]);
        {error, enoent} ->
            ?DEBUG("Found no HTTP upload directory of ~s@~s", [User, Server]);
        {error, Error} ->
            ?ERROR_MSG("Can't remove HTTP upload directory of ~s@~s: ~p", [User, Server, Error])
    end,
    ok.

-spec del_tree(file: filename_all()) -> ok | {error, term()}.
del_tree(Dir) when is_binary(Dir) ->
    del_tree(binary_to_list(Dir));
del_tree(Dir) ->
    try
        {ok, Entries} = file:list_dir(Dir),
        lists:foreach(fun(Path) ->
                              case filelib:is_dir(Path) of
                                  true -> ok = del_tree(Path);
                                  false -> ok = file:delete(Path)
                              end
                      end, [Dir ++ "/" ++ Entry || Entry <- Entries]),
        ok = file:del_dir(Dir)
    catch
        _:{badmatch, {error, Error}} -> {error, Error};
        _:Error -> {error, Error}
    end.

%%====================================================================
%% Internal functions
%%====================================================================
add_hooks_handlers(Host) ->
    ejabberd_hooks:add(remove_user, Host,
                       ?MODULE, remove_user, 50),
    ejabberd_hooks:add(anonymous_purge_hook, Host,
                       ?MODULE, remove_user, 50).

remove_hooks_handlers(Host) ->
    ejabberd_hooks:delete(remove_user, Host,
                          ?MODULE, remove_user, 50),
    ejabberd_hooks:delete(anonymous_purge_hook, Host,
                          ?MODULE, remove_user, 50).

wait_for_process_to_stop(Pid) ->
    Ref = erlang:monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _} ->
            ok
    after
        1000 ->
            {error, still_running}
    end.

-spec make_user_string(binary(), sha1 | node) -> binary().
make_user_string(User, sha1) ->
    sha:sha1_hex(User);
make_user_string(User, node) ->
    [Node, _Domain] = binary:split(User, <<$@>>),
    re:replace(Node, <<"[^a-zA-Z0-9_.-]">>, <<$_>>, [global, {return, binary}]).

-spec expand_home(binary()) -> binary().
expand_home(Subject) ->
    {ok, [[Home]]} = init:get_argument(home),
    Parts = binary:split(Subject, <<"@HOME@">>, [global]),
    str:join(Parts, list_to_binary(Home)).

-spec expand_host(binary(), binary()) -> binary().
expand_host(Subject, Host) ->
    Parts = binary:split(Subject, <<"@HOST@">>, [global]),
    str:join(Parts, Host).
