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
-define(NS_HTTP_UPLOAD_OLD, <<"eu:siacs:conversations:http:upload">>).

-define(SERVICE_REQUEST_TIMEOUT, 5000). % 5 seconds.
-define(SLOT_TIMEOUT, 600000). % 10 minutes.

-define(SUPERVISOR, ejabberd_sup).
-define(URL_ENC(URL), binary_to_list(http_uri:encode(URL))).
-define(ADDR_TO_STR(IP), jlib:ip_to_list(IP)).
-define(STR_TO_INT(Str, B), binary_to_integer(iolist_to_binary(Str), B)).
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
-export([start/2, stop/1, iq_http_upload/3]).

%% gen_server callbacks
-export([init/1, terminate/2, handle_call/3, handle_cast/2,
         handle_info/2, code_change/3]).

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
                put_prefix :: binary(),
                get_prefix :: binary(),
                service_url :: binary() | undefined,
                slots = dict:new() :: term()}).

%%-type state() :: #state{}.
%%-type slot() :: [binary()].

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
    gen_iq_handler:add_iq_handler(ejabberd_sm, Host,
                                  ?NS_HTTP_UPLOAD, ?MODULE, iq_http_upload, IQDisc),
    gen_iq_handler:add_iq_handler(ejabberd_local, Host,
                                  ?NS_HTTP_UPLOAD, ?MODULE, iq_http_upload, IQDisc),
    add_hooks_handlers(Host),

    {ok, init_state(Host, Opts)}.

terminate(_Reason, #state{host = Host}) ->
    remove_hooks_handlers(Host),
    gen_iq_handler:remove_iq_handler(ejabberd_local, Host, ?NS_HTTP_UPLOAD),
    gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, ?NS_HTTP_UPLOAD),
    mod_disco:unregister_feature(Host, ?NS_HTTP_UPLOAD).

handle_call({use_slot, Slot}, _From, #state{host = Host,
                                            file_mode = FileMode,
                                            dir_mode = DirMode,
                                            docroot = DocRoot} = State) ->
    case get_slot(Host, Slot) of
        {ok, {Size, Timer}} ->
            timer:cancel(Timer),
            NewState = del_slot(Host, Slot),
            Path = str:join([DocRoot | Slot], <<$/>>),
            {reply, {ok, Size, Path, FileMode, DirMode}, NewState};
        _ ->
            {reply, {error, <<"Invalid slot">>}, State}
    end;
handle_call(get_docroot, _From, #state{docroot = DocRoot} = State) ->
    {reply, {ok, DocRoot}, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(Request, From, State) ->
    ?ERROR_MSG("Got unexpected request from ~p: ~p", [From, Request]),
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Hook callbacks
%%====================================================================
iq_http_upload(_From, To, #iq{type = get, xmlns = ?NS_DISCO_INFO, lang = Lang} = IQ) ->
    Host = To#jid.lserver,
    AddInfo = ejabberd_hooks:run_fold(disco_info, Host, [],
                                      [Host, ?MODULE, <<"">>, <<"">>]),
    Name = config(Host, name),
    IQ#iq{type = result,
          sub_el = [#xmlel{name = <<"query">>,
                           attrs = [{<<"xmlns">>, ?NS_DISCO_INFO}],
                           children = iq_disco_info(Lang, Name) ++ AddInfo}]};
iq_http_upload(#jid{luser = LUser, lserver = LServer} = From, #jid{lserver = Host} = _To,
               #iq{type = get, xmlns = XMLNS, lang = Lang, sub_el = SubEl} = IQ) ->

    User = <<LUser/binary, $@, LServer/binary>>,
    Access = config(Host, access),

    case acl:match_rule(Host, Access, From) of
        allow ->
            case parse_request(SubEl, Lang) of
                {ok, File, Size, ContentType} ->
                    ServiceURL = config(Host, service_url),
                    MaxSize = config(Host, max_size),
                    JIDinURL = config(Host, jid_in_url),
                    SecretLength = config(Host, secret_length),
                    case create_slot(ServiceURL, MaxSize, JIDinURL, SecretLength,
                                     User, File, Size, ContentType, Lang) of
                        {ok, Slot} ->
                            {ok, Timer} = timer:send_after(?SLOT_TIMEOUT,
                                                           {slot_timed_out, Slot}),

                            GetPrefix = config(Host, get_prefix),
                            PutPrefix = config(Host, put_prefix),

                            add_slot(Host, Slot, Size, Timer),

                            SlotEl = slot_el(Slot, PutPrefix, GetPrefix, XMLNS),
                            IQ#iq{type = result, sub_el = [SlotEl]};
                        {ok, PutPrefix, GetPrefix} ->
                            SlotEl = slot_el(PutPrefix, GetPrefix, XMLNS),
                            IQ#iq{type = result, sub_el = [SlotEl]};
                        {error, Error} ->
                            IQ#iq{type = error, sub_el = [SubEl, Error]}
                    end;
                {error, Error} ->
                    ?DEBUG("Cannot parse request from ~s", [User]),
                    IQ#iq{type = error, sub_el = [SubEl, Error]}
            end;
        deny ->
            ?DEBUG("Denying HTTP upload slot request from ~s", [User]),
            IQ#iq{type = error, sub_el = [SubEl, ?ERR_FORBIDDEN]}
    end;
iq_http_upload(_From, _To, #iq{sub_el = SubEl} = IQ) ->
    IQ#iq{type = error, sub_el = [SubEl, ?ERR_NOT_ALLOWED]};
iq_http_upload(_From, _To, reply) ->
    not_request;
iq_http_upload(_From, _To, error) ->
    not_request;
iq_http_upload(_From, _To, invalid) ->
    not_request.

-spec remove_user(binary(), binary()) -> ok.
remove_user(User, Server) ->
    LUser = jid:nodeprep(User),
    LServer = jid:nameprep(Server),
    DocRoot = gen_mod:get_module_opt(LServer, ?MODULE, docroot, <<"@HOME@/upload">>),
    JIDinURL = gen_mod:get_module_opt(LServer, ?MODULE, jid_in_url, sha1),
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

-spec init_state(binary(), binary()) -> binary().
init_config(Host, Opts) ->
    UploadHost = gen_mod:get_opt_host(Host, Opts, <<"upload.@HOST@">>),
    Name = gen_mod:get_opt(name, Opts, <<"HTTP File Upload">>),
    Access = gen_mod:get_opt(access, Opts, local),
    MaxSize = gen_mod:get_opt(max_size, Opts, infinity),
    SecretLength = gen_mod:get_opt(secret_length, Opts, 40),
    JIDinURL = gen_mod:get_opt(jid_in_url, Opts, sha1),
    DocRoot = gen_mod:get_opt(docroot, Opts, <<"@HOME@/upload">>),
    FileMode = gen_mod:get_opt(file_mode, Opts, undefined),
    DirMode = gen_mod:get_opt(dir_mode, Opts, undefined),
    PutPrefix = gen_mod:get_opt(put_prefix, Opts, <<"http://@HOST@:5444">>),
    GetPrefix = gen_mod:get_opt(get_prefix, Opts, PutPrefix),
    ServiceURL = gen_mod:get_opt(service_url, Opts),
    case ServiceURL of
        undefined ->
            ok;
        <<"http://", _/binary>> ->
            application:start(inets);
        <<"https://", _/binary>> ->
            application:start(inets),
            application:start(crypto),
            application:start(public_key),
            application:start(ssl)
    end,

    case DirMode of
        undefined ->
            ok;
        Mode ->
            file:change_mode(DocRoot, Mode)
    end,

    ets:new(gen_mod:get_module_proc(Host, config), [set, named_table]),
    ets:new(gen_mod:get_module_proc(Host, slots), [set, named_table]),

    ets:insert(gen_mod:get_module_proc(Host, config), {host, Host}),
    ets:insert(gen_mod:get_module_proc(Host, config), {upload_host, UploadHost}),
    ets:insert(gen_mod:get_module_proc(Host, config), {name, Name}),
    ets:insert(gen_mod:get_module_proc(Host, config), {access, Access}),
    ets:insert(gen_mod:get_module_proc(Host, config), {max_size, MaxSize}),
    ets:insert(gen_mod:get_module_proc(Host, config), {secret_length, SecretLength}),
    ets:insert(gen_mod:get_module_proc(Host, config), {jid_in_url, JIDinURL}),
    ets:insert(gen_mod:get_module_proc(Host, config), {file_mode, FileMode}),
    ets:insert(gen_mod:get_module_proc(Host, config), {dir_mode, DirMode}),
    ets:insert(gen_mod:get_module_proc(Host, config), {docroot, expand_home(str:strip(DocRoot, right, $/))}),
    ets:insert(gen_mod:get_module_proc(Host, config), {put_prefix, expand_host(str:strip(PutPrefix, right, $/), UploadHost)}),
    ets:insert(gen_mod:get_module_proc(Host, config), {get_prefix, expand_host(str:strip(GetPrefix, right, $/), UploadHost)}),
    ets:insert(gen_mod:get_module_proc(Host, config), {service_url, ServiceURL}),

    %%    ejabberd_router:register_route(Host),
    ok.

init_state(Host, Opts) ->
    ok = init_config(Host, Opts),
    UploadHost = config(Host, upload_host),
    Name = config(Host, name),
    Access = config(Host, access),
    MaxSize = config(Host, max_size),
    SecretLength = config(Host, secret_length),
    JIDinURL = config(Host, jid_in_url),
    FileMode = config(Host, file_mode),
    DirMode = config(Host, dir_mode),
    DocRoot = config(Host, docroot),
    PutPrefix = config(Host, put_prefix),
    GetPrefix = config(Host, get_prefix),
    ServiceURL = config(Host, service_url),
    State = #state{
               host = Host, upload_host = UploadHost, name = Name,
               access = Access, max_size = MaxSize,
               secret_length = SecretLength, jid_in_url = JIDinURL,
               file_mode = FileMode, dir_mode = DirMode,
               docroot = DocRoot,
               put_prefix = PutPrefix, get_prefix = GetPrefix,
               service_url = ServiceURL},
    %%    Proc = gen_mod:get_module_proc(Host, ?LOOPNAME),
    %%    Pid = case whereis(Proc) of
    %%              undefined ->
    %%                  SendLoop = spawn(?MODULE, send_loop, [State]),
    %%                  register(Proc, SendLoop),
    %%                  SendLoop;
    %%              Loop ->
    %%                  Loop
    %%          end,
    {ok, State}.

iq_disco_info(Lang, Name) ->
    [#xmlel{name = <<"identity">>,
            attrs = [{<<"category">>, <<"store">>},
                     {<<"type">>, <<"file">>},
                     {<<"name">>, translate:translate(Lang, Name)}]},
     #xmlel{name = <<"feature">>,
            attrs = [{<<"var">>, ?NS_HTTP_UPLOAD}]},
     #xmlel{name = <<"feature">>,
            attrs = [{<<"var">>, ?NS_HTTP_UPLOAD_OLD}]}].

parse_request(#xmlel{name = <<"request">>, attrs = Attrs} = Request, Lang) ->
    case xml:get_attr(<<"xmlns">>, Attrs) of
        {value, XMLNS} when XMLNS == ?NS_HTTP_UPLOAD;
                            XMLNS == ?NS_HTTP_UPLOAD_OLD ->
            case {xml:get_path_s(Request, [{elem, <<"filename">>}, cdata]),
                  xml:get_path_s(Request, [{elem, <<"size">>}, cdata]),
                  xml:get_path_s(Request, [{elem, <<"content-type">>}, cdata])} of
                {File, SizeStr, ContentType} when byte_size(File) > 0 ->
                    case catch binary_to_integer(SizeStr) of
                        Size when is_integer(Size), Size > 0 ->
                            {ok, File, Size, yield_content_type(ContentType)};
                        _ ->
                            Text = <<"Please specify file size.">>,
                            {error, ?ERRT_BAD_REQUEST(Lang, Text)}
                    end;
                _ ->
                    Text = <<"Please specify file name.">>,
                    {error, ?ERRT_BAD_REQUEST(Lang, Text)}
            end;
        _ ->
            {error, ?ERR_BAD_REQUEST}
    end;
parse_request(_El, _Lang) -> {error, ?ERR_BAD_REQUEST}.

-spec create_slot(binary(), binary(), binary(), binary(),
                  binary(), binary(), pos_integer(), binary(), binary())
                 -> {ok, slot()} | {ok, binary(), binary()} | {error, xmlel()}.
create_slot(undefined, MaxSize, _JIDinURL, _SecretLength,
            User, File, Size, _ContentType, Lang) when MaxSize /= infinity,
                                                       Size > MaxSize ->
    Text = <<"File larger than ", (integer_to_binary(MaxSize))/binary,
             " Bytes.">>,
    ?INFO_MSG("Rejecting file ~s from ~s (too large: ~B bytes)",
              [File, User, Size]),
    {error, ?ERRT_NOT_ACCEPTABLE(Lang, Text)};
create_slot(undefined, _MaxSize, JIDinURL, SecretLength,
            User, File, _Size, _ContentType, _Lang) ->
    UserStr = make_user_string(User, JIDinURL),
    RandStr = make_rand_string(SecretLength),
    FileStr = make_file_string(File),
    ?INFO_MSG("Got HTTP upload slot for ~s (file: ~s)", [User, File]),
    {ok, [UserStr, RandStr, FileStr]};
create_slot(ServiceURL, _MaxSize, _JIDinURL, _SecretLength,
            User, File, Size, ContentType, _Lang) ->
    Options = [{body_format, binary}, {full_result, false}],
    HttpOptions = [{timeout, ?SERVICE_REQUEST_TIMEOUT}],
    SizeStr = integer_to_binary(Size),
    GetRequest = binary_to_list(ServiceURL) ++
        "?jid=" ++ ?URL_ENC(User) ++
        "&name=" ++ ?URL_ENC(File) ++
        "&size=" ++ ?URL_ENC(SizeStr) ++
        "&content_type=" ++ ?URL_ENC(ContentType),
    case httpc:request(get, {GetRequest, []}, HttpOptions, Options) of
        {ok, {Code, Body}} when Code >= 200, Code =< 299 ->
            case binary:split(Body, <<$\n>>, [global, trim]) of
                [<<"http", _/binary>> = PutURL, <<"http", _/binary>> = GetURL] ->
                    ?INFO_MSG("Got HTTP upload slot for ~s (file: ~s)",
                              [User, File]),
                    {ok, PutURL, GetURL};
                Lines ->
                    ?ERROR_MSG("Cannot parse data received for ~s from <~s>: ~p",
                               [User, ServiceURL, Lines]),
                    {error, ?ERR_SERVICE_UNAVAILABLE}
            end;
        {ok, {402, _Body}} ->
            ?INFO_MSG("Got status code 402 for ~s from <~s>", [User, ServiceURL]),
            {error, ?ERR_RESOURCE_CONSTRAINT};
        {ok, {403, _Body}} ->
            ?INFO_MSG("Got status code 403 for ~s from <~s>", [User, ServiceURL]),
            {error, ?ERR_NOT_ALLOWED};
        {ok, {413, _Body}} ->
            ?INFO_MSG("Got status code 413 for ~s from <~s>", [User, ServiceURL]),
            {error, ?ERR_NOT_ACCEPTABLE};
        {ok, {Code, _Body}} ->
            ?ERROR_MSG("Got unexpected status code ~s from <~s>: ~B",
                       [User, ServiceURL, Code]),
            {error, ?ERR_SERVICE_UNAVAILABLE};
        {error, Reason} ->
            ?ERROR_MSG("Error requesting upload slot for ~s from <~s>: ~p",
                       [User, ServiceURL, Reason]),
            {error, ?ERR_SERVICE_UNAVAILABLE}
    end.

%% TODO: We need refactoring slots storage
add_slot(Host, Slot, Size, Timer) ->
    ets:insert(gen_mod:get_module_proc(Host, slots), {Slot, {Size, Timer}}).

get_slot(Host, Slot) ->
    {Slot, Value} = ets:lookup(gen_mod:get_module_proc(Host, slots), Slot),
    {ok ,Value}.

del_slot(Host, Slot) ->
    ets:delete(gen_mod:get_module_proc(Host, slots), Slot).

config(Host, Key) ->
    config(Host, Key, undefined).
config(Host, Key, Default) ->
    case catch ets:lookup(gen_mod:get_module_proc(Host, config), Key) of
        [{Key, Value}] -> Value;
        _ -> Default
    end.

%%-spec slot_el(slot() | binary(), state() | binary(), binary()) -> xmlel().

slot_el(Slot, PutPrefix, GetPrefix, XMLNS) ->
    PutURL = str:join([PutPrefix | Slot], <<$/>>),
    GetURL = str:join([GetPrefix | Slot], <<$/>>),
    slot_el(PutURL, GetURL, XMLNS).

slot_el(PutURL, GetURL, XMLNS) ->
    #xmlel{name = <<"slot">>,
           attrs = [{<<"xmlns">>, XMLNS}],
           children = [#xmlel{name = <<"put">>,
                              children = [{xmlcdata, PutURL}]},
                       #xmlel{name = <<"get">>,
                              children = [{xmlcdata, GetURL}]}]}.

-spec make_user_string(binary(), sha1 | node) -> binary().
make_user_string(User, sha1) ->
    sha:sha1_hex(User);
make_user_string(User, node) ->
    [Node, _Domain] = binary:split(User, <<$@>>),
    re:replace(Node, <<"[^a-zA-Z0-9_.-]">>, <<$_>>, [global, {return, binary}]).
-spec make_file_string(binary()) -> binary().
make_file_string(File) ->
    re:replace(File, <<"[^a-zA-Z0-9_.-]">>, <<$_>>, [global, {return, binary}]).

-spec make_rand_string(non_neg_integer()) -> binary().
make_rand_string(Length) ->
    list_to_binary(make_rand_string([], Length)).

-spec make_rand_string(string(), non_neg_integer()) -> string().
make_rand_string(S, 0) -> S;
make_rand_string(S, N) -> make_rand_string([make_rand_char() | S], N - 1).

-spec make_rand_char() -> char().
make_rand_char() ->
    map_int_to_char(crypto:rand_uniform(0, 62)).

-spec expand_home(binary()) -> binary().
expand_home(Subject) ->
    {ok, [[Home]]} = init:get_argument(home),
    Parts = binary:split(Subject, <<"@HOME@">>, [global]),
    str:join(Parts, list_to_binary(Home)).

-spec map_int_to_char(0..61) -> char().
map_int_to_char(N) when N =<  9 -> N + 48; % Digit.
map_int_to_char(N) when N =< 35 -> N + 55; % Upper-case character.
map_int_to_char(N) when N =< 61 -> N + 61. % Lower-case character.

-spec expand_host(binary(), binary()) -> binary().
expand_host(Subject, Host) ->
    Parts = binary:split(Subject, <<"@HOST@">>, [global]),
    str:join(Parts, Host).

-spec yield_content_type(binary()) -> binary().
yield_content_type(<<"">>) -> ?DEFAULT_CONTENT_TYPE;
yield_content_type(Type) -> Type.
