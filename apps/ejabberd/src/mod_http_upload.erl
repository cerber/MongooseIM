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

-define(DEFAULT_HOST, <<"upload.@HOST@">>).
-define(DEFAULT_NAME, <<"HTTP File Upload">>).

-define(DEFAULT_JIDINURL, sha1).
-define(DEFAULT_DOCROOT, <<"@HOME@/upload">>).
-define(DEFAULT_PREFIX, <<"http://@HOST@:5444">>).

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
-export([start_link/3]).

%% gen_mod callbacks
%%-export([start/2, stop/1, iq_http_upload/3]).
-export([start/2, stop/1]).

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

-type state() :: #state{}.
-type slot() :: [binary()].

%%====================================================================
%% API
%%====================================================================
-spec start_link(binary(), atom(), gen_mod:opts())
                -> {ok, pid()} | ignore | {error, _}.
start_link(Host, Proc, Opts) ->
    ?INFO_MSG("start_link on host: ~p Proc: ~p", [Host, Proc]),
    gen_server:start_link({local, Proc}, ?MODULE, [Host, Opts], []).

%%====================================================================
%% gen_mod callbacks
%%====================================================================
start(Host, Opts) ->
    case gen_mod:get_opt(rm_on_unregister, Opts,
                         fun(B) when is_boolean(B) -> B end,
                         true) of
        true ->
            ejabberd_hooks:add(remove_user, Host, ?MODULE, remove_user, 50),
            ejabberd_hooks:add(anonymous_purge_hook, Host, ?MODULE, remove_user, 50);
        false ->
            ok
    end,
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    HttpUploadSpec = {Proc, {?MODULE, start_link, [Host, Proc, Opts]},
                      permanent, 3000, worker, [?MODULE]},
    ?INFO_MSG("started on host: ~p with Proc=~p, Opts=~p", [Host, Proc, Opts]),
    supervisor:start_child(?SUPERVISOR, HttpUploadSpec).

stop(Host) ->
    case gen_mod:get_module_opt(Host, ?MODULE, rm_on_unregister,
                                fun(B) when is_boolean(B) -> B end,
                                true) of
        true ->
            ejabberd_hooks:delete(remove_user, Host, ?MODULE, remove_user, 50),
            ejabberd_hooks:delete(anonymous_purge_hook, Host, ?MODULE, remove_user, 50);
        false ->
            ok
    end,
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    Pid = erlang:whereis(Proc),
    gen_server:call(Proc, stop),
    wait_for_process_to_stop(Pid),
    supervisor:delete_child(?SUPERVISOR, Proc),
    ?INFO_MSG("stopped on host: ~p", [Host]).

%%====================================================================
%% gen_server callbacks
%%====================================================================
init([Host, Opts]) ->
    process_flag(trap_exit, true),
    UploadHost = gen_mod:get_opt_host(Host, Opts, ?DEFAULT_HOST),
    Name = gen_mod:get_opt(name, Opts, ?DEFAULT_NAME),
    Access = gen_mod:get_opt(access, Opts, local),
    MaxSize = gen_mod:get_opt(max_size, Opts, infinity),
    SecretLength = gen_mod:get_opt(secret_length, Opts, 40),
    JIDinURL = gen_mod:get_opt(jid_in_url, Opts, ?DEFAULT_JIDINURL),
    DocRoot = gen_mod:get_opt(docroot, Opts, ?DEFAULT_DOCROOT),
    FileMode = gen_mod:get_opt(file_mode, Opts, undefined),
    DirMode = gen_mod:get_opt(dir_mode, Opts, undefined),
    PutPrefix = gen_mod:get_opt(put_prefix, Opts, ?DEFAULT_PREFIX),
    GetPrefix = gen_mod:get_opt(get_prefix, Opts, PutPrefix),
    ServiceURL = gen_mod:get_opt(service_url, Opts, undefined),
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

    ejabberd_router:register_route(UploadHost),
    ?INFO_MSG("initialized on host: ~p with Opts=~p", [Host, Opts]),
    State = #state{
               host = Host, upload_host = UploadHost, name = Name,
               access = Access, max_size = MaxSize,
               secret_length = SecretLength, jid_in_url = JIDinURL,
               file_mode = FileMode, dir_mode = DirMode,
               docroot = expand_home(DocRoot),
               put_prefix = expand_host(PutPrefix, UploadHost),
               get_prefix = expand_host(GetPrefix, UploadHost),
               service_url = ServiceURL},
    {ok, State}.

terminate(Reason, #state{upload_host = UploadHost, host = Host}) ->
    ?DEBUG("Stopping HTTP upload process for ~s: ~p", [Host, Reason]),
    ejabberd_router:unregister_route(UploadHost),
    ok.

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

handle_cast(Request, State) ->
    ?ERROR_MSG("Got unexpected request: ~p", [Request]),
    {noreply, State}.

handle_info({route, From, To, #xmlel{name = <<"iq">>} = Stanza}, State) ->
    ?INFO_MSG("#### route: From: ~p, To: ~p, Stanza: ~p", [From, To, Stanza]),
    Request = jlib:iq_query_info(Stanza),
    {Reply, NewState} = case process_iq(From, Request, State) of
                            R when is_record(R, iq) ->
                                {R, State};
                            {R, S} ->
                                {R, S};
                            not_request ->
                                {none, State}
                        end,
    if Reply /= none ->
            ejabberd_router:route(To, From, jlib:iq_to_xml(Reply));
       true ->
            ok
    end,
    {noreply, NewState};
handle_info({slot_timed_out, Slot}, State) ->
    NewState = del_slot(Slot, State),
    {noreply, NewState};
handle_info(Info, State) ->
    ?ERROR_MSG("Got unexpected info: ~p", [Info]),
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%====================================================================
%% XMPP requests handling
%%====================================================================
process_iq(_From, #iq{type = get, xmlns = ?NS_DISCO_INFO, lang = Lang} = IQ,
           #state{upload_host = UploadHost, name = Name}) ->
    ?INFO_MSG("get discovery info. To: ~p", [UploadHost]),
    AddInfo = ejabberd_hooks:run_fold(disco_info, UploadHost, [],
                                      [UploadHost, ?MODULE, <<"">>, <<"">>]),
    IQ#iq{type = result,
          sub_el = [#xmlel{name = <<"query">>,
                           attrs = [{<<"xmlns">>, ?NS_DISCO_INFO}],
                           children = iq_disco_info(Lang, Name) ++ AddInfo}]};
process_iq(#jid{luser = LUser, lserver = LServer} = From,
           #iq{type = get, xmlns = XMLNS, lang = Lang, sub_el = SubEl} = IQ,
           #state{upload_host = UploadHost, access = Access} = State)
  when XMLNS == ?NS_HTTP_UPLOAD;
       XMLNS == ?NS_HTTP_UPLOAD_OLD ->
    User = <<LUser/binary, $@, LServer/binary>>,
    case acl:match_rule(UploadHost, Access, From) of
        allow ->
            case parse_request(SubEl, Lang) of
                {ok, File, Size, ContentType} ->
                    case create_slot(State, User, File, Size, ContentType, Lang) of
                        {ok, Slot} ->
                            {ok, Timer} = timer:send_after(?SLOT_TIMEOUT,
                                                           {slot_timed_out, Slot}),
                            NewState = add_slot(Slot, Size, Timer, State),
                            SlotEl = slot_el(Slot, State, XMLNS),
                            {IQ#iq{type = result, sub_el = [SlotEl]}, NewState};
                        {ok, PutURL, GetURL} ->
                            SlotEl = slot_el(PutURL, GetURL, XMLNS),
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
process_iq(_From, #iq{sub_el = SubEl} = IQ, _State) ->
    IQ#iq{type = error, sub_el = [SubEl, ?ERR_NOT_ALLOWED]};
process_iq(_From, reply, _State) ->
    not_request;
process_iq(_From, invalid, _State) ->
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

wait_for_process_to_stop(Pid) ->
    Ref = erlang:monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _} ->
            ok
    after
        1000 ->
            {error, still_running}
    end.


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

-spec create_slot(state(), binary(), binary(), pos_integer(), binary(),
                  binary())
                 -> {ok, slot()} | {ok, binary(), binary()} | {error, xmlel()}.
create_slot(#state{service_url = undefined, max_size = MaxSize},
            User, File, Size, _ContentType, Lang) when MaxSize /= infinity,
                                                       Size > MaxSize ->
    Text = <<"File larger than ", (integer_to_binary(MaxSize))/binary,
             " Bytes.">>,
    ?INFO_MSG("Rejecting file ~s from ~s (too large: ~B bytes)",
              [File, User, Size]),
    {error, ?ERRT_NOT_ACCEPTABLE(Lang, Text)};
create_slot(#state{service_url = undefined,
                   jid_in_url = JIDinURL,
                   secret_length = SecretLength},
            User, File, _Size, _ContentType, _Lang) ->
    UserStr = make_user_string(User, JIDinURL),
    RandStr = make_rand_string(SecretLength),
    FileStr = make_file_string(File),
    ?INFO_MSG("Got HTTP upload slot for ~s (file: ~s)", [User, File]),
    {ok, [UserStr, RandStr, FileStr]};
create_slot(#state{service_url = ServiceURL}, User, File, Size, ContentType,
            _Lang) ->
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
-spec add_slot(slot(), pos_integer(), timer:tref(), state()) -> state().
add_slot(Slot, Size, Timer, #state{slots = Slots} = State) ->
    NewSlots = dict:store(Slot, {Size, Timer}, Slots),
    State#state{slots = NewSlots}.

-spec get_slot(slot(), state()) -> {ok, {pos_integer(), timer:tref()}} | error.
get_slot(Slot, #state{slots = Slots}) ->
    dict:find(Slot, Slots).

-spec del_slot(slot(), state()) -> state().
del_slot(Slot, #state{slots = Slots} = State) ->
    NewSlots = dict:erase(Slot, Slots),
    State#state{slots = NewSlots}.

-spec slot_el(slot() | binary(), state() | binary(), binary()) -> xmlel().
slot_el(Slot, #state{put_prefix = PutPrefix, get_prefix = GetPrefix}, XMLNS) ->
    PutURL = str:join([PutPrefix | Slot], <<$/>>),
    GetURL = str:join([GetPrefix | Slot], <<$/>>),
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
