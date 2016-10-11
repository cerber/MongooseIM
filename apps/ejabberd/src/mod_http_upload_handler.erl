%%%-------------------------------------------------------------------
%%% @author Dmytro Nezhynskyi <dmytro@xpyriens.com>
%%% @copyright (C) 2016, Dmytro Nezhynskyi
%%% @doc XEP-0363: HTTP File Upload
%%% @end
%%%-------------------------------------------------------------------

-module(mod_http_upload_handler).
-author('dmytro@xpyriens.com').

-include("ejabberd.hrl").

-behabiour(cowboy_http_handler).

%% common callbackks
-export([init/3]).

-record(state, {}).

-type option() :: {atom(), any()}.
-type state() :: #state{}.

-define(ADDR_TO_STR(IP), jlib:ip_to_list(IP)).

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

%%--------------------------------------------------------------------
%% common callback
%%--------------------------------------------------------------------
-spec init({atom(), http}, cowboy_req:req(), [option()])
          -> {ok, cowboy_req:req(), state()} |
             {shutdown, cowboy_req:req(), state()} |
             {upgrade, protocol, cowboy_websocket, cowboy_req:req(), state()}.
init({tcp, http}, Req, _Opts) ->
    {Method, _} = cowboy_req:method(Req),
    {ok, process(Method, Req), #state{}};
init(_Method, Req, Opts) ->
    ?INFO_MSG("Unsupported protocol. Req: ~p, Opts: ~p", [Req, Opts]),
    {shutdown, Req, #state{}}.

-spec process(binary(), cowboy_req:req()) -> cowboy_req:req().
process(<<"PUT">>, Req) ->
    [Host, {IP, _Port}, LocalPath] = cowboy_req:get([host, peer, path], Req),
    Proc = gen_mod:get_module_proc(Host, mod_http_upload),
    {ok, Headers, Req2} = cowboy_req:read_part(Req),
    {ok, Data, _Req3} = cowboy_req:read_part_body(Req2),
    {file, <<"inputfile">>, Filename, ContentType, _TE}
        = cow_multipart:form_data(Headers),
    ?INFO_MSG("Received file ~p of content-type ~p",
              [Filename, ContentType]),

    case catch gen_server:call(Proc, {use_slot, LocalPath}) of
        {ok, Size, Path, FileMode, DirMode} when byte_size(Data) == Size ->
            ?DEBUG("Storing file from ~s for ~s: ~s", [?ADDR_TO_STR(IP), Host, Path]),
            case store_file(Path, Data, FileMode, DirMode) of
                ok ->
                    http_response(Host, 201);
                {error, Error} ->
                    ?ERROR_MSG("Cannot store file ~s from ~s for ~s: ~s",
                               [Path, ?ADDR_TO_STR(IP), Host, Error]),
                    http_response(Host, 500)
            end;
        {ok, Size, Path} ->
            ?INFO_MSG("Rejecting file ~s from ~s for ~s: Size is ~B, not ~B",
                      [Path, ?ADDR_TO_STR(IP), Host, byte_size(Data), Size]),
            http_response(Host, 413);
        {error, Error} ->
            ?INFO_MSG("Rejecting file from ~s for ~s: ~p",
                      [?ADDR_TO_STR(IP), Host, Error]),
            http_response(Host, 403);
        Error ->
            ?ERROR_MSG("Cannot handle PUT request from ~s for ~s: ~p",
                       [?ADDR_TO_STR(IP), Host, Error]),
            http_response(Host, 500)
    end;
process(Method, Req)
  when Method == <<"GET">>;
       Method == <<"HEAD">> ->
    [Host, {IP, _Port}, LocalPath] = cowboy_req:get([host, peer, path], Req),
    ?DEBUG("### Request processing to host: ~p, from ~p, LocalPath: ~p",
           [Host, ?ADDR_TO_STR(IP), LocalPath]),
    Proc = gen_mod:get_module_proc(Host, ?MODULE),
    case catch gen_server:call(Proc, get_docroot) of
        {ok, DocRoot} ->
            Path = str:join([DocRoot | LocalPath], <<$/>>),
            case file:read_file(Path) of
                {ok, Data} ->
                    ?INFO_MSG("Serving ~s to ~s", [Path, ?ADDR_TO_STR(IP)]),
                    FileName = lists:last(LocalPath),
                    ContentType = guess_content_type(FileName,
                                                     ?DEFAULT_CONTENT_TYPE,
                                                     ?CONTENT_TYPES),
                    Headers1 = case ContentType of
                                   <<"image/", _SubType/binary>> -> [];
                                   <<"text/", _SubType/binary>> -> [];
                                   _ ->
                                       [{<<"Content-Disposition">>,
                                         <<"attachment; filename=",
                                        $", FileName/binary, $">>}]
                               end,
                    Headers2 = [{<<"Content-Type">>, ContentType} | Headers1],
                    http_response(Host, 200, Headers2, Data);
                {error, eacces} ->
                    ?INFO_MSG("Cannot serve ~s to ~s: Permission denied",
                              [Path, ?ADDR_TO_STR(IP)]),
                    http_response(Host, 403);
                {error, enoent} ->
                    ?INFO_MSG("Cannot serve ~s to ~s: No such file or directory",
                              [Path, ?ADDR_TO_STR(IP)]),
                    http_response(Host, 404);
                {error, eisdir} ->
                    ?INFO_MSG("Cannot serve ~s to ~s: Is a directory",
                              [Path, ?ADDR_TO_STR(IP)]),
                    http_response(Host, 404);
                {error, Error} ->
                    ?INFO_MSG("Cannot serve ~s to ~s: ~p",
                              [Path, ?ADDR_TO_STR(IP), Error]),
                    http_response(Host, 500)
            end;
        Error ->
            ?ERROR_MSG("### Hi Gideon! Cannot handle ~s request from ~s for ~s: ~p",
                       [Method, ?ADDR_TO_STR(IP), Host, Error]),
            http_response(Host, 500)
    end;
process(<<"OPTIONS">>, Req) ->
    [Host, {IP, _Port}] = cowboy_req:get([host, peer], Req),
    ?DEBUG("Responding to OPTIONS request from ~s for ~s",
           [?ADDR_TO_STR(IP), Host]),
    http_response(Host, 200);
process(Method, Req) ->
    [Host, {IP, _Port}] = cowboy_req:get([host, peer], Req),
    ?DEBUG("Rejecting ~s request from ~s for ~s",
           [Method, ?ADDR_TO_STR(IP), Host]),
    http_response(Host, 405, [{<<"Allow">>, <<"OPTIONS, HEAD, GET, PUT">>}]).

%% -spec http_response(binary(), 100..599) ->
%%                           cowboy_req:req()
http_response(Host, Code) ->
    http_response(Host, Code, []).

%%-spec http_response(binary(), 100..599, [{binary(), binary()}]) ->
%%                           cowboy_req:req()
http_response(Host, Code, ExtraHeaders) ->
    Message = <<(code_to_message(Code))/binary, $\n>>,
    http_response(Host, Code, ExtraHeaders, Message).

%%-spec http_response(binary(), 100..599, [{binary(), binary()}], binary()) ->
%%                           cowboy_req:req().
http_response(_Host, Code, ExtraHeaders, Body) ->
    ServerHeader = {<<"Server">>,
    %%                 <<"MongooseIM ", list_to_binary(?VERSION)/binary>>},
                        <<"MongooseIM "/binary>>},
    CustomHeaders = [],
    Headers = case proplists:is_defined(<<"Content-Type">>, ExtraHeaders) of
                  true ->
                      [ServerHeader | ExtraHeaders];
                  false ->
                      [ServerHeader, {<<"Content-Type">>, <<"text/plain">>} | ExtraHeaders]
              end ++ CustomHeaders,
    cowboy_req:reply(Code, Headers, Body).

-spec code_to_message(100..599) -> binary().
code_to_message(201) -> <<"Upload successful">>;
code_to_message(403) -> <<"Forbidden">>;
code_to_message(404) -> <<"Not found">>;
code_to_message(405) -> <<"Method not allowed">>;
code_to_message(413) -> <<"File size dowsn't match requested size">>;
code_to_message(500) -> <<"Internal server error">>;
code_to_message(_Code) -> <<"">>.

-spec store_file(file:filename_all(), binary(), integer(), integer())
                -> ok | {error, term()}.
store_file(Path, Data, FileMode, DirMode) ->
    try
        ok = filelib:ensure_dir(Path),
        {ok, Io} = file:open(Path, [write, exclusive, raw]),
        Ok = file:write(Io, Data),
        ok = file:close(Io),
        if is_integer(FileMode) ->
                ok = file:change_mode(Path, FileMode);
           FileMode == undefined ->
                ok
        end,
        if is_integer(DirMode) ->
                RandDir = filename:dirname(Path),
                UserDir = filename:dirname(RandDir),
                ok = file:change_mode(RandDir, DirMode),
                ok = file:change_mode(UserDir, DirMode);
           DirMode == undefined ->
                ok
        end,
        ok = Ok % Raise an exception if file:write/2 failed.
    catch
        _:{badmatch, {error, Error}} ->
            {error, Error};
        _:Error ->
            {error, Error}
    end.

guess_content_type(Filename, DefaultContentType, ContentTypes) ->
    Extension = str:to_lower(filename:extension(Filename)),
    case lists:keysearch(Extension, 1, ContentTypes) of
        {value, {_, ContentType}} -> ContentType;
        false -> DefaultContentType
    end.
