%%%-------------------------------------------------------------------
%%% @author Dmytro Nezhynskyi <dmytro@xpyriens.com>
%%% @copyright (C) 2016, Dmytro Nezhynskyi
%%% @doc XEP-0363: HTTP File Upload
%%% @end
%%%-------------------------------------------------------------------

-module(mod_http_upload_listener).
-author('dmytro@xpyriens.com').

-include("ejabberd.hrl").

%% common callbackks
-export([init/3]).

%% cowboy_http_handler callbacks
-export([handle/2,
         terminate/3]).

-record(state, {}).

-type option() :: {atom(), any()}.
-type state() :: #state{}.

%%--------------------------------------------------------------------
%% common callback
%%--------------------------------------------------------------------
-spec init({atom(), http}, cowboy_req:req(), [option()])
          -> {ok, cowboy_req:req(), state()} |
             {shutdown, cowboy_req:req(), state()} |
             {upgrade, protocol, cowboy_websocket, cowboy_req:req(), state()}.
init({tcp, http}, Req, Opts) ->
    ?INFO_MSG("Initialization with req: ~p and Opts: ~p", [Req, Opts]),
    {ok, Req, #state{}};
init(_, Req, Opts) ->
    ?INFO_MSG("Unsupported protocol. Req: ~p, Opts: ~p", [Req, Opts]),
    {shutdown, Req, #state{}}.

%%--------------------------------------------------------------------
%% cowboy_http_handler callbacks
%%--------------------------------------------------------------------
-spec handle(cowboy_req:req(), state()) -> {ok, cowboy_req:req(), state()}.
handle(Req, State) ->
    ?INFO_MSG("Handle Request: ~p, State: ~p", [Req, State]),
    {ok, Req, State}.

-spec terminate(any(), cowboy_req:req(), state()) -> ok.
terminate(Reason, Req, State) ->
    ?INFO_MSG("Terminate with reason: ~p and Request: ~p. State: ~p", [Reason, Req, State]),
    ok.
