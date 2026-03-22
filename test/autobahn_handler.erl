-module(autobahn_handler).

-behaviour(websocket_client).

-export([
         init/1,
         onconnect/2,
         ondisconnect/2,
         websocket_handle/3,
         websocket_info/3,
         websocket_terminate/3
        ]).

%% Args: [] or [ParentPid]
%% When a parent pid is provided, received text/binary frames are
%% forwarded to it as {autobahn_msg, WsPid, Frame}.
init(Args) ->
    State = case Args of
        []                          -> #{};
        [Parent] when is_pid(Parent) -> #{parent => Parent}
    end,
    {once, State}.

onconnect(_WSReq, State) ->
    {ok, State}.

ondisconnect(_Reason, State) ->
    {close, normal, State}.

websocket_handle({text, Msg}, _Req, State) ->
    maybe_notify(State, {text, Msg}),
    {reply, {text, Msg}, State};
websocket_handle({binary, Msg}, _Req, State) ->
    maybe_notify(State, {binary, Msg}),
    {reply, {binary, Msg}, State};
websocket_handle({ping, _Payload}, _Req, State) ->
    %% The library auto-responds with pong; nothing extra needed.
    {ok, State};
websocket_handle({pong, _Payload}, _Req, State) ->
    {ok, State}.

websocket_info(_Info, _Req, State) ->
    {ok, State}.

websocket_terminate(_Reason, _Req, _State) ->
    ok.

%%--- internal ---------------------------------------------------------------

maybe_notify(#{parent := Parent}, Frame) ->
    Parent ! {autobahn_msg, self(), Frame};
maybe_notify(_, _Frame) ->
    ok.
