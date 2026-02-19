-module(rfc6455_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("websocket_req.hrl").

-compile([export_all, nowarn_export_all]).

%%====================================================================
%% CT callbacks
%%====================================================================

all() ->
    [{group, rsv_bits},
     {group, reserved_opcodes},
     {group, control_frames},
     {group, close_frames},
     {group, fragmentation},
     {group, payload_size_boundaries},
     {group, handshake_validation},
     {group, encode_close}].

groups() ->
    [{rsv_bits, [parallel],
      [t_rsv1_set_rejected,
       t_rsv2_set_rejected,
       t_rsv3_set_rejected,
       t_rsv_all_set_rejected,
       t_rsv_zero_accepted]},
     {reserved_opcodes, [parallel],
      [t_reserved_noncontrol_opcodes,
       t_reserved_control_opcodes,
       t_valid_opcodes_accepted]},
     {control_frames, [parallel],
      [t_control_frame_max_125_bytes,
       t_control_frame_oversized,
       t_control_frame_fragmented_rejected,
       t_ping_frame_roundtrip,
       t_pong_frame_roundtrip]},
     {close_frames, [parallel],
      [t_close_empty_payload,
       t_close_one_byte_payload,
       t_close_code_1000,
       t_close_code_1002,
       t_close_code_1007,
       t_close_code_1011,
       t_close_application_code_3000,
       t_close_application_code_4999,
       t_close_with_reason]},
     {fragmentation, [parallel],
      [t_two_fragment_text,
       t_two_fragment_binary,
       t_three_fragment_message,
       t_control_interleaved_with_fragments]},
     {payload_size_boundaries, [parallel],
      [t_encode_decode_0_bytes,
       t_encode_decode_125_bytes,
       t_encode_decode_126_bytes,
       t_encode_decode_65535_bytes,
       t_encode_decode_65536_bytes]},
     {handshake_validation, [parallel],
      [t_handshake_valid,
       t_handshake_wrong_accept_key,
       t_handshake_wrong_status_400,
       t_handshake_incomplete,
       t_handshake_missing_accept_header]},
     {encode_close, [parallel],
      [t_encode_close_bare_atom,
       t_encode_close_with_payload,
       t_encode_close_with_code_and_reason]}].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    Config.

end_per_testcase(_TC, _Config) ->
    ok.

%%====================================================================
%% Helpers
%%====================================================================

%% Build a raw unmasked server-to-client frame.
%% Fin: 0 or 1, RSV: 0-7, OpCode: 0-15, Payload: binary()
build_frame(Fin, RSV, OpCode, Payload) ->
    Len = byte_size(Payload),
    if
        Len < 126 ->
            <<Fin:1, RSV:3, OpCode:4, 0:1, Len:7, Payload/binary>>;
        Len =< 16#ffff ->
            <<Fin:1, RSV:3, OpCode:4, 0:1, 126:7, Len:16, Payload/binary>>;
        true ->
            <<Fin:1, RSV:3, OpCode:4, 0:1, 127:7, Len:64, Payload/binary>>
    end.

%% Create a minimal WSReq for testing decode_frame
make_wsreq() ->
    Transport = #transport{
        mod = gen_tcp,
        name = tcp,
        closed = tcp_closed,
        error = tcp_error,
        opts = []
    },
    websocket_req:new(ws, "localhost", 8080, "/", Transport, <<"dGVzdGtleQ==">>).

%% Decode a client-masked frame (as produced by encode_frame) for roundtrip testing.
%% Strips the mask bit and unmasks payload to produce a server-like frame,
%% then decodes with wsc_lib:decode_frame/2.
decode_encoded_frame(Encoded) ->
    WSReq = make_wsreq(),
    %% Client frames are masked. We need to unmask for decode_frame which
    %% expects server-to-client (unmasked) frames. However, decode_frame
    %% actually handles masked frames via unpack_frame/unmask_frame,
    %% so we can pass them directly but we need to clear the mask bit
    %% since the server wouldn't send masked frames.
    %% Actually, unpack_frame handles Mask:1 generically. Let's just decode.
    wsc_lib:decode_frame(WSReq, Encoded).

%%====================================================================
%% RSV bits tests (RFC 6455 §5.2)
%%====================================================================

t_rsv1_set_rejected(_Config) ->
    Frame = build_frame(1, 4, 1, <<"hello">>),  % RSV=4 (0b100)
    WSReq = make_wsreq(),
    {error, {invalid_rsv, 4}} = wsc_lib:decode_frame(WSReq, Frame).

t_rsv2_set_rejected(_Config) ->
    Frame = build_frame(1, 2, 1, <<"hello">>),  % RSV=2 (0b010)
    WSReq = make_wsreq(),
    {error, {invalid_rsv, 2}} = wsc_lib:decode_frame(WSReq, Frame).

t_rsv3_set_rejected(_Config) ->
    Frame = build_frame(1, 1, 1, <<"hello">>),  % RSV=1 (0b001)
    WSReq = make_wsreq(),
    {error, {invalid_rsv, 1}} = wsc_lib:decode_frame(WSReq, Frame).

t_rsv_all_set_rejected(_Config) ->
    Frame = build_frame(1, 7, 1, <<"hello">>),  % RSV=7 (0b111)
    WSReq = make_wsreq(),
    {error, {invalid_rsv, 7}} = wsc_lib:decode_frame(WSReq, Frame).

t_rsv_zero_accepted(_Config) ->
    Frame = build_frame(1, 0, 1, <<"hello">>),  % RSV=0
    WSReq = make_wsreq(),
    {frame, {text, <<"hello">>}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Frame).

%%====================================================================
%% Reserved opcodes tests (RFC 6455 §5.2)
%%====================================================================

t_reserved_noncontrol_opcodes(_Config) ->
    WSReq = make_wsreq(),
    lists:foreach(fun(Op) ->
        Frame = build_frame(1, 0, Op, <<>>),
        {error, {reserved_opcode, Op}} = wsc_lib:decode_frame(WSReq, Frame)
    end, [3, 4, 5, 6, 7]).

t_reserved_control_opcodes(_Config) ->
    WSReq = make_wsreq(),
    lists:foreach(fun(Op) ->
        Frame = build_frame(1, 0, Op, <<>>),
        {error, {reserved_opcode, Op}} = wsc_lib:decode_frame(WSReq, Frame)
    end, [11, 12, 13, 14, 15]).

t_valid_opcodes_accepted(_Config) ->
    WSReq = make_wsreq(),
    %% text
    {frame, {text, _}, _, _} = wsc_lib:decode_frame(WSReq, build_frame(1, 0, 1, <<"a">>)),
    %% binary
    {frame, {binary, _}, _, _} = wsc_lib:decode_frame(WSReq, build_frame(1, 0, 2, <<"a">>)),
    %% close (empty)
    {close, {remote, <<>>}, _} = wsc_lib:decode_frame(WSReq, build_frame(1, 0, 8, <<>>)),
    %% ping
    {frame, {ping, _}, _, _} = wsc_lib:decode_frame(WSReq, build_frame(1, 0, 9, <<>>)),
    %% pong
    {frame, {pong, _}, _, _} = wsc_lib:decode_frame(WSReq, build_frame(1, 0, 10, <<>>)).

%%====================================================================
%% Control frames tests (RFC 6455 §5.5)
%%====================================================================

t_control_frame_max_125_bytes(_Config) ->
    Payload = crypto:strong_rand_bytes(125),
    Frame = build_frame(1, 0, 9, Payload),  % ping with 125 bytes
    WSReq = make_wsreq(),
    {frame, {ping, Payload}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Frame).

t_control_frame_oversized(_Config) ->
    %% 126-byte control frame can't be encoded in the 7-bit length field
    %% for control frames (opcode >= 8). unpack_frame requires OpCode < 8
    %% for 16-bit length, so it falls through to incomplete.
    Payload = crypto:strong_rand_bytes(126),
    Frame = build_frame(1, 0, 9, Payload),  % ping with 126 bytes
    WSReq = make_wsreq(),
    {recv, _WSReq2, _} = wsc_lib:decode_frame(WSReq, Frame).

t_control_frame_fragmented_rejected(_Config) ->
    Frame = build_frame(0, 0, 9, <<"ping">>),  % FIN=0, ping
    WSReq = make_wsreq(),
    {error, {fragmented_control_frame, 9}} = wsc_lib:decode_frame(WSReq, Frame).

t_ping_frame_roundtrip(_Config) ->
    Payload = <<"ping data">>,
    Encoded = wsc_lib:encode_frame({ping, Payload}),
    %% Encoded is a masked client frame. Decode it directly (unpack_frame handles masks).
    WSReq = make_wsreq(),
    {frame, {ping, Payload}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Encoded).

t_pong_frame_roundtrip(_Config) ->
    Payload = <<"pong data">>,
    Encoded = wsc_lib:encode_frame({pong, Payload}),
    WSReq = make_wsreq(),
    {frame, {pong, Payload}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Encoded).

%%====================================================================
%% Close frames tests (RFC 6455 §5.5.1, §7.4)
%%====================================================================

t_close_empty_payload(_Config) ->
    Frame = build_frame(1, 0, 8, <<>>),
    WSReq = make_wsreq(),
    {close, {remote, <<>>}, _} = wsc_lib:decode_frame(WSReq, Frame).

t_close_one_byte_payload(_Config) ->
    Frame = build_frame(1, 0, 8, <<42>>),
    WSReq = make_wsreq(),
    {error, {invalid_close_payload, 1}} = wsc_lib:decode_frame(WSReq, Frame).

t_close_code_1000(_Config) ->
    Frame = build_frame(1, 0, 8, <<1000:16>>),
    WSReq = make_wsreq(),
    {close, {normal, <<>>}, _} = wsc_lib:decode_frame(WSReq, Frame).

t_close_code_1002(_Config) ->
    Frame = build_frame(1, 0, 8, <<1002:16>>),
    WSReq = make_wsreq(),
    {close, {error, badframe, <<>>}, _} = wsc_lib:decode_frame(WSReq, Frame).

t_close_code_1007(_Config) ->
    Frame = build_frame(1, 0, 8, <<1007:16>>),
    WSReq = make_wsreq(),
    {close, {error, badencoding, <<>>}, _} = wsc_lib:decode_frame(WSReq, Frame).

t_close_code_1011(_Config) ->
    Frame = build_frame(1, 0, 8, <<1011:16>>),
    WSReq = make_wsreq(),
    {close, {error, handler, <<>>}, _} = wsc_lib:decode_frame(WSReq, Frame).

t_close_application_code_3000(_Config) ->
    Frame = build_frame(1, 0, 8, <<3000:16>>),
    WSReq = make_wsreq(),
    {close, {remote, 3000, <<>>}, _} = wsc_lib:decode_frame(WSReq, Frame).

t_close_application_code_4999(_Config) ->
    Frame = build_frame(1, 0, 8, <<4999:16>>),
    WSReq = make_wsreq(),
    {close, {remote, 4999, <<>>}, _} = wsc_lib:decode_frame(WSReq, Frame).

t_close_with_reason(_Config) ->
    Reason = <<"going away">>,
    Payload = <<1000:16, Reason/binary>>,
    Frame = build_frame(1, 0, 8, Payload),
    WSReq = make_wsreq(),
    {close, {normal, Reason}, _} = wsc_lib:decode_frame(WSReq, Frame).

%%====================================================================
%% Fragmentation tests (RFC 6455 §5.4)
%%====================================================================

t_two_fragment_text(_Config) ->
    %% When both fragments are in the same buffer, decode_frame processes
    %% them recursively in a single call.
    Frag1 = build_frame(0, 0, 1, <<"hel">>),        % FIN=0, text
    Frag2 = build_frame(1, 0, 0, <<"lo">>),          % FIN=1, continuation
    WSReq = make_wsreq(),
    %% Pass fragments separately to test stateful continuation
    {recv, WSReq1, <<>>} = wsc_lib:decode_frame(WSReq, Frag1),
    {frame, {text, <<"hello">>}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq1, Frag2).

t_two_fragment_binary(_Config) ->
    Frag1 = build_frame(0, 0, 2, <<"hel">>),        % FIN=0, binary
    Frag2 = build_frame(1, 0, 0, <<"lo">>),          % FIN=1, continuation
    WSReq = make_wsreq(),
    {recv, WSReq1, <<>>} = wsc_lib:decode_frame(WSReq, Frag1),
    {frame, {binary, <<"hello">>}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq1, Frag2).

t_three_fragment_message(_Config) ->
    Frag1 = build_frame(0, 0, 1, <<"he">>),         % FIN=0, text
    Frag2 = build_frame(0, 0, 0, <<"ll">>),          % FIN=0, continuation
    Frag3 = build_frame(1, 0, 0, <<"o">>),           % FIN=1, continuation
    WSReq = make_wsreq(),
    %% First fragment starts continuation
    {recv, WSReq1, <<>>} = wsc_lib:decode_frame(WSReq, Frag1),
    %% Second fragment appends to continuation
    {recv, WSReq2, <<>>} = wsc_lib:decode_frame(WSReq1, Frag2),
    %% Third fragment completes reassembly
    {frame, {text, <<"hello">>}, _WSReq3, <<>>} = wsc_lib:decode_frame(WSReq2, Frag3).

t_control_interleaved_with_fragments(_Config) ->
    Frag1 = build_frame(0, 0, 1, <<"hel">>),        % FIN=0, text
    Ping  = build_frame(1, 0, 9, <<"ping">>),        % FIN=1, ping (control)
    Frag2 = build_frame(1, 0, 0, <<"lo">>),          % FIN=1, continuation
    WSReq = make_wsreq(),
    %% First fragment starts continuation
    {recv, WSReq1, <<>>} = wsc_lib:decode_frame(WSReq, Frag1),
    %% Ping is delivered as a complete frame (control frames don't interrupt fragmentation)
    {frame, {ping, <<"ping">>}, WSReq2, <<>>} = wsc_lib:decode_frame(WSReq1, Ping),
    %% Final fragment completes the text message
    {frame, {text, <<"hello">>}, _WSReq3, <<>>} = wsc_lib:decode_frame(WSReq2, Frag2).

%%====================================================================
%% Payload size boundaries tests (RFC 6455 §5.2)
%%====================================================================

t_encode_decode_0_bytes(_Config) ->
    Payload = <<>>,
    Encoded = wsc_lib:encode_frame({binary, Payload}),
    WSReq = make_wsreq(),
    {frame, {binary, Payload}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Encoded).

t_encode_decode_125_bytes(_Config) ->
    Payload = crypto:strong_rand_bytes(125),
    Encoded = wsc_lib:encode_frame({binary, Payload}),
    WSReq = make_wsreq(),
    {frame, {binary, Payload}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Encoded).

t_encode_decode_126_bytes(_Config) ->
    Payload = crypto:strong_rand_bytes(126),
    Encoded = wsc_lib:encode_frame({binary, Payload}),
    WSReq = make_wsreq(),
    {frame, {binary, Payload}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Encoded).

t_encode_decode_65535_bytes(_Config) ->
    Payload = crypto:strong_rand_bytes(65535),
    Encoded = wsc_lib:encode_frame({binary, Payload}),
    WSReq = make_wsreq(),
    {frame, {binary, Payload}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Encoded).

t_encode_decode_65536_bytes(_Config) ->
    Payload = crypto:strong_rand_bytes(65536),
    Encoded = wsc_lib:encode_frame({binary, Payload}),
    WSReq = make_wsreq(),
    {frame, {binary, Payload}, _WSReq2, <<>>} = wsc_lib:decode_frame(WSReq, Encoded).

%%====================================================================
%% Handshake validation tests (RFC 6455 §4.2.2)
%%====================================================================

t_handshake_valid(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    Accept = base64:encode(
        crypto:hash(sha, <<Key/binary, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11">>)),
    Response = <<"HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-Websocket-Accept: ", Accept/binary, "\r\n"
                 "\r\n">>,
    {ok, <<>>} = wsc_lib:validate_handshake(Response, Key).

t_handshake_wrong_accept_key(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    Response = <<"HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-Websocket-Accept: wrongkey==\r\n"
                 "\r\n">>,
    {error, invalid_handshake} = wsc_lib:validate_handshake(Response, Key).

t_handshake_wrong_status_400(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    Response = <<"HTTP/1.1 400 Bad Request\r\n"
                 "Content-Length: 0\r\n"
                 "\r\n">>,
    {error, {400, _}} = wsc_lib:validate_handshake(Response, Key).

t_handshake_incomplete(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    Response = <<"HTTP/1.1 101 Switching Proto">>,
    {notfound, Response} = wsc_lib:validate_handshake(Response, Key).

t_handshake_missing_accept_header(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    Response = <<"HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "\r\n">>,
    {error, invalid_handshake} = wsc_lib:validate_handshake(Response, Key).

%%====================================================================
%% Encode close tests (RFC 6455 §5.5.1)
%%====================================================================

t_encode_close_bare_atom(_Config) ->
    Encoded = wsc_lib:encode_frame(close),
    WSReq = make_wsreq(),
    {close, {remote, <<>>}, _} = wsc_lib:decode_frame(WSReq, Encoded).

t_encode_close_with_payload(_Config) ->
    Payload = <<1000:16, "normal closure">>,
    Encoded = wsc_lib:encode_frame({close, Payload}),
    WSReq = make_wsreq(),
    {close, {normal, <<"normal closure">>}, _} = wsc_lib:decode_frame(WSReq, Encoded).

t_encode_close_with_code_and_reason(_Config) ->
    Encoded = wsc_lib:encode_frame({close, 1000, <<"bye">>}),
    WSReq = make_wsreq(),
    {close, {normal, <<"bye">>}, _} = wsc_lib:decode_frame(WSReq, Encoded).
