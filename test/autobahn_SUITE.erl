-module(autobahn_SUITE).

%% Runs the websocket_client against the Autobahn fuzzingserver
%% (crossbario/autobahn-testsuite) to validate RFC 6455 compliance.
%%
%% Prerequisites:
%%   docker compose -f docker-compose.autobahn.yml up -d
%%
%% Or use the convenience script:
%%   test/autobahn/run.sh

-include_lib("common_test/include/ct.hrl").

-export([
         all/0,
         init_per_suite/1,
         end_per_suite/1,
         run_autobahn_cases/1
        ]).

-define(AGENT, "websocket_client").
-define(HOST, "localhost").
-define(PORT, 9001).
-define(BASE_URL, "ws://" ++ ?HOST ++ ":" ++ integer_to_list(?PORT)).
-define(CASE_TIMEOUT, 60000).

all() -> [run_autobahn_cases].

init_per_suite(Config) ->
    case gen_tcp:connect(?HOST, ?PORT, [], 2000) of
        {ok, Sock} ->
            gen_tcp:close(Sock),
            Config;
        {error, _} ->
            {skip, "Autobahn fuzzingserver not running on port "
                   ++ integer_to_list(?PORT)}
    end.

end_per_suite(_Config) ->
    ok.

%%--- test cases --------------------------------------------------------------

run_autobahn_cases(_Config) ->
    CaseCount = get_case_count(),
    ct:pal("Autobahn test suite: ~B cases to run", [CaseCount]),

    Results = lists:map(
        fun(I) ->
            Result = run_case(I),
            case Result of
                ok ->
                    ct:pal("  Case ~B/~B: ok", [I, CaseCount]);
                {error, Reason} ->
                    ct:pal("  Case ~B/~B: ~p", [I, CaseCount, Reason])
            end,
            {I, Result}
        end,
        lists:seq(1, CaseCount)
    ),

    update_reports(),

    Errors = [{I, R} || {I, R} <- Results, R =/= ok],
    ct:pal("~nCompleted ~B cases, ~B had connection errors",
           [CaseCount, length(Errors)]),
    ct:pal("Check test/autobahn/reports/index.html for detailed results"),
    ok.

%%--- helpers -----------------------------------------------------------------

get_case_count() ->
    Self = self(),
    Ref = make_ref(),
    spawn_link(fun() ->
        process_flag(trap_exit, true),
        case websocket_client:start_link(
                ?BASE_URL ++ "/getCaseCount",
                autobahn_handler, [Self]) of
            {ok, Pid} ->
                receive
                    {'EXIT', Pid, _} -> ok
                after 10000 ->
                    exit(Pid, kill)
                end;
            {error, Reason} ->
                Self ! {Ref, {error, Reason}}
        end,
        Self ! {Ref, done}
    end),
    receive
        {autobahn_msg, _WsPid, {text, CountBin}} ->
            receive {Ref, _} -> ok after 5000 -> ok end,
            binary_to_integer(string:trim(CountBin));
        {Ref, {error, Reason}} ->
            error({connection_failed, Reason})
    after 10000 ->
        error(timeout_getting_case_count)
    end.

run_case(CaseId) ->
    URL = lists:flatten(io_lib:format(
        "~s/runCase?case=~B&agent=~s", [?BASE_URL, CaseId, ?AGENT])),
    Parent = self(),
    Ref = make_ref(),
    spawn(fun() ->
        process_flag(trap_exit, true),
        Result = try
            {ok, Pid} = websocket_client:start_link(
                URL, autobahn_handler, []),
            receive
                {'EXIT', Pid, _} -> ok
            after ?CASE_TIMEOUT ->
                exit(Pid, kill),
                {error, timeout}
            end
        catch
            _:Err -> {error, Err}
        end,
        Parent ! {Ref, Result}
    end),
    receive
        {Ref, Res} -> Res
    after ?CASE_TIMEOUT + 5000 ->
        {error, outer_timeout}
    end.

update_reports() ->
    Parent = self(),
    Ref = make_ref(),
    spawn(fun() ->
        process_flag(trap_exit, true),
        try
            {ok, Pid} = websocket_client:start_link(
                ?BASE_URL ++ "/updateReports?agent=" ++ ?AGENT,
                autobahn_handler, []),
            receive
                {'EXIT', Pid, _} -> ok
            after 30000 ->
                exit(Pid, kill)
            end
        catch
            _:_ -> ok
        end,
        Parent ! {Ref, done}
    end),
    receive
        {Ref, _} -> ok
    after 35000 ->
        ct:pal("Warning: timed out waiting for report generation")
    end.
