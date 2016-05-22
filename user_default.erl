-module(user_default).
-compile([export_all]).
-import(lists, [foldl/3,foldr/3,zip/2,unzip/2,append/1,append/2
                ,filter/2,reverse/1,flatten/1,duplicate/2
                ,sort/1,usort/1,keysort/2,ukeysort/2
                ,concat/1,concat/2,last/1,seq/2,nth/2,member/2
                ,keyfind/3,keystore/4,nthtail/2,foreach/2]).

%% linux下return_trace()找不到
-include_lib("stdlib/include/ms_transform.hrl").

-define(G_1970_1_1_8, 62167248000).

%% 网易uu启动后就变成有2个IP了，把uu进程干掉变回1个
-define(OUTPUT(F), ?OUTPUT(F, [])).
-define(OUTPUT(F, A), io:format("~ts~n", [list_to_binary(
                            io_lib:format("~w: " ++ F, [?LINE|A])
                                           )])).

-define(DEFAULT_COMPILE_OPTS, [verbose,report_errors,report_warnings]).
-define(LOCAL_IP,           "127.0.0.1").
-define(DOMAIN,             "ljl").

-define(PRJ_CFG_DIR,        "c:/work/project/prj_server/app").
-define(PRJ_SCRIPT_DIR,     filename:join(?PRJ_CFG_DIR, "../script")).
-define(PRJ_BEAM_DIR,       filename:join(?PRJ_CFG_DIR, "../beam")).
-define(PRJ_HBEAM_DIR,      filename:join(?PRJ_CFG_DIR, "../.beam")).
-include("c:/work/project/prj_server/include/common.hrl").

%%-record(role_state, {
%%          id            = 0
%%          ,acct_name    = <<>>
%%          ,name         = 0
%%          ,pid
%%          ,conn_pid
%%         }).

%% Running a function when a module is loaded
%% 页签 -> 手游 -> 收藏 -> 第3个
-on_load(on_load/0).

%% @desc    : 每次调用hot/0时，都会走到这里
%% @return  : ok
on_load() ->
    (
     node() =:= prj_node_name()
     orelse
     node() =:= prj_node_name_test()
    ) andalso
    whereis(on_load) =:= undefined andalso
    spawn(fun() ->
                  register(on_load, self()),
                  %%IP = init_ip(),
                  IP = ?LOCAL_IP,
                  wait_until_prj_started(),
                  register(pp, spawn(fun() -> init_pp(), pp_loop([], []) end)),
                  %%pp([112]),
                  on_load_loop(IP)
          end),
    ok.

prj_node_name() -> list_to_atom("s1" ++ "@" ++ ?LOCAL_IP).

prj_node_name_test() -> list_to_atom("test" ++ "@" ++ ?DOMAIN).

ud_node_name() -> list_to_atom(atom_to_list(?MODULE) ++ "@" ++ ?DOMAIN).

on_load_loop(IP) ->
    receive
        {From, '$get_ip'=Flag} ->
            From ! {Flag, IP};
        Other ->
            ?OUTPUT("on_load进程收到未知消息: ~p", [Other])
    end,
    ?MODULE:on_load_loop(IP).

init_ip() ->
    {NewStr, Pattern} =
        case os:type() of
            {win32, _} ->
                %% 把下载iconv.exe，放到c:\windows，iconv -help
                %% 把os:cmd('ipconfig')乱码用gvim还原
                %% :set enc=latin1 粘贴 :set enc=gbk
                Str = os:cmd('ipconfig | iconv -f gbk -t utf-8'),
                {Str, case string:str(Str, "gz4399.com") > 0 of
                          true -> 
                              binary_to_list(unicode:characters_to_binary("gz4399.com.*IPv4 地址.*"));
                          false ->
                              binary_to_list(unicode:characters_to_binary("本地连接 \\d+:.*"))
                      end};
            {unix, _} ->
                {os:cmd('ifconfig'), "eth0.*"}
        end,
    IPRegular = "\\b((?:(?:25[0-5]\|2[0-4]\\d\|[01]?\\d\\d?)\\.)\{3}"
                       "(?:25[0-5]\|2[0-4]\\d\|[01]?\\d\\d?))\\b",
    Options = [ungreedy, dotall, {capture, [1], list}],
    S = binary_to_list(unicode:characters_to_binary(NewStr)),
    P = Pattern ++ IPRegular,
io:format("~n[Debug ~p ~p]~p~n~p~n", [?MODULE, ?LINE, P, S]),
    {match, [IP]} = re:run(S, P, Options),
    IP.
    
wait_until_prj_started() ->
    whereis(listener) =:= undefined andalso
    begin
        timer:sleep(1000),
        wait_until_prj_started()
    end.

init_pp() ->
    put('$pp_role_id',      0),
    put('$unpp',            0).
    
load_pp() ->
    Mod = pack_print,
    Compile = Mod:module_info(compile),
    Opts = proplists:get_value(options, Compile),
    ObjFile = code:which(Mod),
    Source = proplists:get_value(source, Compile),
    {ok, SourceBin} = file:read_file(Source),
    NewOpts = ?DEFAULT_COMPILE_OPTS ++ [{source, Source}|Opts],
    {Mod, NewObjBin} = dc:from_string(binary_to_list(SourceBin), NewOpts),
    code:load_binary(Mod, ObjFile, NewObjBin).

pp_loop(ACmds, RCmds) ->
    Cmds = 
        receive
            {pp2, {RoleId, RecvCmds}} ->
                put(pp_role_id,  RoleId),
                put(unpp,        0),
                RecvCmds;
            {pp, RecvCmds} -> 
                put(pp_role_id,  0),
                put(unpp,        0),
                RecvCmds;
            {unpp, []=RecvCmds} ->
                put(pp_role_id,  0),
                put(unpp,        1),
                RecvCmds;
            {add, RecvCmd} ->
                [RecvCmd|ACmds ++ RCmds];
            {del, RecvCmd} ->
                [X || X <- ACmds ++ RCmds, X =/= RecvCmd, X div 100 =/= RecvCmd];
            {other, check} ->
                ACmds ++ RCmds
        end,
    {NewACmds, NewRCmds}=NewCmds = foldl(fun(Cmd, {ACmdsAcc, RCmdsAcc}) ->
                    if
                        Cmd >= 10000 ->
                            {[Cmd|ACmdsAcc], RCmdsAcc};
                        Cmd >= 100,Cmd =< 999 ->
                            {ACmdsAcc, [Cmd|RCmdsAcc]};
                        true ->
                            {ACmdsAcc, RCmdsAcc}
                    end
                                         end, {[], []}, Cmds),
    ?OUTPUT("NewCmds: ~w~n", [NewCmds]),
    put(pp_accept_cmd, NewACmds),
    put(pp_range_cmd , NewRCmds),
    load_pp(),
    ?MODULE:pp_loop(NewACmds, NewRCmds).

%% print_protocol
pp(List) when is_list(List) -> ppsend(pp, List);
pp(A)                       -> ppsend(pp, [A]).
pp(A, B)                    -> ppsend(pp, [A, B]).
pp(A, B, C)                 -> ppsend(pp, [A, B, C]).
pp()                        -> ppsend(pp, []).          %% 打印全部
unpp()                      -> ppsend(unpp, []).        %% 屏蔽全部

pp2(RoleId, List) when is_list(List)    -> ppsend(pp2, {RoleId, List});
pp2(RoleId, A)                          -> ppsend(pp2, {RoleId, [A]}).
pp2(RoleId, A, B)                       -> ppsend(pp2, {RoleId, [A, B]}).
pp2(RoleId, A, B, C)                    -> ppsend(pp2, {RoleId, [A, B, C]}).
pp2(RoleId)                             -> ppsend(pp2, {RoleId, []}).           %% 打印全部

ppadd(Cmd)  -> ppsend(add, Cmd).
ppdel(Cmd)  -> ppsend(del, Cmd).
ppcheck()   -> ppsend(other, check).

ppsend(Flag, Msg) ->
    pp ! {Flag, Msg},
    ok.

%% @desc    : 区分 在线 | 离线 | 全部
%%            dc模块用到
get_pp_role_links(RoleId) ->
    case lib_role:get_pid(RoleId) of
        {ok, Pid} ->
            {_, Links} = p(Pid, links),
            [Pid|Links];
        null ->
            []
    end.

%% @return  : {ok, term()} | {false, on_load_not_exist}
get_info_from_on_load(Flag) ->
    case whereis(on_load) of
        undefined ->
            {false, on_load_not_exist};
        Pid ->
            Pid ! {self(), Flag},
            receive
                {Flag, Info} ->
                    {ok, Info}
            end
    end.

get_ip() ->
    get_info_from_on_load('$get_ip').

cs() ->
    Mods = [shell, inet, make],
    [cs(X) || X <- Mods],
    create_tags(),
    halt().

cs(Mod) ->
    {ok, SrcDir} = find_src_dir(Mod),
    Source  = filename:join(SrcDir, Mod) ++ ".erl",
    OutDir  = filename:join([SrcDir, "..", ebin]),
    IncDir  = filename:join([SrcDir, "..", include]),

%%    Opts = [export_all, debug_info, {i, IncDir}, {outdir, OutDir}],
%%    StringOpts = flatten(io_lib:format("~w", [Opts])),
%%    Str = "werl -nostick -eval \"c:c(" ++ "\\\"" ++ Source ++ "\\\","
%%            ++ StringOpts ++ "),halt()\"",
    
    %% 用~w 还是 ~p，在格式化字符串的时候起作用
    %% 辛辛苦苦对~p做了很多处理，最后改成~w就搞掂了！！！
    %% 归根到底是路径是否由双引号括住
    %% 但是为什么outdir可以用单引号，而i则必须用双引号？？？
    %% 简单弄2个文件夹inc，ebin来测试，的确i必须要字符串！！
    %% 看源码！！！

    Str = flatten(io_lib:format("erl -nostick -eval \"c:c('~s',"
                                "[export_all, debug_info, {i, ['~s']}, {outdir, '~s'}])"
                                ",halt()\"", [Source, IncDir, OutDir])),
    os:cmd(Str).

%% @desc    : 创建源文件ctags
%% ctags.exe放在此路径C:\Program Files (x86)\Vim\vim74
%% 再把路径加到环境变量，使ctags.exe生效
create_tags() ->
    {ok, Home} = find_src_dir(?MODULE),
    Libs = [erts, stdlib, kernel, sasl, ssh, tools],
    ObjDirs = string:join([io_lib:write_string(code:lib_dir(X, '*'))|| X <- Libs], " "),
    Fmt = "ctags --languages=erlang -f ~s ~s -R ~s",
    Args = [filename:join(Home, tags), filename:join(Home, "*"), ObjDirs],
    Str = flatten(io_lib:format(Fmt, Args)),
    os:cmd(Str),
    ok.

%% @desc    : 出自shell.erl
find_src_dir(?MODULE) ->
    {ok, [[Home]]} = init:get_argument(home),
    {ok, Home};
find_src_dir(Mod) when is_atom(Mod) ->
    case code:which(Mod) of
        File when is_list(File) ->
            {ok, filename:join([filename:dirname(File), "..", src])};
        preloaded ->
            {_M, _Bin, BeamFile} = code:get_object_code(Mod),
            {ok, filename:join([filename:dirname(BeamFile), "..", src])};
        _Else ->    %% non_exsiting, interpreted, cover_compiled
            _Else
    end.

find_src_dir_deep(SrcDir, FName) ->
    find_src_dir_deep(".", [SrcDir], FName).
find_src_dir_deep(_LastPath, [], _) -> null;
find_src_dir_deep(LastPath, [H|Rest], FName) ->
    Path = filename:join(LastPath, H),
    Files = filelib:wildcard("*", Path),
    case member(FName, Files) of
        true ->
            {ok, Path};
        false ->
            case find_src_dir_deep(Path, Files, FName) of
                {ok, Path2} ->
                    {ok, Path2};
                null ->
                    find_src_dir_deep(LastPath, Rest, FName)
            end
    end.

%% @desc    : 重新加载本文件
%% 此rpc保证user_default.erl和dc.erl的修改全局化
hot() ->
    {ok, Home} = find_src_dir(?MODULE),
    Opts = [debug_info, export_all, {outdir, Home}],
    [begin
         Source     = filename:join(Home, Mod) ++ ".erl",
         {ok, Mod}  = c:c(Source, Opts),
         BeamFile   = filename:join(Home, Mod) ++ code:objfile_extension(),
         {ok, Bin}  = file:read_file(BeamFile),
         rpc:eval_everywhere(nodes(connected), code, load_binary, [Mod, BeamFile, Bin])
     end || Mod <- [?MODULE]].

o(u) ->
    {ok, Home} = find_src_dir(?MODULE),
    open(filename:join(Home, ?MODULE) ++ ".erl");
o(Mod) ->
    case find_src_dir(Mod) of
        {ok, SrcDir} ->
            FName = atom_to_list(Mod) ++ ".erl",
            case find_src_dir_deep(SrcDir, FName) of
                {ok, NewSrcDir} ->
                    Path = filename:join(NewSrcDir, FName),
                    open(Path);
                null ->
                    ?OUTPUT("未找到该源文件")
            end;
        Err ->
            ?OUTPUT("~p", [Err])
    end.

open(Source) ->
    %% 这里路径++要注意！双引号要用\转义
    %% dos 下，gvim "c:/.../" 所以要把前后双引号转义
    %% Cmd = "gvim \"" ++ Source ++ "\""
    %% 或
    %% Cmd = "gvim " ++ io_lib:write_string(Source)
    Cmd = flatten(io_lib:format("gvim \"~s\"", [Source])),
    spawn(fun() -> os:cmd(Cmd) end).

ht(Mod) ->
    FName = atom_to_list(Mod) ++ ".html",
    RootDir = code:root_dir(),
    case find_src_dir(Mod) of
        {ok, SrcDir} ->
            HtmlFile = filename:join([SrcDir, "../doc/html", FName]),
            case filelib:is_file(HtmlFile) of
                true ->
                    spawn(fun() -> os:cmd(io_lib:write_string(HtmlFile)) end);
                false ->
                    ErtsDir = "erts-" ++ erlang:system_info(version),
                    ObjFile = filename:join([RootDir, ErtsDir, "doc/html", FName]),
                    case filelib:is_file(ObjFile) of
                        true ->
                            spawn(fun() -> os:cmd(io_lib:write_string(ObjFile)) end);
                        false ->
                            ?OUTPUT("未找到该html文件")
                    end
            end;
        _Err ->
            case find_src_dir_deep(RootDir, FName) of
                {ok, HtmlDir} ->
                    HtmlFile = filename:join([HtmlDir, FName]),
                    spawn(fun() -> os:cmd(io_lib:write_string(HtmlFile)) end);
                null ->
                    ?OUTPUT("深度查找失败，未找到该html文件")
            end
    end.

%% list() -> tuple()
aton(IP) when is_list(IP) -> 
    list_to_tuple([list_to_integer(T) || T <- string:tokens(IP, ".")]).

%% inet_tcp_dist.erl
split_ip(IP)                -> split(IP, $., []).
split_node(Node)            -> split(Node, $@, []).
split([Chr|T], Chr, Ack)    -> [reverse(Ack)|split(T, Chr, [])];
split([H|T], Chr, Ack)      -> split(T, Chr, [H|Ack]);
split([], _, Ack)           -> [reverse(Ack)].

%% @desc    : 获取节点监听端口
get_node_port() -> get_node_port(node()).
get_node_port(Node) when is_atom(Node) ->
    get_node_port(atom_to_list(Node));
get_node_port(Node) ->
    [Name, Address] = split_node(Node),
    case inet:getaddr(Address, inet) of
        {ok, IP} ->
            {port, _TcpPort, _Version}=Ret = erl_epmd:port_please(Name, IP),
            Ret;
        _Els ->
            _Els
    end.

get_pid(PidX) when is_atom(PidX) ->
    whereis(PidX);
get_pid(PidX) when is_integer(PidX) ->
    c:pid(0,PidX,0);
get_pid(PidX) when is_pid(PidX) ->
    PidX.

p()             -> process_info(self()).
p(PidX)         -> Pid = get_pid(PidX), process_info(Pid).
p(PidX, Key)    -> Pid = get_pid(PidX), process_info(Pid, Key).

k()             -> k(self()).
k(PidX)         -> Pid = get_pid(PidX), exit(Pid, kill).

%% @desc    : 获取进程数量
pc()            -> {erlang:system_info(process_count), erlang:system_info(process_limit)}.

gc()            -> garbage_collect().
gc(PidX)        -> garbage_collect(get_pid(PidX)).

t2l(Tab)        -> ets:tab2list(Tab).

rand(X)         ->
    <<A:32,B:32,C:32>> = crypto:strong_rand_bytes(12),
    random:seed({A,B,C}),
    random:uniform(X).

rand(A0, B0) ->
    if
        A0 =< B0 ->
            A = A0,
            B = B0;
        true ->
            A = B0,
            B = A0
    end,
    Rand = random:uniform(B - (A - 1)),
    Rand + A - 1.

ts() ->
    {M, S, _} = erlang:now(),
    M * 1000000 + S.

ts2() ->
    {M, S, Micro} = erlang:now(),
    M * 1000000 * 1000000 + S * 1000000 + Micro.

ts({Date, Time}) ->
    calendar:datetime_to_gregorian_seconds({Date, Time}) - ?G_1970_1_1_8.

dt(TS) ->
    calendar:gregorian_seconds_to_datetime(TS + ?G_1970_1_1_8).

secs() ->
    {M, S, _Micro} = erlang:now(),
    M * 1000000 + S.

%% 根据1970年以来的描述获得日期
%% @param   : int()
%% @return  : {{Y, M, D}, {H, Minu, S}}
ts2dt(Sec) ->
    OriginDT = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    DateTime = calendar:gregorian_seconds_to_datetime(Sec + OriginDT),
    calendar:universal_time_to_local_time(DateTime).

%% @param   : "2014.03.27-10:16:30"
str2ts(DateTime) ->
    {ok, [Y,M,D,H,Minu,S], []} = io_lib:fread("~d.~d.~d-~d:~d:~d", DateTime),
    dt2ts({{Y,M,D}, {H,Minu,S}}).

%% @param   : {{2014,9,5} {11,0,0}}
dt2ts({Date, Time}) ->
    case valid_date_time(Date, Time) of
        ok ->
            ConvertDT = hd(calendar:local_time_to_universal_time_dst({Date, Time})),
            DateTime = calendar:datetime_to_gregorian_seconds(ConvertDT),
            OriginDT = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
            Secs = DateTime - OriginDT,
            Secs;
        Err ->
            Err
    end.

valid_date_time({_Y, _M, _D}=Date, {H, Minu, S}=_Time) ->
    case calendar:valid_date(Date) of
        true ->
            if
                H >= 0,H =< 23,
                Minu >= 0,Minu =< 59,
                S >= 0,S =< 59 ->
                    ok;
                true ->
                    {false, bad_time}
            end;
        false ->
            {false, bad_date}
    end.

%% @param   : {{2014,03,27},{10,16,30}}
%% @return  : "2014.03.27-10:16:30"
dt2str() ->
    dt2str(erlang:localtime()).
dt2str(TupleDT) ->
    {{Y,M,D}, {H,Minu,S}} = TupleDT,
    flatten(io_lib:format("~w.~2..0w.~2..0w-~2..0w:~2..0w:~2..0w", [Y,M,D,H,Minu,S])).

%% term反序列化，string转换为term，"[{a},1]" => [{a},1]
string_to_term(Str) ->
    case erl_scan:string(Str ++ ".") of
        {ok, Tokens, _} ->
            case erl_parse:parse_term(Tokens) of
                {ok, Term} -> Term;
                Err -> Err
            end;
        _Err ->
            _Err
    end.

bitstring_to_term(BitStr) when is_binary(BitStr) ->
    string_to_term(binary_to_list(BitStr)).

pid2file() ->
    filelib:ensure_dir("c:/work/log"),
    File = "c:/work/log/processes_infos.log",
    Fun = fun(Pid) -> io_lib:format("=>~p~n~p~3n", [Pid, p(Pid)]) end,
    [H|T] = processes(),
    file:write_file(File, Fun(H)),
    {ok, Fd} = file:open(File, [write, raw, binary, append]),
    Fun2 = fun(Pid) -> file:write(Fd, Fun(Pid)) end,
    [Fun2(Pid) || Pid <- T],
    file:close(Fd).

b2e() ->
    List = filelib:wildcard("*.beam"),
    ?OUTPUT("开始反编译: ~p", [List]),
    [spawn(fun() -> b2e(File) end) || File <- List],
    ok.

%% @param   : list() | atom() | binary()
b2e(ModX) ->
    case catch beam_lib:chunks(ModX, [abstract_code]) of
        {ok, {_, [{abstract_code, {raw_abstract_v1, Forms}}]}} ->
            b2e(ModX, Forms);
        Els ->
            Els
    end.

b2e(ModX, Forms) ->
    FName = filename:rootname(ModX) ++ "_b2e.erl",
    %% tl/1干掉首行file
    List = erl_syntax:form_list(tl(Forms)),
    CT1 = erl_prettypr:format(List),
%%    ?OUTPUT("~p ~p", [io_lib:printable_list(CT1),CT1]),
    %% 干掉 (C-q Tab)，不过未能缩进对齐
    CT2 = re:replace(unicode:characters_to_binary(CT1), [$\t], duplicate(4, $ ), [{return, list}, global]),
    %% 替换模块名
    BName = filename:basename(FName, ".erl"),
    CT3 = re:replace(CT2, "-module\\(.*\\)", "-module(" ++ BName ++ ")", [{return, list}]),
    %% io:put_char(CT3)
    Content = CT3,
    file:write_file(FName, Content).

%% @desc    : 另一种反编译，牛逼啦，连注释也弄出来
%% 但只能是独立行的注释
revert(Mod) when is_atom(Mod) -> revert(Mod, atom_to_list(Mod) ++ ".erl");
revert(Source) -> revert(filename:basename(Source, ".erl"), Source).

revert(Mod, Source) ->
    {ok, Fd} = file:open(Source, [read, write]),
    {ok, Tree} = epp_dodger:parse(Fd),
    Comment = erl_comment_scan:file(Source),
    {tree, form_list, _, Tree2} = erl_recomment:recomment_forms(Tree, Comment),
    Forms = [erl_syntax:revert(X) || X <- Tree2],

%%    %% 分析注释（待考究）
%%    Ana = erl_syntax_lib:analyze_forms(Forms),
%%    ?OUTPUT("注释: ~p", [Ana]),

    b2e(Mod, Forms),
    file:close(Fd).

revert2(Mod) when is_atom(Mod) -> revert2(Mod, atom_to_list(Mod) ++ ".erl");
revert2(Source) -> revert2(filename:basename(Source, ".erl"), Source).

revert2(Mod, Source) ->
    {ok, Forms} = epp:parse_file(Source, [], ""),
    Comment = erl_comment_scan:file(Source),
    {tree, form_list, _, Tree2} = erl_recomment:recomment_forms(Forms, Comment),

%%io:format("~n[Debug ~p ~p]~p~n~n", [?MODULE, ?LINE, Tree2]),
%%    Forms2 = [erl_syntax:revert(X) || X <- Tree2],
%%io:format("~n[Debug ~p ~p]~p~n~n", [?MODULE, ?LINE, Forms]),

    %% 解决，若函数上一行是注释，则导致反编译不出这种注释，的问题
    Forms2 = foldr(fun(X, Acc) ->
                           Res = erl_syntax:revert(X),
                           case erl_syntax:type(X) =:= function of
                               true ->
                                   PreComms = erl_syntax:get_precomments(X),
                                   PreComms ++ [Res|Acc];
                              false ->
                                   [Res|Acc]
                           end
                   end, [], Tree2),

    b2e(Mod, Forms2).

%% 一个参数
%% dbg:tpl(Mod, dbg:fun2ms(fun(['_']) -> return_trace() end));
%% 两个参数
%% dbg:tpl(Mod, dbg:fun2ms(fun(['_', '_']) -> return_trace() end));
dbg(Mod) ->
    case dbg:tracer() of
        {ok, _} ->
            dbg:p(all, c),
            dbg:tpl(Mod, dbg:fun2ms(fun(['_', '_']) -> return_trace() end));
        Els ->
            Els
    end.

dbg(Mod, Fun) ->
    case dbg:tracer() of
        {ok, _} ->
            dbg:p(all, c),
            dbg:tpl(Mod, Fun, dbg:fun2ms(fun(['_', '_']) -> return_trace() end));
        Els ->
            Els
    end.

dbgadd(Mod) ->
    dbg:tpl(Mod, [{'_', [], [{return_trace}]}]).

dbgadd(Mod, Fun) ->
    dbg:tpl(Mod, Fun, [{'_', [], [{return_trace}]}]).

dbgdel(Mod) ->
    dbg:ctpl(Mod).

dbgdel(Mod, Fun) ->
    dbg:ctpl(Mod, Fun).

undbg() ->
    dbg:stop().

dbgtc(File) ->
    Fun = fun({trace, _, call, {M,F,A}}, _) ->
                  ?OUTPUT("call: ~w:~w~w~n", [M,F,A]);
             ({trace, _, return_from, {M,F,A}, R}, _) ->
                  ?OUTPUT("retn: ~w:~w/~w -> ~w~n", [M,F,A,R]);
             (A, B) ->
                  ?OUTPUT("~w: ~w~n", [A,B])
          end,
    dbg:trace_client(file, File, {Fun, []}).

lmod2() ->
    A = code:all_loaded(),
    %B = [L_X || {Mod, _Path} <- A, code:is_stickty(Mod)],
    [begin io:format("~p~n", [L_X]), c:l(Mod) end || {Mod, _Path}=L_X <- A, not code:is_sticky(Mod)].
    %[c:l(Mod) || {Mod, Path} <- A, Path =:= preloaded].
    %[c:l(Mod) || {Mod, _Path} <- A, code:is_sticky(Mod)].

lmod() ->
    [c:l(Mod) || {Mod, Path} <- code:all_loaded(), not code:is_sticky(Mod), Path =/= preloaded].

inet_tcp_sockets() ->
    Name = "tcp_inet",
    filter(
      fun(Port) ->
              case erlang:port_info(Port, name) of
                  {name, Name} -> true;
                  _ -> false
              end
      end, erlang:ports()).

s() ->
    case 
        node() =:= prj_node_name()
    of
        true ->
            Ss = inet_tcp_sockets(),
            Fs = [owner, local_address, foreign_address],
            ii(filter_socket(Ss), Fs, tcp);
        false ->
            not_prj_node
    end.

%% @desc    : 过滤socket
filter_socket([])       -> [];
filter_socket([H|T])    ->
    case {prim_inet:sockname(H), prim_inet:peername(H)} of
        {{ok, {_SIP, SPort}}, {ok, {_PIP, PPort}}} ->
            if
                SPort =:= 43992;SPort =:= 43991 ->
                    [H|filter_socket(T)];
                PPort =:= 43992;PPort =:= 43991 ->
                    [H|filter_socket(T)];
                true ->
                    filter_socket(T)
            end;
        _Els ->
            %?OUTPUT("filter_socket fail: ~w ~w ~w~n", [_Els, H, erlang:port_info(H)]),
            filter_socket(T)
    end.

%% @desc    : 组织结构并打印
ii(Ss, Fs, Proto) ->
    InfoLines   = inet_info_lines(Ss, Fs, Proto),
    HLine       = {["RoleId", "AcctName", "RoleName", "Pid"], inet_h_line(Fs)},
    Lines       = [HLine|InfoLines],

    foreach(fun({[_, _, RName, _]=RInfo, SInfo}) ->
                    RNameLen    = ii_adjust_len(13, RName),
                    RNameTS     = "~-" ++ integer_to_list(RNameLen) ++ "ts",
                    Fmt         = "~-7s ~-11ts " ++ RNameTS ++ " ~-12s ~-11s ~-15i ~-20ts~n",
                    io:format(Fmt, RInfo ++ SInfo)
            end, Lines).

ii_adjust_len(Limit, Bin) ->
    List = unicode:characters_to_list(Bin),
    ii_adjust_len2(List, length(List), Limit, Limit, 0).

ii_adjust_len2([], _OrigLen, Limit, PrintWidth, OccupyWidth) when OccupyWidth =< Limit -> PrintWidth;
ii_adjust_len2([], OrigLen, _Limit, _PrintWidth, _OccupyWidth) -> OrigLen;
ii_adjust_len2([H|T], OrigLen, Limit, PrintWidth, OccupyWidth) when H > 16#7f ->
    ii_adjust_len2(T, OrigLen, Limit, PrintWidth - 1, OccupyWidth + 2);
ii_adjust_len2([_|T], OrigLen, Limit, PrintWidth, OccupyWidth) ->
    ii_adjust_len2(T, OrigLen, Limit, PrintWidth, OccupyWidth + 1).

inet_info_lines(Ss, Fs, Proto)  -> [ii_info(S, Fs, Proto)   || S <- Ss].

ii_info(S, Fs, Proto)           -> {ii_role_info(S), inet_i_line(S, Fs, Proto)}.

inet_i_line(S, Fs, Proto)       -> [inet_info(S, F, Proto)  || F <- Fs].

%% @desc    : 获取[RoleId, AcctName, RoleName, Pid]
ii_role_info(S) when is_port(S) ->
    {connected, Owner} = erlang:port_info(S, connected),
    {links, Links} = process_info(Owner, links),
    ii_role_info2(Links).

ii_role_info2([])       -> ["0", "", "", ""];
ii_role_info2([H|T])    ->
    case catch sys:get_state(H) of
        #role_state{role_id=RoleId, acct_name=AcctName, name=RName} ->
            [integer_to_list(RoleId), AcctName, RName, pid_to_list(H)];
        _ ->
            ii_role_info2(T)
    end.

inet_h_line(Fs) -> [inet_h_field(atom_to_list(F)) || F <- Fs].

inet_h_field([C|Cs]) -> [upper(C) | inet_hh_field(Cs)].

inet_hh_field([$_,C|Cs]) -> [$\s,upper(C) | inet_hh_field(Cs)];
inet_hh_field([C|Cs]) -> [C|inet_hh_field(Cs)];
inet_hh_field([]) -> [].

upper(C) when C >= $a, C =< $z -> (C-$a) + $A;
upper(C) -> C.

%% @desc    : 直接从inet.erl拷贝过来，再用==命令对齐
%%            函数名加上前缀inet_，foreign_address分之要处理
inet_info(S, F, Proto) ->
    case F of
        owner ->
            case erlang:port_info(S, connected) of
                {connected, Owner} -> pid_to_list(Owner);
                _ -> " "
            end;
        port ->
            case erlang:port_info(S,id) of
                {id, Id}  -> integer_to_list(Id);
                undefined -> " "
            end;
        sent ->
            case prim_inet:getstat(S, [send_oct]) of
                {ok,[{send_oct,N}]} -> integer_to_list(N);
                _ -> " "
            end;
        recv ->
            case  prim_inet:getstat(S, [recv_oct]) of
                {ok,[{recv_oct,N}]} -> integer_to_list(N);
                _ -> " "
            end;
        local_address ->
            inet_fmt_addr(prim_inet:sockname(S), Proto);
        foreign_address ->
            ii_parse_address(inet_fmt_addr(prim_inet:peername(S), Proto));
        state ->
            case prim_inet:getstatus(S) of
                {ok,Status} -> inet_fmt_status(Status);
                _ -> " "
            end;
        packet ->
            case prim_inet:getopt(S, packet) of
                {ok,Type} when is_atom(Type) -> atom_to_list(Type);
                {ok,Type} when is_integer(Type) -> integer_to_list(Type);
                _ -> " "
            end;
        type ->
            case prim_inet:gettype(S) of
                {ok,{_,stream}} -> "STREAM";
                {ok,{_,dgram}}  -> "DGRAM";
                {ok,{_,seqpacket}} -> "SEQPACKET";
                _ -> " "
            end;
        fd ->
            case prim_inet:getfd(S) of
                {ok, Fd} -> integer_to_list(Fd);
                _ -> " "
            end;
        module ->
            case inet_db:lookup_socket(S) of
                {ok,Mod} -> atom_to_list(Mod);
                _ -> "prim_inet"
            end
    end.
%% Possible flags: (sorted)
%% [accepting,bound,busy,connected,connecting,listen,listening,open]
%%
inet_fmt_status(Flags) ->
    case lists:sort(Flags) of
        [accepting | _]               -> "ACCEPTING";
        [bound,busy,connected|_]      -> "CONNECTED*";
        [bound,connected|_]           -> "CONNECTED";
        [bound,listen,listening | _]  -> "LISTENING";
        [bound,listen | _]            -> "LISTEN";
        [bound,connecting | _]        -> "CONNECTING";
        [bound,open]                  -> "BOUND";
        [open]                        -> "IDLE";
        []                            -> "CLOSED";
        _                             -> "????"
    end.

inet_fmt_addr({error,enotconn}, _) -> "*:*";
inet_fmt_addr({error,_}, _)        -> " ";
inet_fmt_addr({ok,Addr}, Proto) ->
    case Addr of
        %%Dialyzer {0,0}            -> "*:*";
        {{0,0,0,0},Port} -> "*:" ++ inet_fmt_port(Port, Proto);
        {{0,0,0,0,0,0,0,0},Port} -> "*:" ++ inet_fmt_port(Port, Proto);
        {{127,0,0,1},Port} -> "localhost:" ++ inet_fmt_port(Port, Proto);
        {{0,0,0,0,0,0,0,1},Port} -> "localhost:" ++ inet_fmt_port(Port, Proto);
        {IP,Port} -> inet_parse:ntoa(IP) ++ ":" ++ inet_fmt_port(Port, Proto)
    end.

inet_fmt_port(N, Proto) ->
    case inet:getservbyport(N, Proto) of
        {ok, Name} -> Name;
        _ -> integer_to_list(N)
    end.

ii_parse_address(Address) ->
    [IP, Port] = string:tokens(Address, ":"),
    case match_ip(IP) of
        not_match ->
            flatten(io_lib:format("~s: ~s", [IP, Port]));
        Match ->
            Bin = list_to_binary(Match),
            Len = ii_adjust_len(12, Bin),
            Fmt = "~-" ++ integer_to_list(Len) ++ "ts:~s",
            flatten(io_lib:format(Fmt, [Bin, Port]))
    end.

match_ip(?LOCAL_IP)                 -> "本地"           ;
match_ip(_)                         -> not_match        .

get_ip_by_name(me)                  -> ?LOCAL_IP        ;
get_ip_by_name(_)                   -> ""               .
%% @desc    : 由owner获取socket
get_sock(PidX) ->
    do_get_sock(PidX, filter_socket(inet_tcp_sockets())).

%% @desc    : 由role_id获取socket
get_sock2(RoleId) ->
    {ok, #role_state{conn_pid=Owner}} = lib_role:get_state(RoleId),
    get_sock(Owner).

do_get_sock(PidX, Ss) ->
    Owner = get_pid(PidX),
    Fun = fun(_F, []) -> null;
             (F, [H|T]) ->
                  case erlang:port_info(H, connected) of
                      {connected, Owner} -> H;
                      _ -> F(F, T)
                  end
          end,
    Fun(Fun, Ss).

gv(RoleId, SubAtom) ->
    case lib_role:get_role_alive_pid(RoleId) of
        {ok, Pid} ->
            inc(SubAtom),
            gv_dict(Pid, SubAtom);
        null ->
            pid_not_exist
    end.

gv2(RegName, SubAtom) ->
    case catch whereis(RegName) of
        {'EXIT', _} -> pid_not_exist;
        Pid ->
            inc(SubAtom),
            gv_dict(Pid, SubAtom)
    end.

gv_dict(Pid, SubAtom) ->
    SubStr = atom_to_list(SubAtom),
    {dictionary, Dict} = process_info(Pid, dictionary),
    [KV || KV <- Dict
           ,begin
                case KV of
                    {{Key, _}, _} -> ok;
                    {Key, _} -> ok;
                    _ -> Key=''
                end,
                string:str(atom_to_list(Key), SubStr) > 0
            end].


%% @desc    : 参考shell:read_records/2
%%            加载record，相当于rr/1
inc(SubAtom) ->
    SubStr = atom_to_list(SubAtom),
    Mods = [Mod || {Mod, Path} <- code:all_loaded()
                   ,string:str(atom_to_list(Mod), SubStr) > 0
                   andalso
                   string:str(Path, ?PRJ_CFG_DIR) > 0],
    inc2(Mods).

inc2(Mods) ->
    [ShellRecords|_] = [X || X <- ets:all(), ets:info(X, name) =:= shell_records],
    Recs = append(usort([begin
                             Compile = Mod:module_info(compile),
                             Source = proplists:get_value(source, Compile),
                             IncDir = proplists:get_value(i, proplists:get_value(options, Compile)),
                             %% 注意epp:parse_file/3的第一个参数是"t.erl"不是"t.beam"
                             {ok, Forms} = epp:parse_file(Source, [IncDir], ""),
                             [{RecName, Attr} || {attributes, _, record, {RecName, _}}=Attr <- Forms]
                         end || Mod <- Mods])),
    ets:insert(ShellRecords, Recs).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
sil() ->
    Str = "on_debug() -> {ok, [none]}.",
    logger(Str).

unsil() ->
    Str = "on_debug() -> {ok, []}.",
    logger(Str).

unsil(Mod) -> do_unsil([Mod]).

do_unsil(Mods) ->
    Str = flatten(io_lib:format("on_debug() -> {ok, ~w}.", [Mods])),
    logger(Str).

%% @desc    : 区别 compile:forms/2 compile:file/2 的{outdir, OurDir}，后者才会更新.beam生成的时间
logger(Str) ->
    Mod         = handle_xge_logger,
    Compile     = Mod:module_info(compile),
    Opts        = proplists:get_value(options, Compile),
    Source      = proplists:get_value(source, Compile),
    BeamFile    = code:which(Mod),
    {ok, {_,[{_,{_,AC}}]}} = beam_lib:chunks(BeamFile, [abstract_code]),
    {ok, Ele}   = erl_parse:parse(element(2, erl_scan:string(Str))),
    NewAC       = keystore(on_debug, 3, AC, Ele),
    NewOpts     = ?DEFAULT_COMPILE_OPTS ++ [{source, Source}|Opts],
    {ok, Mod, Bin} = compile:forms(NewAC, NewOpts),
    code:load_binary(Mod, BeamFile, Bin).

%% @desc    : 屏蔽端口
sh_port(Ports) ->
    RedirNode = node(),
    rpc:multicall(get_hack_nodes(), erlang, apply, [fun() ->
        hack_kill_connections(fun(_S_SIP, _SPort, S_PIP, _PPort) ->
            ZeroIP = get_ip_by_name(zero),
            LocalIP = get_ip_by_name(local),
            MeIP = get_ip_by_name(me),
            not lists:member(S_PIP, [ZeroIP, LocalIP, MeIP])
                              end),
        hack_load_mod(?MODULE, hack_port_call_back, [RedirNode, Ports]),
        ok
                                                    end, []]),
    hack_free_connections(),
    ok.

%% @desc    : 屏蔽IP
unsh_ip() -> sh_ip(null).

sh_ip(Name) ->
    TargetIP = get_ip_by_name(Name),
    RedirNode = node(),
    rpc:multicall(get_hack_nodes(), erlang, apply, [fun() ->
        hack_load_mod(?MODULE, hack_ip_call_back, [RedirNode, TargetIP]),
        hack_kill_connections(fun(_S_SIP, SPort, S_PIP, _PPort) ->
                member(SPort, [4399]) andalso S_PIP =:= TargetIP
                              end),
        ok
                                                    end, []]),
    hack_free_connections(),
    ok.

%% IP被屏蔽的节点，无法被外界节点ping通
%% 也就是说，sh_ip(local)会导致热更新失败，要注意！！！
hack_test() ->
    TargetIP = get_ip_by_name(local),
    RedirNode = node(),
    hack_load_mod(?MODULE, hack_ip_call_back, [RedirNode, TargetIP]),
    [begin
         Port = element(2,element(2,primt_inet:sockname(X))),
         catch {ok, _S} = gen_tcp:connect(get_ip_by_name(local), Port, [])
     end || X <- inet_tcp_sockets(), hd(element(2,prim_inet:getstatus(X))) =:= accepting],
    ok.

get_hack_nodes() -> ["tom@ljl", "joe@ljl"].

hack_kill_connections(Fun) ->
    [case {prim_inet:sockname(X), prim_inet:peername(X)} of
         {{ok, {SIP, SPort}}, {ok, {PIP, PPort}}} ->
             S_PIP = inet_parse:ntoa(PIP),
             S_SIP = inet_parse:ntoa(SIP),
             case Fun(S_SIP, SPort, S_PIP, PPort) of
                 true ->
                     {connected, Owner} = erlang:port_info(X, connected),
                     {ok, {_SIP, SPort}} = prim_inet:sockname(X),
                     gen_tcp:close(X),
                     ?OUTPUT("~p 干掉已有连接(~p ~p)~n~p ~p ~p~n", [dt2str(), node(Owner), SPort, S_PIP, PPort, Owner]);
                 false ->
                     ok
             end;
         _ ->
             ok
     end || X <- inet_tcp_sockets()],
    ok.

%% @desc    : 让 [指定端口] 正在acceping的让进结束旧版本
hack_free_connections() ->
    Ports = [4399, 8101],
    [[
      %% on_load/0的时候，4399端口还没有开放
      %% gen_tcp:connect/3返回{error, econnrefused}
      %% 导致badmatch，所以用catch
      %% 如果端口未开放，则要等待，可以设置超时gen_tcp:connect/4
      catch {ok, _S} = gen_tcp:connect(?LOCAL_IP, Port, [])
      || _ <- list:seq(1,10)
     ] || Port <- Ports],
    ok.
    
%% @desc    : 回调接口全部在执行gen_tcp:accept/1的节点上执行
%%            只能用这种形式，不能用匿名函数，不然报错badfun
hack_ip_call_back(S, RedirNode, TargetIP0) ->
    TargetIP = aton(TargetIP0),
    {ok, {PIP, PPort}} = prim_inet:peername(S),
    PIP =:= TargetIP andalso
    begin
        {ok, {SIP, SPort}} = prim_inet:sockname(S),
        {connected, Owner} = erlang:port_info(S, connected),
        rpc:cast(RedirNode, erlang, apply, [fun() ->
                group_leader(whereis(user), self()),
                ?OUTPUT("~p(~p ~p)~n"
                        "来自本地: ~p ~p~n"
                        "来自对方: ~p ~p~n",
                        [dt2str(), node(Owner), Owner, inet_parse:ntoa(SIP), SPort, inet_parse:ntoa(PIP), PPort]),
                ok
                                            end, []]),
        %% kill不行，accepting进程非正常死亡
        %% 会导致重启次数过多而终止所有accepting进程，以及监督进程
        %% exit(POwner, kill)
        %% header 可以，但是服务器会打印 【未知消息】
        %% ok = inet:setopts(S, [{header, 1}])
        gen_tcp:close(S)
    end,
    ok.

hack_port_call_back(S, RedirNode, Ports) ->
    {ok, {SIP, SPort}} = prim_inet:sockname(S),
    member(SPort, Ports) andalso inet_parse:ntos(SIP) =/= get_ip_by_name(local) andalso
    spawn(fun() -> 
                  timer:sleep(3000),
                  erlang:port_info(S) =/= undefined andalso
                  begin
                      [_, _, _, StringPid] = ii_role_info(S),
                      Pid = list_to_pid(StringPid),
                      Msg = <<"小样，先别连">>,
                      [lib_conn:notify(Pid, Msg) || _ <- seq(1,10)],
                      timer:sleep(3000),
                      {ok, {PIP, PPort}} = prim_inet:peername(S),
                      {connected, Owner} = erlang:port_info(S, connected),
                      rpc:cast(RedirNode, erlang, apply, [fun() ->
                            group_leader(whereis(user), self()),
                            ?OUTPUT("~p~n~p Owner: ~p~n"
                                    "来自本地: ~s       端口: ~p~n"
                                    "屏蔽对方: ~s       端口: ~p~n",
                                    [dt2str(), node(Owner), Owner, 
                                     match_ip(inet_parse:ntoa(SIP)), SPort, match_ip(inet_parse:ntoa(PIP)), PPort]),
                            ok
                                                          end, []]),
                      gen_tcp:close(S)
                  end
          end).

hack_load_mod(ExecMod, ExecFunc, ExecArgs) ->
    Mod             = inet_tcp,
    Compile         = Mod:module_info(compile),
    Opts            = proplists:get_value(options, Compile),
    OutDir          = proplists:get_value(outdir, Opts),
    BeamFile        = filename:join(OutDir, atom_to_list(Mod) ++ code:objfile_extension()),
    IncDir          = proplists:get_value(i, Opts),
    {ok, {_, [{_, {_, AC}}]}} = beam_lib:chunks(BeamFile, [abstract_code]),
    try
        %% IP不能有.，内容不能有注释，尼玛！！！accpet/1里面不能有io:format/2
        %% erl_parse:parse/1只支持函数，匿名函数也不行！！！

        Str = 
        "           accept(L)           ->"
        "               case prim_inet:accept(L) of"
        "                   {ok, S} ->"
                                ++ flatten(io_lib:format("erlang:apply(~w,~w,[S|~w]),",
                                                         [ExecMod, ExecFunc, ExecArgs])) ++
        "                       inet_db:register_socket(S, " ++ atom_to_list(Mod) ++ "),"
        "                       {ok, S};"
        "                   Err -> Err"
        "               end.",

        {ok, Ele} = erl_parse:parse(element(2, erl_scan:string(Str))),
        NewAC =
            foldr(fun(X, RetL) ->
                          case tuple_to_list(X) of
                              [function, _, accept, 1|_] ->
                                  [Ele|RetL];
                              _ ->
                                  [X|RetL]
                          end
                  end, [], AC),
        Opts = [export_all, debug_info, {i, IncDir}, {outdir, OutDir}],
        %% compile:forms/2编译错误的话，只返回error
        {ok, Mod, Bin} = compile:forms(NewAC, ?DEFAULT_COMPILE_OPTS ++ Opts),
        %% 注意，如果有进程运行在旧版本的话，这里会把正在accept/1的进程干掉
        {module, Mode} = code:load_binary(Mod, [], Bin),
        ok
    catch
        _:Reason ->
            ?OUTPUT("植入~p代码失败: ~p~n", [Mod, Reason])
    end.













%%%% 屏蔽IP
%%unhack()        -> hack("").
%%hack()          -> hack(["192.16.251.78").
%%hack(hy)        -> hack(["172.16.251.80"]);
%%hack(TargetIPs) when is_list(TargetIPs) ->
%%    make_sure_unstick(),
%%    hack_load_mod(hack_ip_call_back, [TargetIPs]),
%%    hack_kill_connections(fun(_S_SIP, SPort, S_PIP, _PPort) ->
%%            SPort =:= 43991 andalso lists:member(S_PIP, TargetIPs)
%%                          end),
%%    hack_free_connections(),
%%    ok.
%%%% 屏蔽段
%%hack2(Part) ->
%%    make_sure_unstick(),
%%    hack_load_mod(hack_ip_part_call_back, [Part]),
%%    hack_kill_connections(fun(_S_SIP, SPort, S_PIP, _PPort) ->
%%            TargetIP = aton(S_PIP),
%%            SPort =:= 43991 andalso Part =:= element(3, TargetIP)
%%                          end),
%%    hack_free_connections(),
%%    ok.
%%make_sure_unstick() ->
%%    Mod = inet_tcp
%%    case code:is_sticky(Mod) of
%%        true ->
%%            code:unstick_mod(Mod);
%%        false ->
%%            already_unstick
%%    end.
%%hack_ip_call_back(S, TargetIPs) ->
%%    {ok, {PIP, PPort}} = prim_inet:peername(S),
%%    [begin
%%         TargetIP = atom(S_TargetIP),
%%         PIP =/= {127,0,0,1} andalso io:format("hack_ip_call_back: ~p ~p ~p ~p~n", [PIP, PPort, TargetIP, S]),
%%         PIP =:= TargetIP andalso
%%         begin
%%             {ok, {SIP, SPort}} = prim_inet:sockname(S),
%%             {connected, _Owner} = erlang:port_info(S, connected),
%%             ?OUTPUT("~p~n"
%%                     "来自本地: ~p ~p~n"
%%                     "干掉对方: ~p ~p~n",
%%                     [dt2str(),
%%                      inet_parse:ntoa(SIP), SPort,
%%                      inet_parse:ntoa(PIP), PPort]),
%%             gen_tcp:close(S)
%%         end
%%     end || S_TargetIP <- TargetIPs],
%%    ok.
%%hack_ip_part_call_back(S, Part) ->
%%    {ok, {PIP, PPort}} = prim_inet:peername(S),
%%    PIP =/= {127,0,0,1} andalso io:format("hack_ip_part_call_back: ~p ~p ~p~n", [PIP, PPort, S]),
%%    Part =:= element(3, PIP) andalso
%%    begin
%%        {ok, {SIP, SPort}} = prim_inet:sockname(S),
%%        {connected, _Owner} = erlang:port_info(S, connected),
%%        ?OUTPUT("~p~n"
%%                "来自本地: ~p ~p~n"
%%                "干掉对方: ~p ~p~n",
%%                [dt2str(),
%%                 inet_parse:ntoa(SIP), SPort,
%%                 inet_parse:ntoa(PIP), PPort]),
%%        gen_tcp:close(S)
%%    end,
%%    ok.























rec_val(Rec, Pos) when is_record(Rec, role_state) ->
    do_rec_val(record_info(fields, role_state), Rec, Pos);
rec_val(_Rdc, _Pos) ->
    rec_not_define.

do_rec_val(Fields, Rec, Pos) ->
    proplists:get_value(Pos, zip(Fields, tl(tuple_to_list(Rec)))).

tpl(tpl_copy=Tpl, ID, Pos) -> do_tpl(Tpl, ID, Pos);
tpl(_, _, _) -> tpl_not_define.

do_tpl(Tpl, ID, Pos) ->
    case catch ets:lookup(Tpl, ID) of
        {'EXIT', _} -> tpl_not_exist;
        [Tpl] -> rec_val(Tpl, Pos);
        [] -> id_not_exist
    end.

fp(FName, Fun) ->
    fprof:apply(Fun, []),
    fprof:profile(),
    fprof:analyse({dest, "c:/work" ++ FName}).

tob(List) when is_list(List) ->
    Str = flatten(string:join([do_tob(X) || X <- List], "\n")),
    ?OUTPUT("~s", [Str]);
tob(X0) ->
    X1 = do_tob(X0),
    ?OUTPUT("~s", [X1]).

do_tob(X0) ->
    X1 = length(integer_to_list(X0, 2)) / 8,
    X2 = trunc(X1),
    X3 = if X1 > X2 -> X2+1;true -> X2 end,
    B1 = [flatten(io_lib:format("~8.2.0b", [A])) || <<A>> <= <<X0:(X3*8)>>],
    B2 = string:join(B1, " "),
    concat([X0, "\t", io_lib:format("ox~.16b", [X0]), "\t", B2]).

%% @desc    : 正斜杠 转 反斜杠
bslash([])          -> [];
bslash([$/|T])      -> [$\\|bslash(T)];
bslash([Char|T])    -> [Char|bslash(T)].

ld(Mod) ->
    Compile     = Mod:module_info(compile),
    Source      = proplists:get_value(source, Compile),
    code:add_path(?PRJ_BEAM_DIR),
    c:c(Source, prj_cpl_opts()).

join_cfg(Path) ->
    filename:join(?PRJ_CFG_DIR, Path).

%% @desc    : _gvimrc中用到
prj_cpl_opts_str() ->
    "-pa " ++ ?PRJ_BEAM_DIR ++ " -pa " ++ ?PRJ_HBEAM_DIR ++
    foldr(fun(X, Acc) when is_atom(X) ->
                  " +" ++ atom_to_list(X) ++ Acc;
             ({d, Macro, true}, Acc) ->
                  " -D" ++ atom_to_list(Macro) ++ "=true" ++ Acc;
             ({i, IncDir}, Acc) ->
                  " -I \"" ++ IncDir ++ "\"" ++ Acc;
             ({outdir, OutDir}, Acc) ->
                  " -o \"" ++ OutDir ++ "\"" ++ Acc;
             (_, Acc) ->
                  Acc
          end, "", prj_cpl_opts()).

prj_cpl_opts() ->
    {ok, [{_fs0, Opts0}]} = file:consult(join_cfg("Emakefile")),
    [case X of
         {i,        IncDir} -> {i,      join_cfg(IncDir)};
         {outdir,   OutDir} -> {outdir, join_cfg(OutDir)};
         _                  -> X
     end || X <- Opts0].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%服务端文件中，找出中文字符串，或二进制
find_test() ->
    FName = "t.erl",
    {ok, Bin} = file:read_file(FName),
    Text = binary_to_list(Bin),
    {ok, Toks, _} = erl_scan:string(Text, 1, []),
    Toks.

find_srv(FName) ->
    {ok, Fd} = file:open(FName, [write]),
    Files = filelib:wildcard("c:/work/project/**/*.{erl,hrl}"),
    NotInclude = ["lib_chat_gm.erl"],
    [begin
         {ok, Bin} = file:read_file(Src),
         Text = binary_to_list(Bin),
         {ok, Toks, _} = erl_scan:string(Text, 1, []),
         Matchs = find_srv3(Toks, []),
         Matchs =/= [] andalso io:format(Fd, "~p:~n~s~n", [Src, Matchs])
     end || Src <- Files, not member(filename:basename(Src), NotInclude)],
    file:close(Fd).

find_srv3([], Acc) -> reverse(Acc);
find_srv3([{string, Line, Str}|T], Acc0) ->
    case Str =:= unicode:characters_to_list(list_to_binary(Str)) of
        true -> Acc = Acc0;
        false ->
            Ele = flatten(io_lib:format("~-4B:    ~s~n", [Line, Str])),
            Acc = [Ele|Acc0]
    end,
    find_srv3(T, Acc);
find_srv3([{'?',_},_,{'(',_}|T], Acc) ->
    Fun = fun(_, [{')', _}|Rest]) -> Rest;
             (F, [_|Rest]) -> F(F, Rest)
          end,
    TT = Fun(Fun, T),
    find_srv3(TT, Acc);
find_srv3([{'<<',Line}|T], Acc0) ->
    Fun = fun(_, Flag, Buf, [{'>>', _}|Rest]) -> {Flag, Buf, Rest};
             (F, Flag, Buf, [{string, _, Str}|Rest]) ->
                  case Str =:= unicode:characters_to_list(list_to_binary(Str)) of
                      true -> Flag2 = Flag;
                      false -> Flag2 = 1
                  end,
                  Buf2 = [Str|Buf],
                  F(F, Flag2, Buf2, Rest);
             (F, Flag, Buf, [{_, _, X}|Rest]) ->
                  F(F, Flag, [X|Buf], Rest);
             (F, Flag, Buf, [{_, X}|Rest]) ->
                  F(F, Flag, [X|Buf], Rest)
          end,
    case Fun(Fun, 0, [], T) of
        {1, Buf, TT} ->
            Ele = flatten(io_lib:format("~-4B:    ~s~n", [Line, reverse(Buf)])),
            find_srv3(TT, [Ele|Acc0]);
        {0, _, TT} ->
            find_srv3(TT, Acc0)
    end;
find_srv3([_|T], Acc) ->
    find_srv3(T, Acc).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%客户端的.prefab文件中，找出中文
parse_text([], Acc) -> reverse(Acc);
parse_text([$\\, $u, A, B, C, D|T], Acc) ->
    Digit = list_to_integer([A,B,C,D], 16),
    parse_text(T, [<<Digit/utf8>>|Acc]);
parse_text([H|T], Acc) ->
    parse_text(T, [H|Acc]).

get_group(List) ->
    {match, Matchs} = re:run(List, "\n---!u!1 &(\\d+)\n.*\n  m_Component:\n.*  - 4: {fileID: \(\\d+\)}\n.*\n  m_Name: \(\\w+\)\n",
                             [ungreedy, {capture, [1,2,3],list},dotall,global]),
    Group1 = [{{obj_id, GameObjectId}, TransformId, Name} || [GameObjectId, TransformId, Name] <- Matchs],
    {match, [[GameObjectId, []]|T]} = re:run(List, "\n--- !u!4 &.*\n  m_GameObject: {fileID: \(\\d+\)}\n|\n  - {fileID: (\\d+)}",
                                             [ungreedy, {capture, [1,2], list}, dotall, global]),
    Group2 = get_group2(T, GameObjectId, []),
    Group1 ++ Group2.

get_group2([], _, Acc) -> Acc;
get_group2([[NextGameObjectId, []]|T], _GameObjectId, Acc) ->
    get_group2(T, NextGameObjectId, Acc);
get_group2([[[], TransformId]|T], GameObjectId, Acc) ->
    get_group2(T, GameObjectId, [{{trans_id, TransformId}, GameObjectId}|Acc]).

get_text(_File, Bin) ->
    case re:split(Bin, "\n  mText: \"") of
        [_, _|_]=_Split ->
            {match, Matchs} = re:run(Bin, "^--- !u!114.+m_GameObject: {fileID: (\\d+?)}[^!]+mText: \"(.+)\"", 
                                     [ungreedy, {capture, [1,2], list}, dotall, global, multiline]),
            Matchs;
        [_] ->
            []
    end.

get_parent_split(GroupList, GameObjectId, Acc) ->
    case keyfind({obj_id, GameObjectId}, 1, GroupList) of
        {_, TransformId, Name} ->
            case keyfind({trans_id, TransformId}, 1, GroupList) of
                {_, NextGameObjectId} ->
                    ?MODULE:get_parent_split(GroupList, NextGameObjectId, ["    ", Name|Acc]);
                false ->
                    [Name|Acc]
            end;
        false ->
            Acc
    end.

find_cli(ProcNum) ->
    spawn(fun() ->
                  put(num, 1),
        Files = filelib:wildcard("project/**/*.prefab"),
        FileInfos = [{File, filelib:file_size(File)} || File <- Files],
        file:write_file("files.txt", [flatten(io_lib:format("~p", [FileInfos]))]),
        TS = ts(),
        find_cli2({length(Files), 0}, ProcNum, Files, []),
        ?OUTPUT("Coset: ~p~n", [ts() - TS])
          end).

find_cli2({Limit, Limit}, _, [], []) -> ok;
find_cli2({Limit, Limit}, _, [], ContentAcc) ->
    {Y, M, D} = date(),
    Num = get(num),
    FName = flatten(io_lib:format("~4..0B~2..0B~2..0B_~2..0B.txt", [Y, M, D, Num])),
    put(num, Num+1),
    file:write_file(FName, ContentAcc);
find_cli2(Info, ProcNum, [File|Rest], ContentAcc) when ProcNum > 0 ->
    Parent = self(),
    _Pid = spawn(fun() ->
                         TS = ts(),
        {ok, Bin} = file:read_file(File),
        Child = self(),
        case get_text(File, Bin) of
            [] ->
                Parent ! {Child, nomatch, File};
            TextList ->
                GroupList = get_group(Bin),
                AllContent = [receive {Pid, Res} -> Res end
                              || Pid <- [spawn(fun() ->
                                                       Path = ?MODULE:get_parent_split(GroupList, GameObjectId, []),
                                                       Text2 = parse_text(Text, []),
                                                       Content = [$\n, Path, $\n, Text, $\n, Text2, $\n],
                                                       Child ! {self(), Content}
                                               end) || [GameObjectId, Text] <- TextList]],
                Parent ! {Child, match, File, ["---------- ", File, $\n, AllContent], TS}
        end
                 end),
    ?MODULE:find_cli2(Info, ProcNum-1, Rest, ContentAcc);
find_cli2({Limit, Len}, _, Files, ContentAcc) ->
    receive
        {_Pid, match, _File, Content, _TS} ->
            ContentAcc2 = Content ++ "\n\n" ++ ContentAcc,
            Size = byte_size(list_to_binary(ContentAcc2)),
            case Size > 100*1024 of
                true ->
                    {Y, M, D} = date(),
                    Num = get(num),
                    FName = flatten(io_lib:format("~4..0B~2..0B~2..0B_~2..0B.txt", [Y, M, D, Num])),
                    put(num, Num+1),
                    file:write_file(FName, ContentAcc2),
                    NewContentAcc = [];
                false ->
                    NewContentAcc = ContentAcc2
            end;
        {_Pid, nomatch, _File} ->
            NewContentAcc = ContentAcc
    end,
    ?MODULE:find_cli({Limit, Len+1}, 1, Files, NewContentAcc).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%中文转韩文接口处理
change(FName) ->
    {ok, Fd} = file:open(FName, [write]),
    Files = filelib:wildcard("c:/work/project/**/*.erl"),
    NotInclude = ["lib_chat_gm.erl"],
    put(lang_fd, Fd),
    put(lang_id, 1),
    [begin
         {ok, Bin} = file:read_file(Src),
         Text = binary_to_list(Bin),
         {ok, Toks, _} = erl_scan:string(Text, 1, [return]),
         put(lang_file, Src),
         io:format(Fd, "---------- ~s~n~n", [Src]),
         _Matchs = change2(Toks, []),
         io:format(Fd, "~n~n", [])
     end || Src <- Files,not member(filename:basename(Src), NotInclude)],
    file:close(Fd).

skip(_Start, Close, [{Close, _}=H|T], Acc) ->
    {T, [H|Acc]};
skip(Start, Close, [{Start, _}=H|T], Acc) ->
    {T2, Toks} = skip(Start, Close, T, [H|Acc]),
    skip(Start, Close, T2, Toks ++ Acc);
skip(Start, Close, [{Sign, _}=H|T], Acc) when is_atom(Sign) ->
    skip(Start, Close, T, [H|Acc]);
skip(Start, Close, [{_, _, _}=H|T], Acc) ->
    skip(Start, Close, H, [T|Acc]).

%% @desc    : erl_syntax.erl type/1 里面有各种Tok的描述
change2([], Acc) -> append(reverse([to_list(X) || X <- Acc]));
change2([{'<<'=Start, _}=H|T], Acc) ->
    {T2, Toks} = skip(Start, '>>', T, [H]),
    Toks2 = reverse(Toks),
    Matchs = change3(tl(Toks2), Toks2, [], []),
    change2(T2, [Matchs|Acc]);
change2([{'?', _}=H1, {var, _, _}=H2, {'('=Start, _}=H3|T], Acc) ->
    {T2, Toks} = skip(Start, ')', T, reverse([H1, H2, H3])),
    Toks2 = reverse(Toks),
    change2(T2, Toks2 ++ Acc);
change2([{string, _Line, String}|T], Acc) ->
    String2 = [$"|String ++ "\""],
    change2(T, [String2|Acc]);
change2([{dot, Line1}, Ele|T], Acc) ->
    case Ele of {Sign, Line2} when is_atom(Sign) -> ok;{_, Line2, _} -> ok end,
    Add = case Line2 - Line1 =:= 1 of true -> ".\n";false -> "." end,
    change2([Ele|T], [Add|Acc]);
change2([{dot, _}|T], Acc) ->
    change2(T, ["."|Acc]);
change2([{Sign, _}|T], Acc) when is_atom(Sign) ->
    change2(T, [Sign|Acc]);
change2([{atom, _, Var}|T], Acc) ->
    Var2 = flatten(io_lib:format("~w", [Var])),
    change2(T, [Var2|Acc]);
change2([{_, _, Var}|T], Acc) ->
    change2(T, [Var|Acc]).

change3([{'<<', _}|_]=_Rest, Toks, _, _) ->
    append([to_list(X) || X <- Toks]);
change3([{char, _, Char}|T], Toks, StringBuf, ArgBuf) ->
    Ele = [$$, Char],
    ArgBuf2 = [Ele|ArgBuf],
    change3(T, Toks, StringBuf, ArgBuf2);
change3([{'?', _}, {_, _, Var}|T], Toks, StringBuf, ArgBuf) ->
    Ele = [$?|to_list(Var)],
    ArgBuf2 = [Ele|ArgBuf],
    change3(T, Toks, StringBuf, ArgBuf2);
change3([{',', _}|T], Toks, StringBuf, ArgBuf) ->
    change3(T, Toks, StringBuf, ArgBuf);
change3([{white_space, _, _}|T], Toks, StringBuf, ArgBuf) ->
    change3(T, Toks, StringBuf, ArgBuf);
change3([{var, _, _}, {':', _}, {_, _, _}, {'/', _}, {atom, _, binary}|_]=_Rest, Toks, _, _) ->
    append([to_list(X) || X <- Toks]);
change3([{var, _, _}, {':', _}, {integer, _, _}|_]=_Rest, Toks, _, _) ->
    append([to_list(X) || X <- Toks]);
change3([{var, _, Var}, {'/', _}, {atom, _, binary}|T], Toks, StringBuf, ArgBuf) ->
    ArgBuf2 = [Var|ArgBuf],
    change3(T, Toks, StringBuf, ArgBuf2);
change3([{var, _, '_'=Var}|T], Toks, StringBuf, ArgBuf) ->
    ArgBuf2 = [Var|ArgBuf],
    change3(T, Toks, StringBuf, ArgBuf2);
change3([{'(', _}
         ,{atom, _, Var}
         ,{'(', _}
         ,{var, _, Var2}
         ,{')', _}
         ,{')', _}
         ,{'/', _}
         ,{atom, _, binary}|T], Toks, StringBuf, ArgBuf) ->
    Ele = to_list(Var) ++ "(" ++ to_list(Var2) ++ ")",
    ArgBuf2 = [Ele|ArgBuf],
    change3(T, Toks, StringBuf, ArgBuf2);
change3([{'(', _}
         ,{atom, _, Var}
         ,{'(', _}
         ,{'?', _}
         ,{var, _, Var2}
         ,{')', _}
         ,{')', _}
         ,{'/', _}
         ,{atom, _, binary}|T], Toks, StringBuf, ArgBuf) ->
    Ele = to_list(Var) ++ "(" ++ to_list(Var2) ++ ")",
    ArgBuf2 = [Ele|ArgBuf],
    change3(T, Toks, StringBuf, ArgBuf2);
change3([{string, _, String}|T], Toks, StringBuf, ArgBuf) ->
    StringBuf2 = [String|StringBuf],
    change3(T, Toks, StringBuf2, ArgBuf);
change3([{'>>', _Line}], Toks, StringBuf, ArgBuf) ->
    StringList = unicode:characters_to_list(list_to_binary(StringBuf)),
    case io_lib:latin1_char_list(StringList) of
        true ->
            append([to_list(X) || X <- Toks]);
        false ->
            LangId = get(lang_id),
            put(lang_id, LangId+1),
            ArgBuf2 = [$[|string:join(reverse([to_list(X) || X <- ArgBuf]), ", ")] ++ "])",
            Res = "util:lang(" ++ to_list(LangId) ++ ", " ++ ArgBuf2,
            Ori = append([to_list(X) || X <- Toks]),
            io:format(get(lang_fd), "~s~n~s~n~n", [Ori, Res]),
            Res
    end;
change3(_Rest, Toks, _, _) ->
    append([to_list(X) || X <- Toks]).

to_list({Var, _}) -> to_list(Var);
to_list({string, _, Var}) -> to_list([$"|Var ++ "\""]);
to_list({_, _, Var}) -> to_list(Var);
to_list(Var) when is_list(Var) -> Var;
to_list(Var) when is_atom(Var) -> atom_to_list(Var);
to_list(Var) when is_integer(Var) -> integer_to_list(Var);
to_list(Var) when is_float(Var) -> float_to_list(Var, [{decimals, 10}, compact]).


res() ->
    ObjNode = prj_node_name(),
    ScriptDir = ?PRJ_SCRIPT_DIR,
    %% 要是加上 -noshell 会和 c:cd/1 冲突，导致中间节点卡住
    spawn(fun() ->
        %% 第一层用 ~s，嵌套中用 ~w 无敌，2个~w都可以换成'~s'
        Cmd = flatten(io_lib:format("werl -setcookie abc -name ~s -eval \""
            "rpc:call(~w, erlang, apply, [fun() -> erlang:halt() end, []])"
            ",c:cd(~w)"
            ",spawn(fun() -> os:cmd(~w) end)"
            ",timer:sleep(1000)"
            "\" -s erlang halt",
            [ud_node_name(), ObjNode, ScriptDir, 'start.bat'])),
        os:cmd(Cmd)
          end).

epp(FName) -> epp(FName, ["."]).

epp(FName, IncludePath) -> epp(FName, IncludePath, "").

epp(FName, IncludePath, PredefMacros) -> 
    {ok, Pid} = epp:open(FName, IncludePath, PredefMacros),
    do_epp(Pid).

%% epp("t.erl", [], [{'PRINT_PACKET', true}]) 对比 c(t, [{d, 'PRINT_PACKET', true}])
do_epp(Pid) when is_pid(Pid) ->
    case epp:parse_erl_form(Pid) of
        {eof, _} ->
            epp:close(Pid);
        Res ->
            ?OUTPUT("epp: ~p~n", [Res]),
            do_epp(Pid)
    end.

shuffle(List) ->
    lists:sort(fun(_, _) -> random:uniform(2) =:= 1 end, List).

shuffle2(List) ->
    do_shuffle2(length(List), array:from_list(List)).

do_shuffle2(0, Acc) ->
    array:to_list(Acc);
do_shuffle2(N, Acc0) ->
    A = random:uniform(N) - 1,
    ValA = array:get(A, Acc0),
    ValN = array:get(N-1, Acc0),
    Acc1 = array:set(N-1, ValA, Acc0),
    Acc2 = array:set(A, ValN, Acc1),
    do_shuffle2(N-1, Acc2).

shuffle3(List) ->
    Len = length(List),
    A = [{random:uniform(Len), X} || X <- List],
    B = [X || {_, X} <- lists:sort(A)],
    B.

saveh(File) ->
    {ok, Io} = file:open(File, [write, read, delayed_write]),
    GetHist = fun() ->
        {links, [Shell|_]} = hd(process_info(self(), [links])),
        Shell ! {shell_req, self(), get_cmd},
        receive {shell_rep, Shell, R} -> R end
    end,
    Commands = lists:sort([{N,C} || {{command, N}, C} <- GetHist()]),
    try
        [case Trees of 
         []     -> ok;
         [T]    -> io:format(Io, "~s.\n", [erl_prettypr:format(T)]);
         [T|Ts] -> io:format(Io, "~s~s.\n", [
                    erl_prettypr:format(T), [", "++erl_prettypr:format(Tree) || Tree <- Ts]
                   ])
         end || {_, Trees} <- Commands],
        ok
    after 
        file:close(Io)
    end.
    
% Profiling functions inspired by Ulf Wiger post:
% http://www.erlang.org/pipermail/erlang-questions/2007-August/028462.html

tc(N, F) when N > 0 ->
    time_it(fun() -> exit(call(N, N, F, erlang:now())) end).

tc(N, M, F, A) when N > 0 ->
    time_it(fun() -> exit(call(N, N, M, F, A, erlang:now())) end).

time_it(F) -> 
    Pid  = spawn_opt(F, [{min_heap_size, 16384}]),
    MRef = erlang:monitor(process, Pid),
    receive
    {'DOWN', MRef, process, _, Result} -> Result
    end.

call(1, X, F, Time1) ->
    Res = (catch F()),
    return(X, Res, Time1, erlang:now());
call(N, X, F, Time1) ->
    (catch F()),
    call(N-1, X, F, Time1).

call(1, X, M, F, A, Time1) ->
    Res = (catch apply(M, F, A)),
    return(X, Res, Time1, erlang:now());
call(N, X, M, F, A, Time1) ->
    catch apply(M, F, A),
    call(N-1, X, M, F, A, Time1).

return(N, Res, Time1, Time2) ->
    Int   = timer:now_diff(Time2, Time1),
    {Int, Int / N, Res}.

-spec command(string()) -> {integer(), list()}.
command(Cmd) ->
    command(Cmd, [], undefined).

-spec command(string(), list()|undefined|fun((list(),any()) -> any())) ->
    {integer(), any()}.
command(Cmd, Fun) when is_function(Fun, 2) ->
    command(Cmd, [], Fun);
command(Cmd, Opt) when is_list(Opt) ->
    command(Cmd, Opt, undefined).

-spec command(string(), list(), undefined|fun((list(),any()) -> any())) ->
    {integer(), any()}.
command(Cmd, Opt, Fun) when is_list(Opt), Fun=:=undefined orelse is_function(Fun, 2) ->
    Opts = Opt ++ [stream, exit_status, use_stdio, in, hide, eof],
    P    = open_port({spawn, Cmd}, Opts),
    get_data(P, Fun, []).

-spec status(integer()) ->
        {status, ExitStatus :: integer()} |
        {signal, Singnal :: integer(), Core :: boolean()}.
status(Status) when is_integer(Status) ->
    TermSignal = Status band 16#7F,
    IfSignaled = ((TermSignal + 1) bsr 1) > 0,
    ExitStatus = (Status band 16#FF00) bsr 8,
    case IfSignaled of
        true ->
            CoreDump = (Status band 16#80) =:= 16#80,
            {signal, TermSignal, CoreDump};
        false ->
            {status, ExitStatus}
    end.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
get_data(P, Fun, D) ->
    receive
        {P, {data, {eol, Line}}} when Fun =:= undefined ->
            get_data(P, Fun, [Line|D]);
        {P, {data, {eol, Line}}} when is_function(Fun, 2) ->
            get_data(P, Fun, Fun(Line, D));
        {P, {data, {noeol, Line}}} when Fun =:= undefined ->
            get_data(P, Fun, [Line|D]);
        {P, {data, {noeol, Line}}} when is_function(Fun, 2) ->
            get_data(P, Fun, Fun(Line, D));
        {P, {data, D1}} when Fun =:= undefined ->
            get_data(P, Fun, [D1|D]);
        {P, {data, D1}} when is_function(Fun, 2) ->
            get_data(P, Fun, Fun(D1, D));
        {P, eof} ->
            port_close(P),
            receive
                {P, {exit_status, 0}} when is_function(Fun, 2) ->
                    {ok, Fun(eof, D)};
                {P, {exit_status, N}} when is_function(Fun, 2) ->
                    {error, {N, Fun(eof, D)}};
                {P, {exit_status, 0}} ->
                    {ok, lists:reverse(D)};
                {P, {exit_status, N}} ->
                    {error, {N, lists:reverse(D)}}
            after 2000 ->
                %throw({no_exit_status, Fun(eof, D)})
                {ok, lists:reverse(D)}
            end
    end.

res2() ->
    spawn(fun() ->
        Cmd = flatten(io_lib:format("werl -noshell -sname ~s -eval \""
            "erlang:display(aaaaa)"
            ",io:format(\\\"good~~n\\\")"
            ",erlang:display(bbbbb)"
            ",timer:sleep(3000)"
            "\" -s erlang halt",
            [tom@ljl])),
        os:cmd(Cmd)
          end).

%%%% @desc    : 新建tom@ljl节点，在节点上执行res3()
%%%%            问题是，新建的ud@ljl节点卡住
%%res3() ->
%%    spawn(fun() ->
%%        Cmd = flatten(io_lib:format("werl -noshell -sname ~s -eval \""
%%            "rpc:call('~s', erlang, apply, [fun() -> erlang:halt() end, []])"
%%            ",erlang:display(aaaaa)"
%%            ",io:format(\\\"good~~n\\\")"
%%            ",erlang:display(bbbbb)"
%%            ",timer:sleep(3000)"
%%            "\" -s erlang halt",
%%            [ud(), tom@ljl])),
%%        os:cmd(Cmd)
%%          end).
%%

t() ->
    {ok, Bin} = file:read_file("../src/_lib/pack.erl"),
    dynamic_compile:from_string(binary_to_list(Bin), prj_cpl_opts()).

pr(V) ->
    [RT|_] = [X || X <- ets:all(), ets:info(X, name) =:= shell_records],
    io:format("~s~n", [lists:flatten(pr(V, RT))]).

pr(V, RT) ->
    io_lib_pretty:print(V, ([{column, 1}, {line_length, 80}, {depth, -1}, {max_chars, 60},
                             {record_print_fun, record_print_fun(RT)}, {encoding, unicode}])).

record_print_fun(RT) ->
    fun(Tag, NoFields) ->
            case ets:lookup(RT, Tag) of
                [{_,{attribute,_,record,{Tag,Fields}}}] 
                                  when length(Fields) =:= NoFields ->
                    record_fields(Fields);
                _ ->
                    no
            end
    end.

record_fields([{record_field,_,{atom,_,Field}} | Fs]) ->
    [Field | record_fields(Fs)];
record_fields([{record_field,_,{atom,_,Field},_} | Fs]) ->
    [Field | record_fields(Fs)];
record_fields([]) ->
    [].

range_value(List, Value) ->
    range_value(List, Value, 0).

range_value([], _Value, Default) ->
    Default;
range_value([{Min, Max, Find}|_T], Value, _Default) when Value >= Min, Value =< Max ->
    Find;
range_value([{_, 0, Find}], _Value, _Default) ->
    Find;
range_value([_|T], Value, Default) ->
    range_value(T, Value, Default).

save_role(RoleId) ->
    srv_role:cast(RoleId, fun(RS) -> handle_role:save_data(RS) end).

%%test() ->
%%    Mod = pack_print,
%%    Compile = Mod:module_info(compile),
%%    Opts = proplists:get_value(options, Compile),
%%    _ObjFile = code:which(Mod),
%%    Source = proplists:get_value(source, Compile),
%%    {ok, SourceBin} = file:read_file(Source),
%%    NewOpts = ?DEFAULT_COMPILE_OPTS ++ [{source, Source}|Opts],
%%    {Mod, NewObjBin} = dc:from_string(binary_to_list(SourceBin), NewOpts),
%%    NewObjBin.
