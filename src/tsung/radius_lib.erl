-module(radius_lib).
-author('prahveen@sigscale.org').

-export([install_db/4]).
-export([user/1]).
-export([stop/2, lookup_user/3, register_user/2, transfer_ownsership/1, get_user/2]).

-include("ts_radius.hrl").
-include("ts_config.hrl").

%---------------------------------------------------------------
%% CallBack Function for tsung config file
%---------------------------------------------------------------

%% @doc CB for xml config file
user({_Pid, DynVars}) ->
	case ts_dynvars:lookup(tab_id, DynVars) of
		false ->
			"_start";
		{ok, Tab} ->
			{ok, PrevUser} = ts_dynvars:lookup(username, DynVars),
			get_user(Tab, PrevUser)
	end.

%-----------------------------------------------------------------
%% CallBack Function for RADIUS pulgin
%-----------------------------------------------------------------

-spec install_db(Type, Pid, NasID, Tab) ->
		{ok, Tab} | {error, Reason} when
	Type :: string(),
	Pid :: pid(),
	NasID :: string(),
	Tab :: atom(),
	Reason :: term().
install_db("auth", AuthPid, NasID, Tab) ->
	case pg2:join(auths_available, AuthPid) of
		{error, {no_such_group, _}} ->
			pg2:create(auths_available),
			install_db("auth", AuthPid, NasID, Tab);
		ok ->
			ets:new(Tab, ?SessionTabOptions),
			ets:insert(Tab, {'next_key', "$_info", NasID, AuthPid, undefined, undefined}), %% {'$_info', auth_user_id, auth_pid, acct_user_id, acct_pid}
			{ok, Tab}
	end;
install_db("acct", AcctPid, NasID, Tab) ->
	case get_closest_pid(auths_available, AcctPid) of
		{error, {Reason, _}} ->
			{error, Reason};
		Proc ->
			case global:set_lock({?MODULE, Proc}) of
				true ->
					case find_table(Proc) of
						{ok, T} ->
							case ets:lookup(T, "$_info") of
								[{_, Key, AutherUserID, AuthPid, undefined, undefined}] ->
									ets:insert(T, {'next_key', Key, AutherUserID, AuthPid, NasID, AcctPid}),
									pg2:leave(auths_available, AuthPid),
									global:del_lock({?MODULE, Proc}),
									{ok, T};
								[{_, _, _, AuthPid, _, _}] ->
									pg2:leave(auths_available, AuthPid),
									install_db("acct", AcctPid, NasID, Tab);
								[] ->
									{error, not_found}
							end;
						not_found ->
							{error, not_found}
					end;
				false ->
					install_db("acct", AcctPid, NasID, Tab)
			end
	end.

-spec register_user(Tab, User) ->
		ok  when
	Tab :: atom(),
	User :: binary() | list().
%% @doc Register authenticated users
register_user(Tab, User) when is_binary(User)->
	register_user(Tab, binary_to_list(User));
register_user(Tab, User) when is_list(User) ->
	ets:insert(Tab, #radius_user{username = User}),
	ok.

-spec transfer_ownsership(Tab) ->
		ok when
	Tab :: atom().
transfer_ownsership(Tab) ->
	PID = self(),
	case ets:lookup(Tab, "$_info") of
		[{_, _, _, _, _, PID}] ->
			ok;
		[{_, _, _, _, undefined, undefined}] ->
			receive
			after
				300 ->
					transfer_ownsership(Tab)
			end;
		[{_, _Key, AutherUserID, AuthPid, AcctUserID, AcctPid}] ->
			ets:setopts(Tab, {heir, AcctPid,
				[io:fwrite("Successfully transfer ownership {~p, ~p}
				to {~p, ~p} ~n", [AutherUserID, AuthPid, AcctUserID, AcctPid])]}),
			ok;
		[] ->
			ok
	end.

-spec get_user(Tab, PrevUser) ->
		User when
	Tab :: atom(),
	PrevUser :: string(),
	User :: binary() | string().
%% @doc Get authenticated users.
get_user(Tab, first) ->
	case ets:first(Tab) of
		"$_info" ->
			ets:next(Tab, "$_info");
		User ->
			User
	end;
get_user(Tab, PrevUser) ->
	case ets:next(Tab, PrevUser) of
		'$end_of_table' ->
			ets:first(Tab);
		User ->
			User
	end.

-spec lookup_user(Tab, Key, Interval) ->
		{Type, User} when
	Tab :: atom(),
	Key :: string() | '$end_of_table',
	Interval :: integer(),
	Type :: interim | start,
	User :: string().
%% @doc lookup user record
lookup_user(Tab, '$end_of_table', Interval) ->
	do_sleep(Tab, Interval);
lookup_user(Tab, Key, Interval) ->
	case ets:lookup(Tab, Key) of
		[{next_key, "$_info", _, _, _, _}] ->
			lookup_user(Tab, ets:next(Tab, Key), Interval);
		[#radius_user{username = Key, start_time = undefined,
				last_update = undefined} = UR] ->
			ets:insert(Tab, UR#radius_user{start_time = erlang:now(),
					last_update = erlang:now()}),
			{start, Key};
		[#radius_user{username = Key, last_update = LUpdate} = UR] ->
			Elapsed = ts_utils:elapsed(LUpdate, erlang:now()),
			case Elapsed > Interval of
				true ->
					ets:insert(Tab, UR#radius_user{last_update = erlang:now()}),
					{interim, Key};
				false ->
					lookup_user(Tab, ets:next(Tab, Key), Interval)
			end;
		[] ->
			lookup_user(Tab, ets:next(Tab, Key), Interval)
	end.

-spec stop(Tab, Key) ->
		User | finish when
	Tab :: atom(),
	Key :: string(),
	User :: string().
%% @doc select username for send accounting stop
stop(Tab, Key) ->
	case ets:lookup(Tab, Key) of
		[{next_key, "$_info", _, _, _, _}] ->
			stop(Tab, ets:next(Tab, Key));
		[#radius_user{username = Key, start_time = STime}] when STime =/= undefined ->
			ets:insert(Tab, #radius_user{username = Key}),
			Key;
		[#radius_user{}] ->
			stop(Tab, ets:next(Tab, Key));
		[] ->
			finish
	end.
%------------------------------------------------------------
%% Internal Functions
%------------------------------------------------------------
find_table(OP) ->
	{ok, CHost} = ts_utils:node_to_hostname(node()),
	StringTabs = [atom_to_list(Tab) || Tab <- ets:all(), is_atom(Tab)],
	find_table1(OP, CHost, StringTabs).
%% @hidden
find_table1(OP, CHost, [Tab | Tail]) ->
	case string:sub_string(Tab, 1, string:len(CHost)) of
		CHost ->
			case ets:info(list_to_existing_atom(Tab), owner) of
				OP ->
					{ok, list_to_existing_atom(Tab)};
				_ ->
					find_table1(OP, CHost, Tail)
			end;
		_ ->
			find_table1(OP, CHost, Tail)
	end;
find_table1(OP, CHost, []) ->
	not_found.

do_sleep(Tab, Interval) ->
	receive
	after
		Interval ->
			lookup_user(Tab, ets:first(Tab), Interval)
	end.

get_closest_pid(Group, AcctPid) ->
	pg2:join(auths_available, AcctPid),
	AvailableMems = pg2:get_members(auths_available),
	pg2:leave(auths_available, AcctPid),
	get_closest_pid1(AvailableMems, Group, AcctPid).
%% @hidden
get_closest_pid1([AcctPid | T], Group, AcctPid) ->
	get_closest_pid1(T, Group, AcctPid);
get_closest_pid1([H | _], _Group, _AcctPid) ->
	H;
get_closest_pid1([], Group, AcctPid) ->
	{error, {group, Group}};
get_closest_pid1({error, _} = Reason, _Gropu, _AcctPid) ->
	Reason.
