-module(radius_lib).
-author('prahveen@sigscale.org').

-export([install_db/4]).
-export([user/1]).
-export([register_user/2, transfer_ownsership/1, get_user/2]).

-include("ts_radius.hrl").

%---------------------------------------------------------------
%% CallBack Function for tsung config file
%---------------------------------------------------------------

%% @doc CB for xml config file
user({_Pid, DynVars}) ->
	case ts_dynvars:lookup(tab_id, DynVars) of
		false ->
			"_start";
		{ok, Tab} ->
			PrevUser = ts_dynvars:lookup(username, DynVars),
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
			ets:insert(Tab, {'next_key', '$_info', NasID, AuthPid, undefined, undefined}), %% {'$_info', auth_user_id, auth_pid, acct_user_id, acct_pid}
			{ok, Tab}
	end;
install_db("acct", AcctPid, NasID, Tab) ->
	pg2:join(auths_available, AcctPid),
	case pg2:get_closest_pid(auths_available) of
		{error, {no_process, _Name}} ->
			{error, no_such_group};
		Proc ->
			case global:set_lock({?MODULE, Proc}, Tab) of
				true ->
					case find_table(Proc) of
						{ok, T} ->
							case ets:lookup(T, '$_info') of
								[{_, Key, AutherUserID, AuthPid, undefined, undefined}] ->
									ets:insert(T, {Key, AutherUserID, AuthPid, NasID, AcctPid}),
									pg2:leave(AuthPid),
									global:del_lock({?MODULE, Proc}),
									{ok, T};
								[{_, _, _, AuthPid, _, _}] ->
									pg2:leave(AuthPid),
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
	case ets:lookup(Tab, '$_info') of
		[{_, _, _, _, _, PID}] ->
			ok;
		[{_, _, _, _, undefined, undefined}] ->
			ok;
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
		'$_info' ->
			ets:next(Tab, '$_info');
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
	do_loop(Tab, Interval);
lookup_user(Tab, Key, Interval) ->
	case ets:lookup(Tab, Key) of
		[#radius_user{username = Key, start_time = undefined,
				last_update = undefined} = UR] ->
			ets:insert(Tab, UR#radius_user{start_time = erlang:now(),
					last_update = erlang:now()}),
			{start, Key};
		[#radius_user{username = Key, last_update = LUpdate}] ->
			Elapsed = ts_utils:elapsed(LUpdate, erlang:now()),
			case Elapsed < Interval of
				true ->
					{interim, Key};
				false ->
					lookup_user(Tab, ets:next(Tab, Key), Interval)
			end;
		[] ->
			no_users
	end.

%------------------------------------------------------------
%% Internal Functions
%------------------------------------------------------------
authenticated_users(Tab, ChunkSize) ->
	MatchSpec = [{'_', [], ['$_']}],
	F1 = fun(#registered{username = U}) ->
			mnesia:delete(?Registered, U, write),
			ets:insert(Tab, #acc_session{username = U})
	end,
	F2 = fun() ->
			case mnesia:select(?Registered, MatchSpec, ChunkSize, write) of
				'$end_of_table' ->
					'$end_of_table';
				{Users, _} ->
					lists:foreach(F1, Users),
					ok
			end
	end,
	case mnesia:transaction(F2) of
		{atomic, Result} ->
			Result;
		{aborted, Reason} ->
			throw(Reason)
	end.

find_table(OP) ->
	{ok, CHost} = ts_utils:node_to_hostname(node()),
	StringTabs = [atom_to_list(Tab) || Tab <- ets:all(), is_atom(Tab)],
	AvailableTables = [Table || "rt" ++_ = Table <- StringTabs],
	AuthTabs = [{Table, ets:info(list_to_existing_atom(Table), owner)} || Table <- AvailableTables],
	find_table(OP, AuthTabs).
%% @hidden
find_table(OP, [{Tab, OP} | _]) ->
	Tab;
find_table(OP, [_ | T]) ->
	find_table(OP, T);
find_table(_OP, []) ->
	not_found.

do_loop(Tab, Interval) ->
	receive
	after
		30000 ->
			lookup_user(Tab, ets:first(Tab), Interval)
	end.



