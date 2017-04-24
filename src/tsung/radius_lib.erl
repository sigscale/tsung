-module(radius_lib).
-author('prahveen@sigscale.org').

-export([install_db/3]).
-export([user/1]).
-export([register_user/2, transfer_ownsership/2, get_user/2, get_user/3]).

-include("ts_radius.hrl").

%---------------------------------------------------------------
%% CallBack Function for tsung config file
%---------------------------------------------------------------

%% @doc CB for xml config file
user({_Pid, DynVars}) ->
	User = lists:keyfind(username, 1, DynVars),
	{_, ID} = lists:keyfind(tsung_userid, 1, DynVars),
	user1(ID, User).
%% @hidden
user1(ID, false) ->
	Name = "acc_session" ++ integer_to_list(ID),
	Tab = list_to_atom(Name),
	get_user(new, Tab, 100);
user1(ID, {username, PrevUser}) ->
	Name = "acc_session" ++ integer_to_list(ID),
	Tab = list_to_existing_atom(Name),
	get_user(next, Tab, PrevUser).

%-----------------------------------------------------------------
%% CallBack Function for RADIUS pulgin
%-----------------------------------------------------------------

-spec install_db(Type, Pid, Tab) ->
		{ok, Result} | {error, Reason} when
	Type :: string(),
	Pid :: pid(),
	Tab :: atom(),
	Result :: atom(),
	Reason :: term().
install_db("auth", Pid, Tab) ->
	case pg2:join(auth, Pid) of
		{error, {no_such_group, _}} ->
			pg2:create(auths_available),
			install_db("auth", Pid, Tab);
		ok ->
			true = ets:new(Tab, ?SessionTabOptions]),
			ets:insert(Tab, #info{auth_user_id = Tab, auth_pid = Pid}),
			{ok, Tab}
	end;
install_db("acct", Pid, Tab) ->
	case pg2:get_closest_pid(auths_available) of
		{error, {no_process, _Name}} ->
			{error, no_such_group};
		Proc ->
			case global:set_lock(Proc, Tab) of
				true ->
					case find_table(Proc) of
						{ok, T} ->
							case ets:lookup(T, T) of
								[#info{} = Info] ->
									ets:insert(T, Info{acct_user_id = Tab, acct_pid = Pid}),
									pg2:leave(Pid);
									{ok, T};
								[] ->
									{error, not_found}
							end;
						not_found ->
							{error, not_found}
				false ->
					install_db("acct", Pid, Tab)
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
	ets:insert(Tab, #registered{username = User}),
	ok.

-spec transfer_ownsership(Tab, NasID) ->
		own_by_me | tranfered when
	Tab :: atom(),
	NasID :: string() | atom().
transfer_ownsership(Tab, NasID) ->
	case ets:lookup(Tab, NasID) of
		[#info{auth_user_id = NasID,
				acct_user_id = undefined, acct_pid = undefined}] ->
			own_by_me;
		[#info{auth_user_id = NasID,
				acct_pid = AcctPid}] ->
			ets:setopts(Tab, {heir, AcctPid, []}),
			transfered
	end.

-spec get_user(first, Tab) ->
		User when
	Tab :: integer(),
	User :: binary() | string().
%% @equiv get_user(fist, Tab,  undefined)
get_user(first, Tab) ->
	get_user(first, Tab, undefined).

-spec get_user(Type, Tab, Spec) ->
		User when
	Type :: new | start | first | next | next_chunk,
	Tab :: atom(),
	Spec :: integer() | undefined | '$end_of_table',
	User :: binary() | string().
%% @doc Get authenticated users.
get_user(new, Tab, ChunkSize) when is_integer(ChunkSize) ->
	case ets:info(Tab, name) of
		undefined ->
			ets:new(Tab, ?SessionTabOptions),
			get_user(start, Tab, ChunkSize);
		_ ->
			get_user(first, Tab, undefined)
	end;
get_user(start, Tab, ChunkSize) when is_integer(ChunkSize) ->
	case authenticated_users(Tab, ChunkSize) of
		'$end_of_table' ->
			'$end_of_table';
		_ ->
			ets:first(Tab)
	end;
get_user(first, Tab, undefined) ->
	ets:first(Tab);
get_user(next, Tab, '$end_of_table')  ->
	ets:first(Tab);
get_user(next, Tab, PrevUser)  ->
	ets:next(Tab, PrevUser);
get_user(next_chunk, Tab, ChunkSize) ->
	true = ets:delete_all_objects(Tab),
	case authenticated_users(Tab, ChunkSize) of
		'$end_of_table' ->
			get_user(next_chunk, Tab, ChunkSize);
		_ ->
			ets:first(Tab)
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
	InetTabList = [atom_to_list(Tab) || Tab <- ets:all(), is_atom(Tab)],
	AuthTabs = [{Tab, ets:info(list_to_atom(Tab), owner)} || CHost ++ _ = Tab <- InetTables]
	find_tab(OP, InetTabList).
%% @hidden
find_table(OP, [{Tab, OP} | _]) ->
	Tab;
find_table(OP, [_ | T]) ->
	find_table(OP, T);
find_table(_OP, []) ->
	not_found.
