-module(radius_lib).
-author('prahveen@sigscale.org').

-export([install_db/1]).
-export([user/1]).
-export([register_user/1, get_user/1, get_user/2]).

-include("ts_radius.hrl").

-record(registered, {username, password}).
-define(ChunkSize, 10).
-define(Registered, registered).

-record(acc_session,
			{username,
			type = start :: start | interim | stop,
			counter = 0}).
-define(SessionTab, accsession).
-define(SessionTabOptions, [private, named_table, {keypos, 2}]).

%---------------------------------------------------------------
%% CallBack Function for tsung config file
%---------------------------------------------------------------

%% @doc CB for xml config file
user({_Pid, DynVars}) ->
	User = lists:keyfind(username, 1, DynVars),
	user1(User).
%% @hidden
user1(false) ->
	get_user(new, 100);
user1({username, PrevUser}) ->
	get_user(next, PrevUser).

%-----------------------------------------------------------------
%% CallBack Function for RADIUS pulgin
%-----------------------------------------------------------------

-spec install_db(Node) ->
		ok | {error, Reason} when
	Node :: [node()],
	Reason :: term().
install_db(Node) ->
	rpc:multicall(Node, mnesia, start, []),
	case mnesia:wait_for_tables([?Registered], 300) of
		{timeout, _} ->
			ping(),
			Nodes = Node ++ nodes(),
			rpc:multicall(Nodes, mnesia, start, []),
			case mnesia:create_table(?Registered,
					[{attributes, record_info(fields, registered)}]) of
				{atomic, ok} ->
					ok;
				{aborted, Reason} ->
					{error, Reason}
			end;
		ok ->
			ok
	end.

-spec register_user(User) ->
		ok  when
	User :: binary() | list().
%% @doc Register authenticated users
register_user(User) when is_binary(User)->
	register_user(binary_to_list(User));
register_user(User) when is_list(User) ->
	mnesia:dirty_write(?Registered, #registered{username = User}).


-spec get_user(first) ->
		User when
	User :: binary() | string().
%% @equiv get_user(fist, undefined)
get_user(first) ->
	get_user(first, undefined).

-spec get_user(Type, Spec) ->
		User when
	Type :: new | start | first | next,
	Spec :: integer() | undefined | '$end_of_table',
	User :: binary() | string().
%% @doc Get authenticated users.
get_user(new, ChunkSize) when is_integer(ChunkSize) ->
	case ets:info(?SessionTab, name) of
		undefined ->
			ets:new(?SessionTab, ?SessionTabOptions),
			get_user(start, ChunkSize);
		_ ->
			get_user(first, undefined)
	end;
get_user(start, ChunkSize) when is_integer(ChunkSize) ->
	case authenticated_users(?SessionTab, ChunkSize) of
		'$end_of_table' ->
			'$end_of_table';
		_ ->
			ets:first(?SessionTab)
	end;
get_user(first, undefined) ->
	ets:first(?SessionTab);
get_user(next, '$end_of_table')  ->
	ets:first(?SessionTab);
get_user(next, PrevUser)  ->
	ets:next(?SessionTab, PrevUser).

%------------------------------------------------------------
%% Internal Functions
%------------------------------------------------------------
ping() ->
	KnownNodes = nodes(known),
	F = fun(C) when C =/= node() ->
			net_adm:ping(C);
		(_) ->
			ok
	end,
	lists:foreach(F, KnownNodes).

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
