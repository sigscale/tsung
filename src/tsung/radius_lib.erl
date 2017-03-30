-module(radius_lib).
-author('prahveen@sigscale.org').

-export([install_db/1]).
-export([user/1]).
-export([register_user/1, get_user/2, get_user/3]).

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

-spec install_db(Node) ->
		ok | {error, Reason} when
	Node :: [node()],
	Reason :: term().
install_db(Node) ->
	rpc:multicall(Node, mnesia, start, []),
	case ets:info(?Registered, name) of
		undefined ->
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
		_ ->
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
