-module(radius_lib).
-author('prahveen@sigscale.org').

-export([install_db/1]).
-export([register_user/1]).

-include("ts_radius.hrl").

-record(registered, {username, password}).
-define(ChunkSize, 10).
-define(Registered, registered).

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
