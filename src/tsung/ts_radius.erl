-module(ts_radius).
-author('prahveen@sigscale.org').

-behavior(ts_plugin).

-export([session_defaults/0, new_session/0, get_message/2, parse/2,
			parse_config/2, parse_bidi/2, dump/2, decode_buffer/2,
			add_dynparams/4, terminate/1, subst/2]).

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_radius.hrl").
-include("xmerl.hrl").

-define(RadID, 10).
-define(EapID, 1).

-spec session_defaults() ->
		{ok, Persistent} when
	Persistent :: boolean().
%% @doc Default parameters for session.
session_defaults() ->
    {ok,true}.

-spec new_session() ->
			NewSession when
	NewSession :: #radius_session{} | list().
%% @doc Initialize session information
new_session() ->
	#radius_session{radius_id  = ?RadID}.

-spec get_message(Data, State) ->
		{Message, Session} when
	Data :: #radius_request{},
	State :: #state_rcv{},
	Message :: binary(),
	Session :: #radius_session{}.
%% @doc Build a message/request
%%	CbMod:get_message/2 returns `{Msg, NewSession :: #radius_session{}}'.
get_message(#radius_request{type = auth, auth_type = pap} = Data,
		#state_rcv{session = #radius_session{tab_id = undefined},
		dynvars = DynVars, ip = {IP, _} = Session} = State) ->
	NewState = get_message1("auth", State),
	get_message3(Data, NewState);
get_message(#radius_request{type = auth, auth_type = 'eap-pwd'} = Data,
		#state_rcv{session = #radius_session{tab_id = undefined}} = State) ->
	NewState = get_message1("auth", State),
	get_message(Data, NewState);
get_message(#radius_request{type = acct, acct_type = start} = Data,
		#state_rcv{session = #radius_session{tab_id = undefined}} = State) ->
	NewState = get_message1("acct", State),
	get_message(Data, NewState);
get_message(#radius_request{type = auth, auth_type = 'eap-pwd'} = Data,
		#state_rcv{session = #radius_session{data = undefined}} = State) ->
	EapRecord = #pwd{eap_id = ?EapID},
	NewState = get_message2(Data, EapRecord, State),
	get_message(Data, NewState);
get_message(#radius_request{type = acct} = Data, #state_rcv{session =
		#radius_session{data = undefined}} = State) ->
	AccRecord = #accounting{},
	NewState = get_message2(Data, EapRecord, State),
	get_message(Data, NewState);
get_message(#radius_request{type = acct, username = "$end_of_table"} = Data,
		#state_rcv{session = #radius_session{data = #accounting{type = start}
		= Acc} = Session} = State) ->
		%when Session#radius_session.username == undefined ->
	NewAcc = Acc#accounting{type = interim},
	NewSession = Session#radius_session{data = NewAcc},
	NewState = State#state_rcv{session = NewSession},
	get_message(Data, NewState);
get_message(#radius_request{type = acct, username = "$end_of_table"} = Data,
		#state_rcv{session = #radius_session{data = #accounting{type = interim} = Acc} = Session} = State)
		when Session#radius_session.username =/= "$end_of_table" ->
	User = radius_lib:get_user(first, ID),
	NewSession = Session#radius_session{username = User},
	NewState = State#state_rcv{session = NewSession},
	get_message3(Data, NewState);
get_message(#radius_request{type = acct} = Data,
		#state_rcv{session = #radius_session{username = PrevUser, data =
		#accounting{type = interim} = Session}} = State) ->
	NextUser = case radius_lib:get_user(next, ID, PrevUser) of
		'$end_of_table' ->
			radius_lib:get_user(first, ID);
		NU ->
			NU
	end,
	NewSession = Session#radius_session{username = NextUser},
	NewState = State#state_rcv{session = NewSession},
	get_message3(Data, NewState);
get_message(#radius_request{type = acct} = Data,
		#state_rcv{session = #radius_session{data = #accounting{type = interim} = Acc} = Session}
		= State) when CCounter > MCounter->
	User = radius_lib:get_user(first, ID),
	NewAcc = Acc#accounting{type = stop},
	NewSession = Session#radius_session{username = User, data = NewAcc},
	NewState = State#state_rcv{session = NewSession},
	get_message3(Data, NewState);
get_message(#radius_request{type = acct} = Data, #state_rcv{session =
		#radius_session{username = PrevUser, data = #accounting{type = stop
		}} = Session} = State) ->
	case radius_lib:get_user(next, ID, PrevUser) of
		'$end_of_table' ->
			NextUser = radius_lib:get_user(next_chunk, ID, 100),
			NewSession = Session#radius_session{username = NextUser,
					data = undefined},
			NewState = State#state_rcv{session = NewSession},
			NewData = Data#radius_request{username = NextUser},
			get_message(NewData, NewState);
		NU ->
			NewSession = Session#radius_session{username = NU},
			NewState = State#state_rcv{session = NewSession},
			get_message3(Data, NewState)
	end;
get_message(#radius_request{type = acct, username = '$end_of_table'} = Data,
		#state_rcv{session = #radius_session{data = #accounting{type = stop
		} = Acc} = Session} = State) ->
	User = radius_lib:get_user(next_chunk, ID, 100),
	NewSession = Session#radius_session{username = User,
			data = Acc#accounting{type = start}},
	NewState = State#state_rcv{session = NewSession},
	get_message(Data, NewState);
get_message(Data, State) ->
	get_message3(Data, State).
%% @hidden
get_message1(Type, #state_rcv{session = Session ,dynvars = DynVars,
		ip = {IP, _}} = State) ->
	{ok, ID} = ts_dynvars:lookup(tsung_userid, DynVars),
	{ok, CHost} = ts_utils:node_to_hostname(node()),
	NasID = CHost ++ Type ++ integer_to_list(ID),
	Tab = list_to_existing_atom(NasID),
	{ok, NTab} = radius_lib:install_db(Type, self(), NasID, Tab),
	State#state_rcv{session =
		Session#radius_session{tab_id = NTab, nas_id = NasID}}.
%% @hidden
get_message2(Data, RecordData, #state_rcv{session = Session} = State) ->
	NewSession = Session#radius_session{data = RecordData},
	NewState = State#state_rcv{session = NewSession},
	get_message(Data, NewState).
%% @hidden
get_message3(Data, State) ->
	CbMod = Data#radius_request.cb_mod,
	CbMod:get_message(Data, State).

-spec parse(Data, State) ->
			{NewState, Options, Close} when
	Data :: binary(),
	State :: #state_rcv{},
	NewState :: #state_rcv{},
	Options :: list(),
	Close :: boolean().
%% @doc Purpose: Parse the given data and return a new state
%% 	no parsing . use only ack,
%% `Options' is list of options for socket.
parse(Data, #state_rcv{request = #ts_request{param
		= #radius_request{cb_mod = CbMod}}} = State) ->
	{NS, Opts, Close} = CbMod:parse(Data, State),
	parse1(NS, Opts, Close).
%% @hidden
parse1(#state_rcv{session = #radius_session{result_value = "success"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'pap'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessAccept-PAP'}),
	parse2(State, Opts, Close);
parse1(#state_rcv{session = #radius_session{result_value = "failure"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'pap'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessReject-PAP'}),
	parse2(State, Opts, Close);
parse1(#state_rcv{session = #radius_session{result_value = "challenge"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'eap-pwd'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessChallenge-EAP-PWD'}),
	parse2(State, Opts, Close);
parse1(#state_rcv{session = #radius_session{result_value = "success"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'eap-pwd'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessAccept-EAP-PWD'}),
	parse2(State, Opts, Close);
parse1(#state_rcv{session = #radius_session{result_value = "failure"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'eap-pwd'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessReject-EAP-PWD'}),
	parse2(State, Opts, Close);
parse1(#state_rcv{session = #radius_session{result_value = "start"},
		request = #ts_request{param = #radius_request{type = acc}}} = State,
		Opts, Close) ->
	ts_mon:add({count, 'AccountingStart'}),
	parse2(State, Opts, Close);
parse1(#state_rcv{session = #radius_session{result_value = "interim"},
		request = #ts_request{param = #radius_request{type = acc}}} = State,
		Opts, Close) ->
	ts_mon:add({count, 'AccountingInterimUpdate'}),
	parse2(State, Opts, Close);
parse1(#state_rcv{session = #radius_session{result_value = "stop"},
		request = #ts_request{param = #radius_request{type = acc}}} = State,
		Opts, Close) ->
	ts_mon:add({count, 'AccountingStop'}),
	parse2(State, Opts, Close).
%% @hidden
parse2(#state_rcv{session = #radius_session{result_value = "success",
		username = UserName, tab_id = Tab} = Session, request =
		#ts_request{param = #radius_request{type = auth,
		auth_type = 'eap-pwd'}}} = State, Opts, Close) ->
	ok = radius_lib:register_user(Tab, UserName),
	NewSession = Session#radius_session{username = undefined},
	NewState = State#state_rcv{session = NewSession},
	parse3(NewState, Opts, Close);
parse2(#state_rcv{session = #radius_session{result_value = "success",
		username = UserName, tab_id = Tab}, request =
		#ts_request{param = #radius_request{type = auth}}}
		= State, Opts, Close) ->
	ok = radius_lib:register_user(Tab, UserName),
	parse3(State, Opts, Close);
parse2(State, Opts, Close) ->
	parse3(State, Opts, Close).
%% @hidden
parse3(#state_rcv{request = #ts_request{param = #radius_request{type = auth}},
		session = #radius_session{tab_id = Tab, nas_id = NasID}} = State, Opts, Close) ->
	case radius_lib:transfer_ownsership(Tab, NasID) of
		transfered ->
			parse4(State, Opts, Close); %% @TODO close socket
		own_by_me ->
			parse4(State, Opts, Close) 
	end.
%% @hidden
parse4(#state_rcv{ack_done = true, dynvars = DynVars, request =
		#ts_request{param = #radius_request{result_var = VarName}},
		session = #radius_session{result_value = VarValue}}
		= State, Opts, Close) ->
	NewDynVars = set_dynvar(VarName, VarValue, DynVars),
	NewState = State#state_rcv{dynvars = NewDynVars},
	{NewState, Opts, Close};
parse4(#state_rcv{ack_done = false} = State, Options, Close) ->
	{State, Options, Close}.

-spec parse_config(Element, Conf) ->
			Result when
	Element :: #xmlElement{},
	Conf :: #config{},
	Result :: list().
%% @doc  Parse tags in the XML config file
%% 	related to the protocol
parse_config(Element, Conf) ->
    ts_config_radius:parse_config(Element, Conf).

parse_bidi(Data, State) ->
    ts_plugin:parse_bidi(Data,State).

dump(A,B) ->
    ts_plugin:dump(A,B).

-spec decode_buffer(Buffer , Session) ->
		NewBuffer when
	Buffer :: binary(),
	Session :: tuple(),
	NewBuffer :: binary().
%%	@doc We need to decode buffer (remove chunks, decompress ...) for
%%		matching or dyn_variables
decode_buffer(Buffer, {}) ->
    Buffer.

-spec add_dynparams(Subst, DynData, Param, HostData) ->
		Param when
	Subst :: boolean(),
	DynData :: list() | tuple(),
	Param :: #radius_request{},
	HostData :: term().
%% @doc Add dynamic parameters to build the message
add_dynparams(_,[], Param, _Host) ->
    Param;
add_dynparams(Subst, {DynVars, _Session}, OldReq, Host) ->
	add_dynparams1(Subst, OldReq, Host, DynVars).
%% @hidden
add_dynparams1(Subst, #radius_request{type = auth, port = Port}
		= Param, {Address, _, Proto}, DynVars) ->
	NewServer = {Address, Port, Proto},
	NParam = add_dynparams2(Subst, Param, DynVars),
	{NParam, NewServer};
add_dynparams1(Subst, #radius_request{type = acc, port = Port}
		= Param, {Address, _, Proto}, DynVars) ->
	NewServer = {Address, Port, Proto},
	NParam = add_dynparams2(Subst, Param, DynVars),
	{NParam, NewServer}.
%% @hidden
add_dynparams2(true, Param, DynVars) ->
	subst(Param, DynVars);
add_dynparams2(_, Param, _DynVars) ->
	Param.

-spec terminate(State) ->
		ok when
	State :: #state_rcv{}.
terminate(_State) ->
	ok.

-spec subst(Param, DynVars) ->
		Result when
	Param :: #radius_request{},
	DynVars :: [tuple()],
	Result :: #radius_request{}.
%% @doc Replace on the fly dynamic element of the request.
subst(#radius_request{username = UserName, password = Password}
		= Param, DynVars) ->
	Param#radius_request{username = ts_search:subst(UserName, DynVars),
		password = ts_search:subst(Password, DynVars)}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Internal Functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec set_dynvar(ResultVar, VarValue, DynVars) ->
			NewDynVars when
	ResultVar :: none | {var, VarName},
	VarValue :: string(),
	DynVars :: list() | [tuple()],
	NewDynVars :: list() | [tuple()],
	VarName :: atom().
%% @doc Add new dynamic parameter to existing
%% parameter list.
set_dynvar(none, _VarValue, DynVar) ->
	DynVar;
set_dynvar({var, VarName}, VarValue, DynVar)
		when is_list(DynVar) ->
	NewDynVars = lists:keystore(VarName, 1,
			DynVar, {VarName, VarValue}),
	NewDynVars;
set_dynvar(_, _, DynVars) ->
	DynVars.

