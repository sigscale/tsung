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
-include_lib("radius/include/radius.hrl").

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
		#state_rcv{session = #radius_session{tab_id = undefined}} = State) ->
	get_message1("auth", Data, State);
get_message(#radius_request{type = auth, auth_type = 'eap-pwd'} = Data,
		#state_rcv{session = #radius_session{tab_id = undefined}} = State) ->
	get_message1("auth", Data, State);
get_message(#radius_request{type = acct} = Data,
		#state_rcv{session = #radius_session{tab_id = undefined}} = State) ->
	get_message1("acct", Data, State);
get_message(Data, State) ->
	get_message2(Data, State).

%% @hidden
get_message1(Type, Data, #state_rcv{session = Session, dynvars = DynVars} = State) ->
	{ok, ID} = ts_dynvars:lookup(tsung_userid, DynVars),
	{ok, CHost} = ts_utils:node_to_hostname(node()),
	NasID = CHost ++ "_" ++ Type ++ integer_to_list(ID),
	Tab = list_to_atom(NasID),
	case radius_lib:install_db(Type, self(), NasID, Tab) of
		{error, _Reason} ->
error_logger:error_report([{error, _Reason}, {module, ?MODULE}, {line, ?LINE}]),
			Elapsed = ts_utils:elapsed(State#state_rcv.starttime, ?NOW),
			self() ! timeout,
			%% ts_mon:endclient({State#state_rcv.id, ?TIMESTAMP, Elapsed}), is it mandatory to do this ??
			{<<"bogus">>, State#state_rcv.session};
		{ok, AuthTab} ->
			NewState = State#state_rcv{session = Session#radius_session{tab_id = AuthTab,
					nas_id = atom_to_list(AuthTab)}},
			get_message2(Data, NewState)
	end.

%% @hidden
get_message2(#radius_request{type = auth, auth_type = 'eap-pwd'} = Data,
		#state_rcv{session = #radius_session{data = undefined}} = State) ->
	EapRecord = #pwd{eap_id = ?EapID},
	get_message3(Data, EapRecord, State);
get_message2(#radius_request{type = acct} = Data, #state_rcv{session =
		#radius_session{data = undefined}} = State) ->
	AccRecord = #accounting{start_time = erlang:system_time(milli_seconds)},
	get_message3(Data, AccRecord, State);
get_message2(Data, State) ->
	get_message4(Data, State).

%% @hidden
get_message3(Data, RecordData, #state_rcv{session = Session} = State) ->
	NewSession = Session#radius_session{data = RecordData},
	NewState = State#state_rcv{session = NewSession},
	get_message4(Data, NewState).

%% @hidden
get_message4(#radius_request{duration = Duration} = Data,
		#state_rcv{session = #radius_session{duration = undefined}
		= Session} = State) ->
	NewSession = Session#radius_session{duration = Duration},
	NewState = State#state_rcv{session = NewSession},
	get_message5(Data, NewState);
get_message4(Data, State) ->
	get_message5(Data, State).
%% @hidden
get_message5(#radius_request{type = auth, max_reg = MaxReg} = Data,
		#state_rcv{session = #radius_session{duration = Duration, tot_reg = TotReg,
		tab_id = Tab} = Session}  = State) when TotReg >= MaxReg ->
	{User, Password} = radius_lib:reregister_user(Tab, Duration),
	NewData = Data#radius_request{username = User, password = Password},
	NewSession = Session#radius_session{username = User, password = Password},
	NewState = State#state_rcv{session = NewSession},
	get_message6(NewData, NewState);
get_message5(#radius_request{type = auth, password = Password, max_reg = MaxReg} = Data,
		#state_rcv{session = #radius_session{tot_reg = TotReg} = Session}
		= State) when TotReg < MaxReg ->
	NewSession = Session#radius_session{password = Password},
	NewState = State#state_rcv{session = NewSession},
	get_message6(Data, NewState);
get_message5(#radius_request{type = acct, username = "_start"} = Data,
		#state_rcv{session = #radius_session{tab_id = Tab,
		data = #accounting{type = start}}} = State) ->
	User = radius_lib:get_user(Tab, first),
	NewData = Data#radius_request{username = User},
	get_message5(NewData, State);

get_message5(#radius_request{type = acct} = Data,
		#state_rcv{session = #radius_session{tab_id = Tab,
		data = Acct} = Session} = State) ->
	case radius_lib:lookup_user(Tab) of
		{start, User} ->
			NewSession = Session#radius_session{data =
						Acct#accounting{type = start}, username = User},
			NewState = State#state_rcv{session = NewSession},
			get_message6(Data, NewState);
		{interim, User} ->
			NewSession = Session#radius_session{data =
						Acct#accounting{type = interim}, username = User},
			NewState = State#state_rcv{session = NewSession},
			get_message6(Data, NewState);
		{stop, User} ->
			NewSession = Session#radius_session{data =
						Acct#accounting{type = stop}, username = User},
			NewState = State#state_rcv{session = NewSession},
			get_message6(Data, NewState)
	end;
get_message5(Data, State) ->
	get_message6(Data, State).
%% @hidden
get_message6(Data, State) ->
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
parse(Data, #state_rcv{request = #ts_request{param =
		#radius_request{cb_mod = CbMod}}} = State) ->
	RadiusPacket = radius:codec(Data),
	{NS, Opts, Close} = CbMod:parse(RadiusPacket, State),
	parse1(RadiusPacket, NS, Opts, Close).
%% @hidden
parse1(#radius{code = ?AccessAccept, attributes = Attributes},
		#state_rcv{request = #ts_request{param = #radius_request{duration = Duration}},
		session = Session} = State, Opts, Close) ->
	AttributeList = radius_attributes:codec(Attributes),
	{SessionTimeout, InterimInterval} =
				case {radius_attributes:find(?SessionTimeout, AttributeList),
						radius_attributes:find(?AcctInterimInterval, AttributeList)} of
			{{ok, ST}, {ok, II}} ->
				{ST, II};
			{{ok, ST}, {error, _}} ->
				{ST, undefined};
			{{error, _}, {ok, II}} ->
				{Duration, II * 1000};
			{_, _} ->
				{Duration, undefined}
	end,
	NewSession = Session#radius_session{interval = InterimInterval,
			duration = SessionTimeout},
	NextState = State#state_rcv{session = NewSession},
	parse2(NextState, Opts, Close);
parse1(_, NS, Opts, Close) ->
	parse2(NS, Opts, Close).
%% @hidden
parse2(#state_rcv{session = #radius_session{result_value = "success"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'pap'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessAccept-PAP'}),
	parse3(State, Opts, Close);
parse2(#state_rcv{session = #radius_session{result_value = "failure"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'pap'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessReject-PAP'}),
	parse3(State, Opts, Close);
parse2(#state_rcv{session = #radius_session{result_value = "challenge"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'eap-pwd'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessChallenge-EAP-PWD'}),
	parse3(State, Opts, Close);
parse2(#state_rcv{session = #radius_session{result_value = "success"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'eap-pwd'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessAccept-EAP-PWD'}),
	parse3(State, Opts, Close);
parse2(#state_rcv{session = #radius_session{result_value = "failure"},
		request = #ts_request{param = #radius_request{type = auth,
		auth_type = 'eap-pwd'}}} = State, Opts, Close) ->
	ts_mon:add({count, 'AccessReject-EAP-PWD'}),
	parse3(State, Opts, Close);
parse2(#state_rcv{session = #radius_session{result_value = "start"},
		request = #ts_request{param = #radius_request{type = acct}}} = State,
		Opts, Close) ->
	ts_mon:add({count, 'AccountingStart'}),
	parse3(State, Opts, Close);
parse2(#state_rcv{session = #radius_session{result_value = "interim"},
		request = #ts_request{param = #radius_request{type = acct}}} = State,
		Opts, Close) ->
	ts_mon:add({count, 'AccountingInterimUpdate'}),
	parse3(State, Opts, Close);
parse2(#state_rcv{session = #radius_session{result_value = "stop"},
		request = #ts_request{param = #radius_request{type = acct}}} = State,
		Opts, Close) ->
	ts_mon:add({count, 'AccountingStop'}),
	parse3(State, Opts, Close).
%% @hidden
parse3(#state_rcv{request = #ts_request{param = #radius_request{type = auth,
		max_reg = MaxReg}}, session = #radius_session{result_value = "success",
		tab_id = Tab} = Session} = State, Opts, Close) ->
		TotReg = ets:info(Tab, size),
	case MaxReg  > TotReg - 1 of
		true ->
			parse4(State, Opts, Close); %%TODO sleep for awhile
		false ->
			error_logger:info_report(["Maximum RADIUS registrations reached (max_reg)",
					{max_reg, MaxReg}, {registered, TotReg}]),
			NewSession = Session#radius_session{tot_reg = TotReg},
			NewState = State#state_rcv{session = NewSession},
			parse4(NewState, Opts, Close)
	end;
parse3(State, Opts, Close) ->
	parse4(State, Opts, Close).
%% @hidden
parse4(#state_rcv{session = #radius_session{result_value = "failure",
		username = Username, tab_id = Tab, tot_reg = TotReg} = Session, 
		request = #ts_request{param = #radius_request{type = auth,
		max_reg = MaxReg}}} = State, Opts, Close) when TotReg >= MaxReg ->
	ok = radius_lib:remove_user(Tab, Username),
	NewSession = Session#radius_session{tot_reg = TotReg -1},
	NewState = State#state_rcv{session = NewSession},
	parse5(NewState, Opts, Close);
parse4(#state_rcv{session = #radius_session{result_value = "success",
		username = Username, password = Password, tab_id = Tab, interval = Interval,
		duration = Duration} = Session, request = #ts_request{param =
		#radius_request{type = auth, auth_type = 'eap-pwd'}}} = State, Opts, Close) ->
	RegRecord = #radius_user{username = Username, password = Password,
			interval = Interval, session_timeout = Duration,
			reg_time = erlang:system_time(milli_seconds)},
	ok = radius_lib:register_user(Tab, RegRecord),
	NewSession = Session#radius_session{username = undefined},
	NewState = State#state_rcv{session = NewSession},
	parse5(NewState, Opts, Close);
parse4(#state_rcv{session = #radius_session{result_value = "success",
		username = Username, password = Password, tab_id = Tab,
		interval = Interval, duration = Duration}, request = #ts_request{param =
		#radius_request{type = auth}}} = State, Opts, Close) ->
	RegRecord = #radius_user{username = Username, password = Password,
			interval = Interval, session_timeout = Duration,
			reg_time = erlang:system_time(milli_seconds)},
	ok = radius_lib:register_user(Tab, RegRecord),
	parse5(State, Opts, Close);
parse4(#state_rcv{request = #ts_request{param = #radius_request{type = acct}},
		session = #radius_session{tab_id = Tab, username = PeerID}, dynvars = DynVars}
		= State, Opts, Close) ->
	NewDynVars = ts_dynvars:merge([{tab_id, Tab}, {username, PeerID}], DynVars),
	NewState = State#state_rcv{dynvars = NewDynVars},
	parse5(NewState, Opts, Close);
parse4(State, Opts, Close) ->
	parse5(State, Opts, Close).
%% @hidden
parse5(#state_rcv{ack_done = true, dynvars = DynVars, request =
		#ts_request{param = #radius_request{result_var = VarName}},
		session = #radius_session{result_value = VarValue}}
		= State, Opts, Close) ->
	NewDynVars = set_dynvar(VarName, VarValue, DynVars),
	NewState = State#state_rcv{dynvars = NewDynVars},
	{NewState, Opts, Close};
parse5(#state_rcv{ack_done = false} = State, Options, Close) ->
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
add_dynparams1(Subst, #radius_request{type = acct, port = Port}
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
%% @doc Transfer ownsership of the ets table
terminate(#state_rcv{request = #ts_request{param =
		#radius_request{type = auth}}, session =
		#radius_session{tab_id = Tab}}) ->
	radius_lib:transfer_ownsership(Tab);
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

