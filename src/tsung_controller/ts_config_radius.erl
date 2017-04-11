-module(ts_config_radius).
-author('prahveen@sigscale.org').

-export([parse_config/2]).

-export_type([tab/0, tid/0]).

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_radius.hrl").
-include("xmerl.hrl").

%%----------------------------------------------------------------------
%% Func: parse_config/2
%% Args: Element, Config
%% Returns: List
%% Purpose: parse a request defined in the XML config file
%%----------------------------------------------------------------------
parse_config(Element = #xmlElement{name=dyn_variable}, Conf = #config{}) ->
	ts_config:parse(Element,Conf);
parse_config(Element = #xmlElement{name = radius, attributes = Attrs},
		Config=#config{curid = Id, session_tab = Tab, servers = Servers,
		sessions = [CurS | _], dynvar = DynVar, subst = SubstFlag,
		match = MatchRegExp}) ->
	UserName = ts_config:getAttr(string, Attrs, username, undefined),
	Secret = ts_config:getAttr(string, Attrs, secret, undefined),
	RadType = ts_config:getAttr(atom, Attrs, type, undefined),
	AccType = ts_config:getAttr(atom, Attrs, acc_type, undefined),
	AuthType = ts_config:getAttr(atom, Attrs, auth_type, undefined),
	DefParams = #radius_request{type = RadType,
			username = UserName, servers = Servers, secret = Secret},
	SessionData = case {RadType, AuthType} of 
		{acc, _} ->
			ResultVar = ts_config:getAttr(atom, Attrs, result_var, none),
			CbMod = getAttr(atom, Element#xmlElement.content, accounting, cb_mod),
			Counter = getAttr(integer,
					Element#xmlElement.content, accounting, counter, 3),
			DefParams#radius_request{acc_type = AccType, cb_mod = CbMod,
					counter = Counter, result_var = {var, ResultVar}};
		{auth, pap}  ->
			ResultVar = ts_config:getAttr(atom, Attrs, result_var, none),
			CbMod = getAttr(atom, Element#xmlElement.content, pap, cb_mod),
			Password = getAttr(string, Element#xmlElement.content, pap, password),
			DefParams#radius_request{auth_type = pap, cb_mod = CbMod,
					password = Password, result_var = {var, ResultVar}};
		{auth, eap_pwd} ->
			ResultVar = ts_config:getAttr(atom, Attrs, result_var, none),
			CbMod = getAttr(atom, Element#xmlElement.content, eap_pwd, cb_mod),
			Password = getAttr(string, Element#xmlElement.content, eap_pwd, password),
			DefParams#radius_request{auth_type = 'eap-pwd', cb_mod = CbMod,
				password = Password, result_var = {var, ResultVar}};
		{auth, chap} ->
			todo;
		{auth, eap_ttls} ->
			todo
	end,
	TTVal = ts_config:getAttr(integer, Attrs, value, undefined),
	TMin = ts_config:getAttr(integer, Attrs, min, undefined),
	TMax = ts_config:getAttr(integer, Attrs, max, undefined),
	Random = ts_config:getAttr(atom, Attrs, random, false),
	NewConfig = set_thinktime({TTVal, TMin, TMax, Random}, Tab, Id, CurS, Config),
	Msg=#ts_request{ack = parse,
						subst   = SubstFlag,
						match   = MatchRegExp,
						param   = SessionData},
	ets:insert(Tab,{{CurS#session.id, Id},
			Msg#ts_request{endpage=true, dynvar_specs = DynVar}}),
	lists:foldl(fun(A,B)-> ts_config:parse(A,B) end,
	NewConfig#config{dynvar = []}, Element#xmlElement.content);
parse_config(Element = #xmlElement{}, Conf = #config{}) ->
    ts_config:parse(Element,Conf);
parse_config(_, Conf = #config{}) ->
    Conf.

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

-type type() :: string | list | atom | float_or_integer | integer.

-spec getAttr(Type, ElementList, Element, Name) ->
				Attribute | undefined when
			Type :: type(),
			ElementList :: [#xmlElement{}],
			Element :: atom(),
			Name :: atom(),
			Attribute :: type().
%% @equiv getAttr(Type, ElementList, Element, Name, undefined)
getAttr(Type, ElementList, Element, Name) ->
	getAttr(Type, ElementList, Element, Name, undefined).

-spec getAttr(Type, ElementList, Element, Name, Default) ->
				Attribute | undefined when
			Type :: type(),
			ElementList :: [#xmlElement{}],
			Element :: atom(),
			Name :: atom(),
			Default :: undefined | atom(),
			Attribute :: type().
getAttr(Type, [#xmlElement{} = H | T], Element, Attribute, Default) ->
	case H#xmlElement.name of
		Element ->
			ts_config:getAttr(Type, H#xmlElement.attributes, Attribute, Default);
		_ ->
			getAttr(Type, T, Element, Attribute)
	end;
getAttr(Type, [_ | T], Element, Attribute, Default) ->
	getAttr(Type, T, Element, Attribute, Default);
getAttr(_, [], _, _, Default) ->
	Default.
	
-type tab() :: atom() | tid().
-opaque tid() :: integer().

-spec set_thinktime({Value, Min, Max, Random}, Tab, Id, CurS, Config) ->
		NewConfig when
	Value :: integer(),
	Min :: integer(),
	Max :: integer(),
	Random :: boolean(),
	Tab :: tab(),
	Id :: integer(),
	CurS :: #session{},
	Config :: #config{},
	NewConfig :: #config{}.
%% @doc set thinktime if only define in radius element
set_thinktime({undefined, undefined, undefined, _}, _Tab, _Id,  _CurS, Config) ->
	Config;
set_thinktime({undefined, Min, Max, _}, Tab, Id, CurS, Config) ->
	Think = {range, Min, Max},
	ets:insert(Tab,{{CurS#session.id, Id+1},{thinktime, Think}}),
	Config#config{curid = Id +1};
set_thinktime({Val, undefined, undefined, true}, Tab, Id, CurS, Config) ->
	Think = {random, Val},
	ets:insert(Tab,{{CurS#session.id, Id+1},{thinktime, Think}}),
	Config#config{curthink = 1, curid = Id +1};
set_thinktime({Val, undefined, undefined, false}, Tab, Id, CurS, Config) ->
	ets:insert(Tab,{{CurS#session.id, Id+1},{thinktime, Val}}),
	Config#config{curthink = 1, curid = Id +1}.

