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
	ElementType = element_type(Element#xmlElement.content),
	DefParams = #radius_request{type = RadType,
			username = UserName, servers = Servers, secret = Secret},
	SessionData = case {RadType, ElementType} of
		{acc, _} ->
			ResultVar = ts_config:getAttr(atom, Attrs, result_var, none),
			CbMod = getAttr(atom, Element#xmlElement.content, accounting, cb_mod),
			Counter = getAttr(integer,
					Element#xmlElement.content, accounting, counter, 3),
			DefParams#radius_request{cb_mod = CbMod,
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
	Delay = ts_config:getAttr(string, Attrs, delay, undefined),
	TMin = ts_config:getAttr(integer, Attrs, min, undefined),
	TMax = ts_config:getAttr(integer, Attrs, max, undefined),
	NewConfig = set_thinktime({Delay, TMin, TMax}, Tab, Id, CurS, Config),
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
-spec element_type(ElementList) -> Name when
	ElementList :: [tuple()],
	Name :: atom() | undefined.
%% @doc retrun element name accounting, pap, chap ...
element_type([#xmlElement{name = Name} | _]) ->
	Name;
element_type([_| T]) ->
	element_type(T);
element_type([]) ->
	undefined.

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

-spec set_thinktime({Delay, Min, Max}, Tab, Id, CurS, Config) ->
		NewConfig when
	Delay :: random | string(),
	Min :: integer(),
	Max :: integer(),
	Tab :: tab(),
	Id :: integer(),
	CurS :: #session{},
	Config :: #config{},
	NewConfig :: #config{}.
%% @doc set thinktime if only define in radius element
set_thinktime({undefined, undefined, undefined}, _Tab, _Id,  _CurS, Config) ->
	Config;
set_thinktime({"random", undefined, undefined}, _Tab, _Id, _CurS, Config) ->
	Config;
set_thinktime({"random", Min, Max}, Tab, Id, CurS, Config) ->
	Think = {range, Min, Max},
	ets:insert(Tab,{{CurS#session.id, Id+1},{thinktime, Think}}),
	Config#config{curid = Id + 1};
set_thinktime({Delay, undefined, undefined}, Tab, Id, CurS, Config) ->
	Think = list_to_integer(Delay),
	ets:insert(Tab,{{CurS#session.id, Id+1},{thinktime, Think}}),
	Config#config{curthink = 1, curid = Id + 1}.

