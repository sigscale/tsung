-module(ts_accounting).
-author('prahveen@sigscale.org').

-export([get_message/2, parse/2]).

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_radius.hrl").
-include("radius.hrl").
-include("ocs_eap_codec.hrl").

-spec get_message(Data, State) ->
			{NewData, Session} when
	Data :: #radius_request{},
	State :: #state_rcv{},
	NewData :: binary(),
	Session :: #radius_session{}.
%% @doc Build accounting request
get_message(#radius_request{type = acc, username = PeerID, secret = Secret},
		#state_rcv{session = #radius_session{radius_id = RadID,
		data = #accounting{type = start} = Acc} = Session}= State) ->
	MAC = integer_to_list(rand:uniform(19999999999)), %% FIXME
	{_, UserID} = lists:keyfind(tsung_userid, 1, State#state_rcv.dynvars),
	NasID = "mx-west-" ++ integer_to_list(UserID), 
	AcctSessionID = "0A0055C" ++ integer_to_list(UserID), %% FIXME
	ReqAuth = radius:authenticator(),
	RequestPacket = accounting_start(AcctSessionID,
			NasID, Secret, PeerID, MAC, ReqAuth, RadID),
	NewSession =
			Session#radius_session{data = Acc#accounting{req_auth = ReqAuth,
			acc_session_id = AcctSessionID}, mac = MAC, nas_id = NasID},
	{RequestPacket, NewSession};
get_message(#radius_request{type = acc, secret = Secret},
		#state_rcv{session = #radius_session{username = PeerID, 
		radius_id = RadID, nas_id = NasID, mac = MAC, data =
		#accounting{type = interim, acc_session_id = AccSID} = Acc}
		= Session}) when is_list(PeerID)->
	ReqAuth = radius:authenticator(),
	RequestPacket = interim_update(AccSID,
		NasID, Secret, PeerID, MAC, ReqAuth, RadID),
	NewSession =
		Session#radius_session{data = Acc#accounting{req_auth = ReqAuth}},
	{RequestPacket, NewSession};
get_message(#radius_request{type = acc, secret = Secret},
		#state_rcv{session = #radius_session{username = PeerID, 
		radius_id = RadID, nas_id = NasID, mac = MAC, data =
		#accounting{type = stop, acc_session_id = AccSID} = Acc}
		= Session}) when is_list(PeerID)->
	ReqAuth = radius:authenticator(),
	RequestPacket = accounting_stop(AccSID,
		NasID, Secret, PeerID, MAC, ReqAuth, RadID),
	{RequestPacket, Session}.

-spec parse(Data, State) ->
			{NewState, Options, Close} when
	Data :: binary(),
	State :: #state_rcv{},
	NewState :: #state_rcv{},
	Options :: list(),
	Close :: boolean().
%% @doc Validate received radius packet
parse(<<?AccountingResponse, _/binary>> = D, State) ->
	parse1(State);
parse(_, #state_rcv{session = #radius_session{radius_id = RadID, data = Acc} = Session} = State) ->
	NextRadID = (RadID rem 255) + 1,
	NewSession = Session#radius_session{radius_id = NextRadID},
	NewState = State#state_rcv{ack_done = true, session = NewSession},
	{NewState, [], false}.
%% @hidden
parse1(#state_rcv{session = #radius_session{radius_id = RadID, data =
		#accounting{type = start}} = Session} = State) ->
	NextRadID = (RadID rem 255) + 1,
	NewSession = Session#radius_session{radius_id = NextRadID},
	NewState = State#state_rcv{ack_done = true, session = NewSession},
	{NewState, [], false};
parse1( #state_rcv{session = #radius_session{radius_id = RadID, data =
		#accounting{type = interim} = _Acc} = Session} = State) ->
	NextRadID = (RadID rem 255) + 1,
	NewSession = Session#radius_session{radius_id = NextRadID},
	NewState = State#state_rcv{ack_done = true, session = NewSession},
	{NewState, [], false};
parse1(#state_rcv{session = #radius_session{radius_id = RadID,
		data = #accounting{type = stop}} = Session} = State) ->
	NextRadID = (RadID rem 255) + 1,
	NewSession = Session#radius_session{radius_id = NextRadID},
	NewState = State#state_rcv{ack_done = true, session = NewSession},
	{NewState, [], false}.

accounting_start(AcctSessionID, NasID, Secret, PeerID, MAC, Auth, RadID) ->
	A0 = radius_attributes:new(),
	A1 = radius_attributes:add(?AcctStatusType, ?AccountingStart, A0),
	access_request(A1, AcctSessionID, NasID, Secret,
			PeerID, MAC, Auth, RadID).

interim_update(AcctSessionID, NasID, Secret, PeerID, MAC, Auth, RadID) ->
	A0 = radius_attributes:new(),
	A1 = radius_attributes:add(?AcctStatusType, ?AccountingInterimUpdate, A0),
	A2 = radius_attributes:add(?AcctInputOctets, 200, A1),
	A3 = radius_attributes:add(?AcctOutputOctets, 100, A2),
	access_request(A3, AcctSessionID, NasID, Secret,
			PeerID, MAC, Auth, RadID).

accounting_stop(AcctSessionID, NasID, Secret, PeerID, MAC, Auth, RadID) ->
	A0 = radius_attributes:new(),
	A1 = radius_attributes:add(?AcctStatusType, ?AccountingStop, A0),
	A2 = radius_attributes:add(?AcctInputOctets, 500, A1),
	A3 = radius_attributes:add(?AcctOutputOctets, 200, A2),
	access_request(A3, AcctSessionID, NasID, Secret,
			PeerID, MAC, Auth, RadID).

access_request(RadiusAttributes, AcctSessionID, NasId, Secret,
		PeerID, MAC, Auth, RadID) ->
	A1 = radius_attributes:add(?UserName, PeerID, RadiusAttributes),
	A2 = radius_attributes:add(?NasPort, 0, A1),
	A3 = radius_attributes:add(?NasIdentifier, NasId, A2),
	A4 = radius_attributes:add(?CallingStationId, MAC, A3),
	A5 = radius_attributes:add(?AcctSessionId, AcctSessionID, A4),
	AccAttributes = radius_attributes:codec(A5),
	Acc1Length = size(AccAttributes) + 20,
	AccAuthenticator = crypto:md5([<<?AccountingRequest, RadID,
			Acc1Length:16, 0:128>>, AccAttributes, Secret]), 
	AccountingRequest = #radius{code = ?AccountingRequest, id = RadID,
			authenticator = AccAuthenticator, attributes = AccAttributes},
	radius:codec(AccountingRequest).

