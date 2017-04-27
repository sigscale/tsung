-module(ts_auth_pap).
-author('prahveen@sigscale.org').

-export([get_message/2, parse/2]).

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_radius.hrl").
-include_lib("radius/include/radius.hrl").
-include_lib("ocs/include/ocs_eap_codec.hrl").

-spec get_message(Data :: #radius_request{}, State ::#state_rcv{}) ->
	{NewData :: binary(), Session :: #radius_session{}}.
%% @doc Build simple authentication request
get_message(#radius_request{username = PeerID,
		password = Password, secret = Secret}, #state_rcv{session
		= #radius_session{radius_id = RadID, nas_id = NasID} = Session}) ->
	MAC = integer_to_list(rand:uniform(19999999999)),
	Authenticator = radius:authenticator(),
	UserPassword = radius_attributes:hide(Secret, Authenticator, Password),	
	A0 = radius_attributes:new(),
	A1 = radius_attributes:store(?ServiceType, 2, A0),
	A2 = radius_attributes:store(?NasPortId, "wlan3", A1),
	A3 = radius_attributes:store(?NasPortType, 19, A2),
	A4 = radius_attributes:store(?UserName, PeerID, A3),
	A5 = radius_attributes:store(?AcctSessionId, "826005e4", A4),
	A6 = radius_attributes:store(?CallingStationId, MAC, A5),
	A7 = radius_attributes:store(?CalledStationId, "WPA-PSK", A6),
	A8 = radius_attributes:store(?UserPassword, UserPassword, A7),
	A9 = radius_attributes:store(?NasIdentifier, NasID, A8),
	AccessReqest = #radius{code = ?AccessRequest, id = RadID, authenticator = Authenticator,
			attributes = A9},
	AccessReqestPacket= radius:codec(AccessReqest),
	NewSession = Session#radius_session{username = PeerID, mac = MAC, 
		radius_id = RadID},
	{AccessReqestPacket, NewSession}.

-spec parse(Data, State) ->
			{NewState, Options, Close} when
	Data :: binary(),
	State :: #state_rcv{},
	NewState :: #state_rcv{},
	Options :: list(),
	Close :: boolean().
%% @doc Validate received radius packet
parse(<<?AccessReject, _/binary>>,#state_rcv{session
		= #radius_session{radius_id = RadID} = Session} = State) ->
	NextRadID = (RadID rem 255) + 1, 
	NewSession = Session#radius_session{radius_id = NextRadID,
		result_value = "failure"},
	NewState = State#state_rcv{ack_done = true, session = NewSession},
	{NewState, [], false};
parse(AccessAcceptPacket, #state_rcv{session 
		= #radius_session{radius_id = RadID} = Session} = State) ->
	#radius{code = ?AccessAccept, id = RadID} =
			radius:codec(AccessAcceptPacket),
	NextRadID = (RadID rem 255) + 1, 
	NewSession = Session#radius_session{radius_id = NextRadID,
		result_value = "success"},
	NewState = State#state_rcv{ack_done = true, session = NewSession},
	{NewState, [], false}.

