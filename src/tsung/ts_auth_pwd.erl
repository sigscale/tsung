-module(ts_auth_pwd).
-author('prahveen@sigscale.org').

-export([get_message/2, parse/2]).

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_radius.hrl").
-include_lib("radius/include/radius.hrl").
-include_lib("ocs/include/ocs_eap_codec.hrl").

-spec get_message(Data, State) ->
			{NewData, Session} when
	Data :: #radius_request{},
	State :: #state_rcv{},
	NewData :: binary(),
	Session :: #radius_session{}.
%% @doc Build pwd authentication request
get_message(#radius_request{username= PeerID, secret = Secret},
		#state_rcv{session = #radius_session{username = undefined,
		data = #pwd{state = none, eap_id = EapID} = Eap, radius_id = RadID}
		= Session} = State) ->
	MAC = integer_to_list(rand:uniform(19999999999)),
	{_, UserID} = lists:keyfind(tsung_userid, 1, State#state_rcv.dynvars),
	NasID = "mx-north-" ++ integer_to_list(UserID), 
	ReqAuth = radius:authenticator(),
	NewEapID = (EapID rem 255) + 1,
	RequestPacket =
		send_identity(NasID, Secret, PeerID, MAC, ReqAuth, RadID, NewEapID),
	NewSession = Session#radius_session{username = PeerID,
		data = Eap#pwd{state = id, req_auth = ReqAuth}, mac = MAC,
		nas_id = NasID},
	{RequestPacket, NewSession};
get_message(#radius_request{secret = Secret, username = PeerID},
		#state_rcv{session = #radius_session{username = PeerID,
		data = #pwd{state = id, eap_id  = EapID, token = Token} = Eap,
		radius_id = RadID, mac = MAC, nas_id = NasID} = Session}) ->
	ReqAuth = radius:authenticator(),
	RequestPacket = send_id(Secret, ReqAuth, PeerID, NasID, MAC,
			Token, RadID, EapID),
	NewSession = Session#radius_session{data = Eap#pwd{state = commit,
		req_auth = ReqAuth}},
	{RequestPacket, NewSession};
get_message(#radius_request{username = PeerID, password = Password,
		secret = Secret}, #state_rcv{session = #radius_session{username =
		PeerID, data = #pwd{state = commit, eap_id = EapID, token = Token,
		server_id = ServerID} = Eap, radius_id = RadID, mac = MAC,
		nas_id = NasID} = Session}) ->
	BPeerID = list_to_binary(PeerID),
	BPassword = list_to_binary(Password),
	PWE = ocs_eap_pwd:compute_pwe(Token, BPeerID, ServerID, BPassword),
	Prand = crypto:rand_uniform(1, ?R),
	{ScalarP, ElementP} = ocs_eap_pwd:compute_scalar(<<Prand:256>>, PWE),
	ReqAuth = radius:authenticator(),
	RequestPacket = send_commit(Secret, ReqAuth, PeerID, NasID, MAC,
			ScalarP, ElementP, RadID, EapID),
	NewSession = Session#radius_session{data = Eap#pwd{state = confirm,
		req_auth = ReqAuth, p_element = ElementP, p_scalar = ScalarP,
		pwe = PWE, p_rand = Prand}},
	{RequestPacket, NewSession};
get_message(#radius_request{username = PeerID, secret = Secret},
		#state_rcv{session = #radius_session{username = PeerID, data =
		#pwd{state = confirm, eap_id = EapID, p_rand = Prand, pwe = PWE,
		s_scalar = ScalarS, s_element = ElementS, p_scalar = ScalarP,
		p_element = ElementP} = Eap, radius_id = RadID, mac = MAC,
		nas_id = NasID} = Session}) ->
	Ciphersuite = <<19:16, 1, 1>>,
	Kp = ocs_eap_pwd:compute_ks(<<Prand:256>>, PWE, ScalarS, ElementS),
	Input = [Kp, ElementP, ScalarP, ElementS, ScalarS, Ciphersuite],
	ConfirmP = ocs_eap_pwd:h(Input),
	ReqAuth = radius:authenticator(),
	RequestPacket = send_confirm(Secret, ReqAuth,
			PeerID, NasID, MAC, ConfirmP, RadID, EapID),
	NewSession = Session#radius_session{data =
		Eap#pwd{state = success, req_auth = ReqAuth}},
	{RequestPacket, NewSession}.
	
-spec parse(Data, State) ->
			{NewState, Options, Close} when
	Data :: binary(),
	State :: #state_rcv{},
	NewState :: #state_rcv{},
	Options :: list(),
	Close :: boolean().
%% @doc Validate received radius packet
parse(<<?AccessReject, _/binary>>, #state_rcv{session
		= #radius_session{data = #pwd{eap_id = EapID},
		radius_id = RadID}} = State) ->
	NewEapID = (EapID rem 255) + 1,
	Eap = #pwd{eap_id = NewEapID},
	NextRadID = (RadID rem 255) + 1,
	NewSession = #radius_session{data = Eap,
			result_value = "failure", radius_id = NextRadID},
	NewState = State#state_rcv{session = NewSession, ack_done = true},
	{NewState, [], true};
parse(<<?AccessChallenge, _/binary>> = Data,
		#state_rcv{session = #radius_session{data = #pwd{state = id,
		req_auth = ReqAuth} = Eap, radius_id = RadID} = Session, request =
		#ts_request{param = #radius_request{secret = Secret}}} = State) ->
	{EapID, Token, ServerID} = receive_id(Data, Secret, ReqAuth, RadID),
	NewEap = Eap#pwd{eap_id = EapID, token = Token, server_id = ServerID},
	NextRadID = (RadID rem 255) + 1,
	NewSession = Session#radius_session{radius_id = NextRadID, data = NewEap,
		result_value = "challenge"},
	NewState = State#state_rcv{session = NewSession, ack_done = true},
	{NewState, [], false};
parse(<<?AccessChallenge, _/binary>> = Data,
		#state_rcv{session = #radius_session{data = #pwd{state = commit,
		req_auth = ReqAuth} = Eap, radius_id = RadID} = Session, request =
		#ts_request{param = #radius_request{secret = Secret}}} = State) ->
	{EapID, ElementS, ScalarS} = receive_commit(Data, Secret, ReqAuth, RadID),
	NewEap = Eap#pwd{eap_id = EapID, s_element = ElementS, s_scalar = ScalarS},
	NextRadID = (RadID rem 255) + 1,
	NewSession = Session#radius_session{radius_id = NextRadID, data = NewEap},
	NewState = State#state_rcv{session = NewSession, ack_done = true},
	{NewState, [], false};
parse(<<?AccessChallenge, _/binary>> = Data,
		#state_rcv{session = #radius_session{data = #pwd{state = confirm,
		req_auth = ReqAuth} = Eap, radius_id = RadID} = Session, request =
		#ts_request{param = #radius_request{secret = Secret}}} = State) ->
	{EapID, _ConfirmS} =
			receive_confirm(Data, Secret, ReqAuth, RadID),
	NewEap = Eap#pwd{eap_id = EapID},
	NextRadID = (RadID rem 255) + 1,
	NewSession = Session#radius_session{radius_id = NextRadID, data = NewEap},
	NewState = State#state_rcv{session = NewSession, ack_done = true},
	{NewState, [], false};
parse(<<?AccessAccept, _/binary>> = Data,
		#state_rcv{session = #radius_session{username = PeerID,
		data = #pwd{state = success, req_auth = ReqAuth, eap_id = EapID},
		radius_id = RadID} = _Session, request = #ts_request{param =
		#radius_request{secret = Secret}}} = State) ->
	ok = receive_success(Data, Secret, ReqAuth, RadID),
	NewEapID = (EapID rem 255) + 1,
	Eap = #pwd{state = none, eap_id = NewEapID},
	NextRadID = (RadID rem 255) + 1,
	NewSession = #radius_session{username = PeerID, data = Eap,
			result_value = "success", radius_id = NextRadID},
	NewState = State#state_rcv{session = NewSession, ack_done = true},
	{NewState, [], false}.

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------
send_identity(NasID, Secret, PeerID, MAC, Auth, RadID, EapID) ->
	EapPacket  = #eap_packet{code = response, type = ?Identity,
			identifier = EapID, data = list_to_binary(PeerID)},
	EapMsg = ocs_eap_codec:eap_packet(EapPacket),
	access_request(NasID, Secret, PeerID, MAC, Auth, RadID, EapMsg).

send_id(Secret, Auth, PeerID, NasID, MAC, Token, RadID, EapID) ->
	EapPwdID = #eap_pwd_id{group_desc = 19, random_fun = 16#1, prf = 16#1,
			token = Token, pwd_prep = none, identity = list_to_binary(PeerID)},
	EapPwd = #eap_pwd{pwd_exch = id, data = ocs_eap_codec:eap_pwd_id(EapPwdID)},
	EapPacket  = #eap_packet{code = response, type = ?PWD, identifier = EapID,
			data = ocs_eap_codec:eap_pwd(EapPwd)},
	EapMsg = ocs_eap_codec:eap_packet(EapPacket),
	access_request(NasID, Secret, PeerID, MAC, Auth, RadID, EapMsg).

send_commit(Secret, Auth, PeerID, NasID, MAC, ScalarP, ElementP, RadID, EapID) ->
	EapPwdCommit = #eap_pwd_commit{scalar = ScalarP, element = ElementP},
	EapPwd = #eap_pwd{length = false, more = false, pwd_exch = commit,
			data = ocs_eap_codec:eap_pwd_commit(EapPwdCommit)},
	EapPacket = #eap_packet{code = response, type = ?PWD,
			identifier = EapID, data = ocs_eap_codec:eap_pwd(EapPwd)},
	EapMsg = ocs_eap_codec:eap_packet(EapPacket),
	access_request(NasID, Secret, PeerID, MAC, Auth, RadID, EapMsg).

send_confirm(Secret, Auth, PeerID, NasID, MAC, ConfirmP, RadID, EapID) ->
	EapPwd = #eap_pwd{length = false, more = false,
			pwd_exch = confirm, data = ConfirmP},
	EapPacket = #eap_packet{code = response, type = ?PWD,
			identifier = EapID, data = ocs_eap_codec:eap_pwd(EapPwd)},
	EapMsg = ocs_eap_codec:eap_packet(EapPacket),
	access_request(NasID, Secret, PeerID, MAC, Auth, RadID, EapMsg).

receive_id(RadPacket, Secret, ReqAuth, RadId) ->
	EapMsg = access_challenge(RadPacket, Secret, RadId, ReqAuth),
	#eap_packet{code = request, type = ?PWD, identifier = EapId,
			data = EapData} = ocs_eap_codec:eap_packet(EapMsg),
	#eap_pwd{length = false, more = false, pwd_exch = id,
			data = EapPwdData} = ocs_eap_codec:eap_pwd(EapData),
	#eap_pwd_id{group_desc = 19, random_fun = 16#1,
			prf = 16#1, pwd_prep = none, token = Token,
			identity = ServerID} = ocs_eap_codec:eap_pwd_id(EapPwdData),
	{EapId, Token, ServerID}.

receive_commit(RadPacket, Secret, ReqAuth, RadID) ->
	EapMsg = access_challenge(RadPacket, Secret, RadID, ReqAuth),
	#eap_packet{code = request, type = ?PWD, identifier = EapID,
			data = EapData} = ocs_eap_codec:eap_packet(EapMsg),
	#eap_pwd{length = false, more = false, pwd_exch = commit,
			data = EapPwdData} = ocs_eap_codec:eap_pwd(EapData),
	#eap_pwd_commit{element = ElementS,
			scalar = ScalarS} = ocs_eap_codec:eap_pwd_commit(EapPwdData),
	{EapID, ElementS, ScalarS}.

receive_confirm(RadPacket, Secret, ReqAuth, RadID) ->
	EapMsg = access_challenge(RadPacket, Secret, RadID, ReqAuth),
	#eap_packet{code = request, type = ?PWD, identifier = EapID,
			data = EapData} = ocs_eap_codec:eap_packet(EapMsg),
	#eap_pwd{length = false, more = false, pwd_exch = confirm,
			data = ConfirmS} = ocs_eap_codec:eap_pwd(EapData),
	{EapID, ConfirmS}.

receive_success(RadPacket, Secret, ReqAuth, RadID) ->
	EapMsg = access_accept(RadPacket, Secret, RadID, ReqAuth),
	#eap_packet{code = success} = ocs_eap_codec:eap_packet(EapMsg),
	ok.

access_challenge(RadPacket, Secret, RadID, ReqAuth) ->
	receive_radius(?AccessChallenge, RadPacket, Secret, RadID, ReqAuth).

access_accept(RadPacket, Secret, RadID, ReqAuth) ->
	receive_radius(?AccessAccept, RadPacket, Secret, RadID, ReqAuth).

access_request(NasID, Secret, PeerID, MAC, Auth, RadID, EapMsg) ->
	A0 = radius_attributes:new(),
	A1 = radius_attributes:add(?UserName, PeerID, A0),
	A2 = radius_attributes:add(?NasPort, 0, A1),
	A3 = radius_attributes:add(?NasIdentifier, NasID, A2),
	A4 = radius_attributes:add(?CallingStationId, MAC, A3),
	A5 = radius_attributes:add(?EAPMessage, EapMsg, A4),
	A6 = radius_attributes:add(?MessageAuthenticator,
			list_to_binary(lists:duplicate(16,0)), A5),
	Request1 = #radius{code = ?AccessRequest, id = RadID,
		authenticator = Auth, attributes = A6},
	ReqPacket1 = radius:codec(Request1),
	MsgAuth1 = crypto:hmac(md5, Secret, ReqPacket1),
	A7 = radius_attributes:store(?MessageAuthenticator, MsgAuth1, A6),
	Request2 = Request1#radius{attributes = A7},
	radius:codec(Request2).

receive_radius(Code, RadPacket, Secret, RadId, ReqAuth) ->
	Resp1 = radius:codec(RadPacket),
	#radius{code = Code, id = RadId, authenticator = RespAuth,
		attributes = BinRespAttr1} = Resp1,
	Resp2 = Resp1#radius{authenticator = ReqAuth},
	RespPacket2 = radius:codec(Resp2),
	RespAuth = binary_to_list(crypto:hash(md5, [RespPacket2, Secret])),
	RespAttr1 = radius_attributes:codec(BinRespAttr1),
	{ok, MsgAuth} = radius_attributes:find(?MessageAuthenticator, RespAttr1),
	RespAttr2 = radius_attributes:store(?MessageAuthenticator,
			list_to_binary(lists:duplicate(16, 0)), RespAttr1),
	Resp3 = Resp2#radius{attributes = RespAttr2},
	RespPacket3 = radius:codec(Resp3),
	MsgAuth = crypto:hmac(md5, Secret, RespPacket3),
	{ok, EapMsg} = radius_attributes:find(?EAPMessage, RespAttr1),
	EapMsg.



