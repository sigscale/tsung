-define(Registered, registered).
-define(Timeout, 4000).
-define(ChunkSize, 10).
-define(SessionTab, accsession).
-define(SessionTabOptions, [private, named_table, {keypos, 2}]).

-record(registered, {username, password}).

-record(acc_session,
			{username,
			type = start :: start | interim | stop}).

-record(radius_request,
			{type :: auth | acc,
			port :: integer(),
			username :: string() | binary(),
			anon_name :: string() | binary(),
			password :: string() | binary(),
			secret :: string() | binary(),
			cb_mod :: atom(),
			auth_type = undefined :: undefined | pap | eap_pwd,
			acc_type = start :: start | interim | stop,
			result_var = "challenge" :: string()}).

-record(radius_session,
			{username :: string() | binary(),
			anon_name :: string() | binary(),
			radius_id :: byte(),
			mac :: string() | binary(),
			nas_id :: string() | binary(),
			result_value :: atom(),
			data :: string() | binary()}).

-record(pwd,
			{eap_id :: byte(),
			state = none :: none | atom(),
			token = undefined :: undefined | binary(),
			server_id :: string() | binary(),
			req_auth :: binary(),
			s_element :: binary(),
			p_element :: binary(),
			s_scalar :: binary(),
			p_scalar :: binary(),
			p_rand :: integer(),
			pwe :: binary(),
			buffer :: binary(),
			eap_ack = no_ack :: no_ack | ch | sh | cs,
			eap_ack_done :: boolean()}).

-record(accounting,
			{type = start :: start | interim | stop,
			counter = 0 :: integer(),
			req_auth :: binary(),
			resp_auth :: binary(),
			tab_id :: atom(),
			acc_session_id :: string() | binary()}).
