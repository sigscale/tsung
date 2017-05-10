-define(SessionTabOptions, [named_table, public, {keypos, 2}]).

-record(radius_user,
			{username :: string(),
			password :: string() | binary(),
			registered = true :: boolean(),
			reg_time :: integer(),
			session_timeout :: integer(),
			interval :: integer(),
			acct_start_time :: integer(),
			last_interim_update :: integer()}).

-record(radius_request,
			{type :: auth | acct,
			port :: integer(),
			username :: string() | binary(),
			anon_name :: string() | binary(),
			password :: string() | binary(),
			secret :: string() | binary(),
			cb_mod :: atom(),
			duration = 3600 :: integer(),
			interim :: integer(),
			max_reg :: integer(),
			auth_type = undefined :: undefined | pap | eap_pwd,
			acct_type = start :: start | interim | stop,
			result_var = "challenge" :: string()}).

-record(radius_session,
			{username :: string() | binary(),
			password :: string() | binary(),
			anon_name :: string() | binary(),
			radius_id :: byte(),
			mac :: string() | binary(),
			nas_id :: string() | binary(),
			result_value :: atom(),
			tab_id :: atom(),
			tot_reg = 0 :: integer(),
			interval :: integer(),
			duration :: integer(),
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
			req_auth :: binary(),
			resp_auth :: binary(),
			start_time,
			finish :: boolean(),
			acc_session_id :: string() | binary()}).
