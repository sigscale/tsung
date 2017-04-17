#  Tsung for RADIUS/EAP

[Tsung](http://tsung.erlang-projects.org) is a multi-protocol
distributed load testing tool.

The [SigScale](http://www.sigscale.org) plug-ins included in here add
support for the RADIUS and EAP protocols.

## RADIUS

The [RADIUS](https://tools.ietf.org/html/rfc2865) protocol stack provided
in SigScale's [radierl](http://github.com/sigscale/radierl) project is used by
the RADIUS plug-in included here. With the inclusion of this plug-in a scenario
[configuration](http://tsung.erlang-projects.org/user_manual/configuration.html)
file may include a `<radius>...</radius>` stanza as in the examples below.

#### Authentication
```xml
<transaction name="authentication_simple">
    <request>
        <radius type="auth" secret="helga1989" auth_type="pap" username="john">
            <pap cb_mod='ts_auth_pap' password="12345"></pap>
        </radius>
    </request>
</transaction>
```

#### Accounting
```xml
<transaction name="accounting">
    <request>
        <radius type="acc" acc_type="start" secret="helga1989" username="john">
             <accounting cb_mod="ts_accounting"></accounting>
        </radius>
    </request>
</transaction>
```

### Usernames/Passwords
The user names and passwords used may also be provided through
[dynamic substitution](http://tsung.erlang-projects.org/user_manual/conf-advanced-features.html#dynamic-substitutions):
```xml
<setdynvars sourcetype="file" fileid="credentials" delimiter="," order="random">
    <var name="username" />
    <var name="password" />
</setdynvars>
<transaction name="authentication_simple">
    <request subst='true'>
        <radius type="auth" secret="helga1989" auth_type="pap" username="%%_username%%">
            <pap cb_mod='ts_auth_pap' password="%%_password%%"></pap>
        </radius>
    </request>
</transaction>
```

### Users/Clients
While other protocols Tsung supports (e.g. HTTP) have short lived sessions
with RADIUS a Network Access Server (NAS) would maintain a permanent
association with an Access, Authentication & Accounting (AAA) server.
Therefore a scenario configuration for RADIUS will typically use a
[repeat](http://tsung.erlang-projects.org/user_manual/conf-advanced-features.html#repeat)
element in a `<session>`:
```xml
<session weight="1" name="simple-auth" type="ts_radius">
    <repeat name="nas-simple" max_repeat="10000000" >
        <transaction name="authentication_simple">
            <request>
                <radius type="auth" secret="helga1989" auth_type="pap" username="john">
                    <pap cb_mod='ts_auth_pap' password="12345"></pap>
                </radius>
            </request>
        </transaction>
    <while var="username" neq="done"/>
    </repeat>
</session> 
```

### Timing
The [`<thinktime>`](http://tsung.erlang-projects.org/user_manual/conf-sessions.html#thinktimes)
element is normally used in Tsung to space client sessions however since with
RADIUS sessions are long lived the `<radius>` element supports attributes to
control request timing. In the example below a random 50-200ms delay between
requests will be used:
```xml
<radius type="auth" secret="helga1989" auth_type="pap" username="john" min="50" max="200" random="true">
```

## Extensible Authentication Protocol (EAP)
Support for [EAP](https://tools.ietf.org/html/rfc3748) protocol within RADIUS
transactions is provided through SigScale's [OCS](http://github.com/sigscale/ocs)
project. Currently only the [PWD](https://tools.ietf.org/html/rfc5931) method
is supported however [TTLS](https://tools.ietf.org/html/rfc5281) is available
in the [OCS](http://github.com/sigscale/ocs) and another plug-in is planned.

The example below shows how to configure an EAP-PWD transaction by repeating
RADIUS access requests while the AAA server replies with challenge responses,
ending when EAP indicates the final response:
```xml
<transaction name="pwd">
    <repeat name="pwd_repeat" max_repeat="4000">
        <request subst='true'>
            <radius type="auth" shared_secret="helga1989" auth_type="eap-pwd" username="john" result_var="result">
                <eap_pwd cb_mod="ts_auth_pwd" password="12345"></eap_pwd>
            </radius>
        </request>
        <while var="result" eq="challenge"/>
</repeat>
```

