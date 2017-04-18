#  Tsung for RADIUS/EAP

[Tsung](http://tsung.erlang-projects.org) is a multi-protocol
distributed load testing tool.

The [SigScale](http://www.sigscale.org) plug-ins included here add
support for the RADIUS and EAP protocols.

## RADIUS

The [RADIUS](https://tools.ietf.org/html/rfc2865) protocol stack provided
in SigScale's [radierl](http://github.com/sigscale/radierl) project is used by
the RADIUS plug-ins included here.

## Scenario Configuration
An XML format configuration file defines the behaviour of a scenario Tsung will
run when it is started.  With the inclusion of the RADIUS plug-ins a scenario
[configuration](http://tsung.erlang-projects.org/user_manual/configuration.html)
file may include a `<radius>...</radius>` stanza as in the examples below.

### Servers
The system under test (SUT) is defined in the `<servers>` stanza with each
host port defined in a `<server>` element. A RADIUS example follows:
```xml
<servers>
    <server host="ocs" port="1812" type="udp""></server>
    <server host="ocs" port="1813" type="udp"></server>
</servers>
```

### Clients
Tsung may be run distributed on a cluster of hosts. Each host is described
in the `<clients>` stanza of the scenario configuration file. The Tsung
controller node is the one Tsung was started on. Other nodes are started
automatically using `rsh`:
```xml
<clients>
    <client host="tsung-slave-1"/>
    <client host="tsung-slave-2"/>
    <client host="tsung-slave-3"/>
</clients>
```

### Users
In Tsung a "user" is an open socket on a client running a protocol.
Users are defined by a `<users>` element within an `<arrivalphase>`
which specifies how many users are started and how quickly. It is found
in the `<load>` stanza which defines the "load progression":
```xml
<load>
    <arrivalphase phase="1" duration="10" unit="minute">
        <users maxnumber="100" arrivalrate="5" unit="second"></users>
    </arrivalphase>
    <arrivalphase phase="2" duration="1440" unit="minute">
        <users maxnumber="150" arrivalrate="1" unit="second"></users>
    </arrivalphase>
</load>
```

### Sessions
In Tsung "sessions" describe the requests to execute on a user socket.
Sessions are defined in the `<sessions>` stanza with named session
types defined in `<session>` elements. The protocol used is defined
within `<request>` elements which may optionally be enclosed within
a `<transaction>` element (used for grouping in reports):
```xml
<sessions>
    <session name="auth-pwd" type="ts_radius">
        <transaction name="eap-pwd">
            <request> ... </request>
            <request> ... </request>
            <request> ... </request>
        </transaction>
    </session>
</sessions>
```

### RADIUS
In the above example a session was defined to use the RADIUS plug-in with
an attribute of `type="ts_radius"`. This allows the use of a `<radius>`
element within a `<request>`.

#### RADIUS Authentication
RADIUS `Access-Request` transactions are configured with a `<radius>`
element having a `type=auth` attribute. The value of the `secret`
attribute defines the secret shared with the NAS.  Simple authentication
is configured with a `<pap>` element:
```xml
<transaction name="auth-simple">
    <request>
        <radius type="auth" secret="helga1989" username="john">
            <pap cb_mod='ts_auth_pap' password="12345"></pap>
        </radius>
    </request>
</transaction>
```

#### RADIUS Accounting
RADIUS `Accounting-Request` transactions are configured with a `<radius>`
element having a `type=acc` attribute. A session performing An `<accounting>` element may include
an `interim` attribute specifying how many interim updates to send between
start and stop requests.
```xml
<transaction name="accounting">
    <request>
        <radius type="acc" secret="helga1989" username="john">
             <accounting cb_mod="ts_accounting" interim="5"></accounting>
        </radius>
    </request>
</transaction>
```

### Usernames/Passwords
The above examples use static usernames and passwords however they may also
be provided through
[dynamic substitution](http://tsung.erlang-projects.org/user_manual/conf-advanced-features.html#dynamic-substitutions)
as shown in the example below:
```xml
<setdynvars sourcetype="file" fileid="credentials" delimiter="," order="random">
    <var name="username" />
    <var name="password" />
</setdynvars>
<transaction name="auth-simple">
    <request subst='true'>
        <radius type="auth" secret="helga1989" username="%%_username%%">
            <pap cb_mod='ts_auth_pap' password="%%_password%%"></pap>
        </radius>
    </request>
</transaction>
```

### Looping
While other protocols Tsung supports (e.g. HTTP) have short lived sessions
with RADIUS a Network Access Server (NAS) would maintain a permanent
association with an Access, Authentication & Accounting (AAA) server. Each
"user" defined in the scenario configuration represents a socket of a NAS.
Therefore a scenario configuration for RADIUS will typically use a
[repeat](http://tsung.erlang-projects.org/user_manual/conf-advanced-features.html#repeat)
element within a `<session>`:
```xml
<session weight="1" name="simple-auth" type="ts_radius">
    <repeat name="nas-simple" max_repeat="10000000" >
        <transaction name="auth-simple">
            <request>
                <radius type="auth" secret="helga1989" username="john">
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
element is normally used in Tsung to pace client sessions however since with
RADIUS sessions are long lived the `<radius>` element supports attributes to
control inter-request timing. In the example below a random 50-200ms delay between
requests will be used:
```xml
<radius type="auth" secret="helga1989" sername="john" min="50" max="200" random="true">
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
            <radius type="auth" shared_secret="helga1989" username="john" result_var="result">
                <eap_pwd cb_mod="ts_auth_pwd" password="12345"></eap_pwd>
            </radius>
        </request>
        <while var="result" eq="challenge"/>
</repeat>
```

