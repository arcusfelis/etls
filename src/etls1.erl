-module(etls1).
-export([test/0]).

%% Major, minor
-define(PROTOCOL_VERSION_TLS_1_0, 3, 1).

-define(CONTENT_TYPE_HANDSHAKE, 22).
-define(HANDSHAKE_TYPE_CLIENT_HELLO, 1).
-define(HANDSHAKE_TYPE_SERVER_HELLO, 2).

-define(TLS_NULL_WITH_NULL_NULL,               16#00, 16#00).

-define(TLS_RSA_WITH_NULL_MD5,                 16#00, 16#01).
-define(TLS_RSA_WITH_NULL_SHA,                 16#00, 16#02).
-define(TLS_RSA_EXPORT_WITH_RC4_40_MD5,        16#00, 16#03).
-define(TLS_RSA_WITH_RC4_128_MD5,              16#00, 16#04).
-define(TLS_RSA_WITH_RC4_128_SHA,              16#00, 16#05).
-define(TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,    16#00, 16#06).
-define(TLS_RSA_WITH_IDEA_CBC_SHA,             16#00, 16#07).
-define(TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,     16#00, 16#08).
-define(TLS_RSA_WITH_DES_CBC_SHA,              16#00, 16#09).
-define(TLS_RSA_WITH_3DES_EDE_CBC_SHA,         16#00, 16#0A).

-define(TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,  16#00, 16#0B).
-define(TLS_DH_DSS_WITH_DES_CBC_SHA,           16#00, 16#0C).
-define(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,      16#00, 16#0D).
-define(TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,  16#00, 16#0E).
-define(TLS_DH_RSA_WITH_DES_CBC_SHA,           16#00, 16#0F).
-define(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,      16#00, 16#10).
-define(TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, 16#00, 16#11).
-define(TLS_DHE_DSS_WITH_DES_CBC_SHA,          16#00, 16#12).
-define(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,     16#00, 16#13).
-define(TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, 16#00, 16#14).
-define(TLS_DHE_RSA_WITH_DES_CBC_SHA,          16#00, 16#15).
-define(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,     16#00, 16#16).

-define(TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,    16#00, 16#17).
-define(TLS_DH_anon_WITH_RC4_128_MD5,          16#00, 16#18).
-define(TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, 16#00, 16#19).
-define(TLS_DH_anon_WITH_DES_CBC_SHA,          16#00, 16#1A).
-define(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,     16#00, 16#1B).

%% Advanced Encryption Standard (AES) Ciphersuites
%% RFC 3268
-define(TLS_RSA_WITH_AES_128_CBC_SHA,          16#00, 16#2F).
-define(TLS_DH_DSS_WITH_AES_128_CBC_SHA,       16#00, 16#30).
-define(TLS_DH_RSA_WITH_AES_128_CBC_SHA,       16#00, 16#31).
-define(TLS_DHE_DSS_WITH_AES_128_CBC_SHA,      16#00, 16#32).
-define(TLS_DHE_RSA_WITH_AES_128_CBC_SHA,      16#00, 16#33).
-define(TLS_DH_anon_WITH_AES_128_CBC_SHA,      16#00, 16#34).

-define(TLS_RSA_WITH_AES_256_CBC_SHA,          16#00, 16#35).
-define(TLS_DH_DSS_WITH_AES_256_CBC_SHA,       16#00, 16#36).
-define(TLS_DH_RSA_WITH_AES_256_CBC_SHA,       16#00, 16#37).
-define(TLS_DHE_DSS_WITH_AES_256_CBC_SHA,      16#00, 16#38).
-define(TLS_DHE_RSA_WITH_AES_256_CBC_SHA,      16#00, 16#39).
-define(TLS_DH_anon_WITH_AES_256_CBC_SHA,      16#00, 16#3A).

%% Addition of Camellia Cipher Suites
%% RFC 4132
-define(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,     16#00, 16#41).
-define(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,  16#00, 16#42).
-define(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,  16#00, 16#43).
-define(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA, 16#00, 16#44).
-define(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA, 16#00, 16#45).
-define(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA, 16#00, 16#46).

-define(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,     16#00, 16#84).
-define(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,  16#00, 16#85).
-define(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,  16#00, 16#86).
-define(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA, 16#00, 16#87).
-define(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, 16#00, 16#88).
-define(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA, 16#00, 16#89).

%% Addition of SEED Cipher Suites
%% RFC 4162
-define(TLS_RSA_WITH_SEED_CBC_SHA,             16#00, 16#96).
-define(TLS_DH_DSS_WITH_SEED_CBC_SHA,          16#00, 16#97).
-define(TLS_DH_RSA_WITH_SEED_CBC_SHA,          16#00, 16#98).
-define(TLS_DHE_DSS_WITH_SEED_CBC_SHA,         16#00, 16#99).
-define(TLS_DHE_RSA_WITH_SEED_CBC_SHA,         16#00, 16#9A).
-define(TLS_DH_anon_WITH_SEED_CBC_SHA,         16#00, 16#9B).


-record(server_hello, {
        time,
        random,
        version,
        session_id,
        cipher_suite
}).

-record(caller, {
        ref,
        pid,
        cipher,
        reason,
        server_hello
}).

test() ->
    RemoteHostName = "localhost",
    Callers = spawn_callers(RemoteHostName),
    Responces = collert_responses(Callers, []),
    {filter_supported_ciphers(Responces),
     filter_unsupported_ciphers(Responces)}.
    
filter_supported_ciphers(Responces) ->
    [Cipher || #caller{cipher = Cipher, reason = normal} <- Responces].

filter_unsupported_ciphers(Responces) ->
    [Cipher
     || #caller{cipher = Cipher, server_hello = undefined} <- Responces].

spawn_callers(RemoteHostName) ->
    CollectorPid = self(),
    [begin
        timer:sleep(random:uniform(1000) + 300),
        spawn_caller(RemoteHostName, Ciphers, CollectorPid)
     end
     || Ciphers <- cipher_list()].

spawn_caller(RemoteHostName, Ciphers, CollectorPid) ->
    {Pid, Ref} = spawn_monitor(fun() ->
        ServerHelloRec = call_server(RemoteHostName, Ciphers),
        CollectorPid ! {server_hello, self(), ServerHelloRec}
        end),
    #caller{
        pid = Pid,
        ref = Ref,
        cipher = cipher_name(Ciphers)}.
    

collert_responses([], Acc) ->
    Acc;
collert_responses(Callers, Acc) ->
    receive
        {server_hello, Pid, ServerHelloRec} ->
            %% Update and move into `Acc' the caller's record
            {value,
                Caller = #caller{ref = Ref},
                Callers2} = lists:keytake(Pid, #caller.pid, Callers),
            erlang:demonitor(Ref, [flush]),
            Caller2 = Caller#caller{
                reason = normal,
                server_hello = ServerHelloRec},
            io:format("Cipher ~p is supported.~n",
                      [Caller#caller.cipher]),
            collert_responses(Callers2, [Caller2|Acc]);
        {'DOWN', _Ref, process, Pid, Reason} when Reason =/= normal ->
            {value, Caller, Callers2} =
                lists:keytake(Pid, #caller.pid, Callers),
            io:format("Cipher ~p is not supported.~n",
                      [Caller#caller.cipher]),
%           io:format("Caller for ~p crashed with reason ~n~p.~n",
%                     [Caller#caller.cipher, Reason]),
            Caller2 = Caller#caller{reason = Reason},
            collert_responses(Callers2, [Caller2|Acc])
    end.

call_server(RemoteHostName, Ciphers) ->
    TcpOpts = [binary, {packet, 0}, {active, false}],
    {ok, Sock} = gen_tcp:connect(RemoteHostName, 5222, TcpOpts),
    ok = gen_tcp:send(Sock, open_stream(RemoteHostName)),
    ok = gen_tcp:send(Sock, starttls()),
    flush_socket(Sock, 2000),
    ClientHello = encode_handshake_record(Ciphers),
    io:format("ClientHello is ~p.~n", [ClientHello]),
    ok = gen_tcp:send(Sock, ClientHello),
    {ok, ServerHello} = recv_record(Sock),
    ServerHelloRec = decode_server_hello(ServerHello),
    io:format(user, "ServerHelloRec ~p~n", [ServerHelloRec]),
    flush_socket(Sock, 2000),
    ok = gen_tcp:close(Sock),
    ServerHelloRec.


%% http://ceit.uq.edu.au/content/how-xmpp-works-step-step
%% The client sends a open stream packet to server to request a new session.
open_stream(RemoteHostName) ->
    <<"<stream:stream
        to='", (iolist_to_binary(RemoteHostName))/binary, "'
        xmlns='jabber:client'
        xmlns:stream='http://etherx.jabber.org/streams'
        version='1.0'>">>.

%% The client send a STARTTLS to server. 
starttls() ->
    <<"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>">>.

flush_socket(Sock, Timeout) ->
    case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Packet} ->
            io:format("Skip ~p~n", [Packet]),
            flush_socket(Sock, Timeout);
        {error, timeout} ->
            ok
    end.


encode_handshake_record(Ciphers) ->
    HandhsakeFragment = encode_handshake_fragment(Ciphers),
    HandhsakeFragmentLen = byte_size(HandhsakeFragment),
    %% Encode TLSPlaintext record
    <<?CONTENT_TYPE_HANDSHAKE,
      ?PROTOCOL_VERSION_TLS_1_0,
      HandhsakeFragmentLen:16,
      HandhsakeFragment/binary>>.

encode_handshake_fragment(Ciphers) ->
    ClientHello = client_hello(Ciphers),
    Length = byte_size(ClientHello),
    <<?HANDSHAKE_TYPE_CLIENT_HELLO, Length:24, ClientHello/binary>>.

client_hello(Ciphers) ->
    <<?PROTOCOL_VERSION_TLS_1_0,
      (encode_random(unix_timestamp(), crypto:rand_bytes(28)))/binary,
      (encode_empty_session_id())/binary,
      (encode_cipher_suites(Ciphers))/binary,
      (encode_compression_methods())/binary
    >>.

encode_random(Time, Rand)
    when is_integer(Time), is_binary(Rand), byte_size(Rand) =:= 28 ->
    <<Time:32, Rand:28/binary>>.

encode_empty_session_id() ->
    <<0>>.

encode_cipher_suites(Ciphers) when is_binary(Ciphers) ->
    CipherCnt = byte_size(Ciphers),
    <<CipherCnt:16, Ciphers/binary>>.

encode_compression_methods() ->
    %% CompressionMethod.null only
    <<1:8, 0>>.

unix_timestamp() ->
    {Mega, Secs, _} = os:timestamp(),
    Mega * 1000000 + Secs.

cipher_name(<<?TLS_NULL_WITH_NULL_NULL>>) ->
    'TLS_NULL_WITH_NULL_NULL';
cipher_name(<<?TLS_RSA_WITH_NULL_MD5>>) ->
    'TLS_RSA_WITH_NULL_MD5';
cipher_name(<<?TLS_RSA_WITH_NULL_SHA>>) ->
    'TLS_RSA_WITH_NULL_SHA';
cipher_name(<<?TLS_RSA_EXPORT_WITH_RC4_40_MD5>>) ->
    'TLS_RSA_EXPORT_WITH_RC4_40_MD5';
cipher_name(<<?TLS_RSA_WITH_RC4_128_MD5>>) ->
    'TLS_RSA_WITH_RC4_128_MD5';
cipher_name(<<?TLS_RSA_WITH_RC4_128_SHA>>) ->
    'TLS_RSA_WITH_RC4_128_SHA';
cipher_name(<<?TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5>>) ->
    'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5';

cipher_name(<<?TLS_RSA_WITH_IDEA_CBC_SHA>>) ->
    'TLS_RSA_WITH_IDEA_CBC_SHA';
cipher_name(<<?TLS_RSA_EXPORT_WITH_DES40_CBC_SHA>>) ->
    'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA';
cipher_name(<<?TLS_RSA_WITH_DES_CBC_SHA>>) ->
    'TLS_RSA_WITH_DES_CBC_SHA';
cipher_name(<<?TLS_RSA_WITH_3DES_EDE_CBC_SHA>>) ->
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA';

cipher_name(<<?TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA>>) ->
    'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA';
cipher_name(<<?TLS_DH_DSS_WITH_DES_CBC_SHA>>) ->
    'TLS_DH_DSS_WITH_DES_CBC_SHA';
cipher_name(<<?TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA>>) ->
    'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA';
cipher_name(<<?TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA>>) ->
    'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA';
cipher_name(<<?TLS_DH_RSA_WITH_DES_CBC_SHA>>) ->
    'TLS_DH_RSA_WITH_DES_CBC_SHA';
cipher_name(<<?TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA>>) ->
    'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA';
cipher_name(<<?TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA>>) ->
    'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA';
cipher_name(<<?TLS_DHE_DSS_WITH_DES_CBC_SHA>>) ->
    'TLS_DHE_DSS_WITH_DES_CBC_SHA';
cipher_name(<<?TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA>>) ->
    'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA';
cipher_name(<<?TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA>>) ->
    'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA';
cipher_name(<<?TLS_DHE_RSA_WITH_DES_CBC_SHA>>) ->
    'TLS_DHE_RSA_WITH_DES_CBC_SHA';
cipher_name(<<?TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA>>) ->
    'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA';

cipher_name(<<?TLS_DH_anon_EXPORT_WITH_RC4_40_MD5>>) ->
    'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5';
cipher_name(<<?TLS_DH_anon_WITH_RC4_128_MD5>>) ->
    'TLS_DH_anon_WITH_RC4_128_MD5';
cipher_name(<<?TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA>>) ->
    'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA';
cipher_name(<<?TLS_DH_anon_WITH_DES_CBC_SHA>>) ->
    'TLS_DH_anon_WITH_DES_CBC_SHA';
cipher_name(<<?TLS_DH_anon_WITH_3DES_EDE_CBC_SHA>>) ->
    'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA';

cipher_name(<<?TLS_RSA_WITH_AES_128_CBC_SHA>>) ->
    'TLS_RSA_WITH_AES_128_CBC_SHA';
cipher_name(<<?TLS_DH_DSS_WITH_AES_128_CBC_SHA>>) ->
    'TLS_DH_DSS_WITH_AES_128_CBC_SHA';
cipher_name(<<?TLS_DH_RSA_WITH_AES_128_CBC_SHA>>) ->
    'TLS_DH_RSA_WITH_AES_128_CBC_SHA';
cipher_name(<<?TLS_DHE_DSS_WITH_AES_128_CBC_SHA>>) ->
    'TLS_DHE_DSS_WITH_AES_128_CBC_SHA';
cipher_name(<<?TLS_DHE_RSA_WITH_AES_128_CBC_SHA>>) ->
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA';
cipher_name(<<?TLS_DH_anon_WITH_AES_128_CBC_SHA>>) ->
    'TLS_DH_anon_WITH_AES_128_CBC_SHA';

cipher_name(<<?TLS_RSA_WITH_AES_256_CBC_SHA>>) ->
    'TLS_RSA_WITH_AES_256_CBC_SHA';
cipher_name(<<?TLS_DH_DSS_WITH_AES_256_CBC_SHA>>) ->
    'TLS_DH_DSS_WITH_AES_256_CBC_SHA';
cipher_name(<<?TLS_DH_RSA_WITH_AES_256_CBC_SHA>>) ->
    'TLS_DH_RSA_WITH_AES_256_CBC_SHA';
cipher_name(<<?TLS_DHE_DSS_WITH_AES_256_CBC_SHA>>) ->
    'TLS_DHE_DSS_WITH_AES_256_CBC_SHA';
cipher_name(<<?TLS_DHE_RSA_WITH_AES_256_CBC_SHA>>) ->
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA';
cipher_name(<<?TLS_DH_anon_WITH_AES_256_CBC_SHA>>) ->
    'TLS_DH_anon_WITH_AES_256_CBC_SHA';

cipher_name(<<?TLS_RSA_WITH_CAMELLIA_128_CBC_SHA>>) ->
    'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA';
cipher_name(<<?TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA>>) ->
    'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA';
cipher_name(<<?TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA>>) ->
    'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA';
cipher_name(<<?TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA>>) ->
    'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA';
cipher_name(<<?TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA>>) ->
    'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA';
cipher_name(<<?TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA>>) ->
    'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA';

cipher_name(<<?TLS_RSA_WITH_CAMELLIA_256_CBC_SHA>>) ->
    'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA';
cipher_name(<<?TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA>>) ->
    'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA';
cipher_name(<<?TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA>>) ->
    'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA';
cipher_name(<<?TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA>>) ->
    'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA';
cipher_name(<<?TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA>>) ->
    'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA';
cipher_name(<<?TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA>>) ->
    'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA';

cipher_name(<<?TLS_RSA_WITH_SEED_CBC_SHA>>) ->
    'TLS_RSA_WITH_SEED_CBC_SHA';
cipher_name(<<?TLS_DH_DSS_WITH_SEED_CBC_SHA>>) ->
    'TLS_DH_DSS_WITH_SEED_CBC_SHA';
cipher_name(<<?TLS_DH_RSA_WITH_SEED_CBC_SHA>>) ->
    'TLS_DH_RSA_WITH_SEED_CBC_SHA';
cipher_name(<<?TLS_DHE_DSS_WITH_SEED_CBC_SHA>>) ->
    'TLS_DHE_DSS_WITH_SEED_CBC_SHA';
cipher_name(<<?TLS_DHE_RSA_WITH_SEED_CBC_SHA>>) ->
    'TLS_DHE_RSA_WITH_SEED_CBC_SHA';
cipher_name(<<?TLS_DH_anon_WITH_SEED_CBC_SHA>>) ->
    'TLS_DH_anon_WITH_SEED_CBC_SHA'.

ciphers() ->
    <<?TLS_NULL_WITH_NULL_NULL,

      ?TLS_RSA_WITH_NULL_MD5,
      ?TLS_RSA_WITH_NULL_SHA,
      ?TLS_RSA_EXPORT_WITH_RC4_40_MD5,
      ?TLS_RSA_WITH_RC4_128_MD5,
      ?TLS_RSA_WITH_RC4_128_SHA,
      ?TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
      ?TLS_RSA_WITH_IDEA_CBC_SHA,
      ?TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
      ?TLS_RSA_WITH_DES_CBC_SHA,
      ?TLS_RSA_WITH_3DES_EDE_CBC_SHA,

      ?TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
      ?TLS_DH_DSS_WITH_DES_CBC_SHA,
      ?TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
      ?TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
      ?TLS_DH_RSA_WITH_DES_CBC_SHA,
      ?TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
      ?TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
      ?TLS_DHE_DSS_WITH_DES_CBC_SHA,
      ?TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
      ?TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
      ?TLS_DHE_RSA_WITH_DES_CBC_SHA,
      ?TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,

      ?TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
      ?TLS_DH_anon_WITH_RC4_128_MD5,
      ?TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
      ?TLS_DH_anon_WITH_DES_CBC_SHA,
      ?TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,

      ?TLS_RSA_WITH_AES_128_CBC_SHA,
      ?TLS_DH_DSS_WITH_AES_128_CBC_SHA,
      ?TLS_DH_RSA_WITH_AES_128_CBC_SHA,
      ?TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
      ?TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
      ?TLS_DH_anon_WITH_AES_128_CBC_SHA,

      ?TLS_RSA_WITH_AES_256_CBC_SHA,
      ?TLS_DH_DSS_WITH_AES_256_CBC_SHA,
      ?TLS_DH_RSA_WITH_AES_256_CBC_SHA,
      ?TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
      ?TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
      ?TLS_DH_anon_WITH_AES_256_CBC_SHA,

      ?TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
      ?TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
      ?TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
      ?TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
      ?TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
      ?TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,

      ?TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
      ?TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
      ?TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
      ?TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
      ?TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
      ?TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,

      ?TLS_RSA_WITH_SEED_CBC_SHA,
      ?TLS_DH_DSS_WITH_SEED_CBC_SHA,
      ?TLS_DH_RSA_WITH_SEED_CBC_SHA,
      ?TLS_DHE_DSS_WITH_SEED_CBC_SHA,
      ?TLS_DHE_RSA_WITH_SEED_CBC_SHA,
      ?TLS_DH_anon_WITH_SEED_CBC_SHA
      >>.


recv_record(Sock) ->
    case gen_tcp:recv(Sock, 5, 2000) of
    {ok, <<?CONTENT_TYPE_HANDSHAKE,
           _ServerVersion:16, % ?PROTOCOL_VERSION_TLS_1_0,
           HandhsakeFragmentLen:16>>} ->
        gen_tcp:recv(Sock, HandhsakeFragmentLen);
    {ok, PacketHeader} ->
        io:format("Bad packet header ~p~n", [PacketHeader]),
        error(unexpected_packet_header)
    end.

decode_server_hello(<<
      ?HANDSHAKE_TYPE_SERVER_HELLO,
      _Length:24,
      %% ProtocolVersion server_version;
      MajorVersion, MinorVersion,
      %% Random random;
      Time:32, Random:28/binary,
      %% SessionID session_id;
      SessionIdSize, SessionId:SessionIdSize/binary,
      %% CipherSuite cipher_suite;
      CipherSuite:2/binary,
      %% CompressionMethod compression_method;
      _CompressionMethod>>) ->
    #server_hello{
        time = Time,
        random = Random,
        version = {MajorVersion, MinorVersion},
        session_id = SessionId,
        cipher_suite = cipher_name(CipherSuite)
    }.

split_ciphers(Ciphers) ->
    [Cipher || <<Cipher:2/binary>> <= Ciphers].

cipher_list() ->
    split_ciphers(ciphers()).
