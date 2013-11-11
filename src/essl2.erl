-module(essl2).
-export([test/0]).

-record(server_hello, {
    cert,
    ciphers,
    connection_id
}).

-define(SSL_MT_CLIENT_HELLO, 1).
-define(SSL_CLIENT_VERSION_2, 0, 2).
-define(SSL_CK_RC4_128_WITH_MD5,
    16#01, 16#00, 16#80).
-define(SSL_CK_RC4_128_EXPORT40_WITH_MD5,
    16#02, 16#00, 16#80).
-define(SSL_CK_RC2_128_CBC_WITH_MD5,
    16#03, 16#00, 16#80).
-define(SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
    16#04, 16#00, 16#80).
-define(SSL_CK_IDEA_128_CBC_WITH_MD5,
    16#05, 16#00, 16#80).
-define(SSL_CK_DES_64_CBC_WITH_MD5,
    16#06, 16#00, 16#40).
-define(SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
    16#07, 16#00, 16#C0).

test() ->
%   RemoteHostName = "localhost",
    RemoteHostName = "jwchat.org",
    TcpOpts = [binary, {packet, 0}, {active, false}],
    Ciphers = <<?SSL_CK_RC4_128_WITH_MD5,
                ?SSL_CK_RC4_128_EXPORT40_WITH_MD5,
                ?SSL_CK_RC2_128_CBC_WITH_MD5,
                ?SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
                ?SSL_CK_IDEA_128_CBC_WITH_MD5,
                ?SSL_CK_DES_64_CBC_WITH_MD5,
                ?SSL_CK_DES_192_EDE3_CBC_WITH_MD5>>,
    Challenge = <<0:128>>,
    {ok, Sock} = gen_tcp:connect(RemoteHostName, 5222, TcpOpts),
    ok = gen_tcp:send(Sock, open_stream(RemoteHostName)),
    ok = gen_tcp:send(Sock, starttls()),
    flush_socket(Sock),
    ClientHello = client_hello(Ciphers, Challenge),
    io:format("ClientHello is ~p.~n", [ClientHello]),
    ok = gen_tcp:send(Sock, ClientHello),
    {ok, ServerHello} = recv_record(Sock),
    ServerHelloRec = decode_server_hello(ServerHello),
    io:format(user, "ServerHelloRec ~p~n", [ServerHelloRec]),
%   flush_socket(Sock),
    ok = gen_tcp:close(Sock).

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

flush_socket(Sock) ->
    case gen_tcp:recv(Sock, 0, 500) of
        {ok, Packet} ->
            io:format("Skip ~p~n", [Packet]),
            flush_socket(Sock);
        {error, timeout} ->
            ok
    end.

client_hello(Ciphers, Challenge) ->
    CiphersSize   = byte_size(Ciphers),
    ChallengeSize = byte_size(Challenge),
    RecordLength  = 9 + CiphersSize + ChallengeSize,
%% Record header
%% no padding, 2 byte length code
<<1:1, RecordLength:15,
%% Record data
%%  MAC-DATA and PADDING-DATA are empty.
%%  ACTUAL-DATA
%%   CLIENT-HELLO
%%    char MSG-CLIENT-HELLO
        ?SSL_MT_CLIENT_HELLO, 
%%    char CLIENT-VERSION-MSB
%%    char CLIENT-VERSION-LSB
        ?SSL_CLIENT_VERSION_2,
%%    char CIPHER-SPECS-LENGTH-MSB
%%    char CIPHER-SPECS-LENGTH-LSB
%%     in bytes
        CiphersSize:16,
%%    char SESSION-ID-LENGTH-MSB
%%    char SESSION-ID-LENGTH-LSB
        0:16,
%%    char CHALLENGE-LENGTH-MSB
%%    char CHALLENGE-LENGTH-LSB
%%     16-32
        ChallengeSize:16,
%%    char CIPHER-SPECS-DATA[(MSB<<8)|LSB]
        Ciphers/binary,
%%    char SESSION-ID-DATA[(MSB<<8)|LSB]
%%     empty
%%    char CHALLENGE-DATA[(MSB<<8)|LSB]
        Challenge/binary>>.

recv_record(Sock) ->
    case gen_tcp:recv(Sock, 2) of
        %% 2 byte header
        {ok, <<1:1, L:15>>} ->
            gen_tcp:recv(Sock, L);
        %% 3 byte header
        {ok, <<0:1, _:1, L:14>>} ->
            io:format("Record size is ~p.~n", [L]),
            %% Padding is zero
            {ok, <<0, Data/binary>>} = gen_tcp:recv(Sock, L+1, 5000),
            {ok, Data}
    end.

decode_server_hello(
%% char MSG-SERVER-HELLO
    <<4,
%% char SESSION-ID-HIT
      _,
%% char CERTIFICATE-TYPE
      _,
%% char SERVER-VERSION-MSB
      _,
%% char SERVER-VERSION-LSB
      _,
%% char CERTIFICATE-LENGTH-MSB
%% char CERTIFICATE-LENGTH-LSB
      CertSize:16,
%% char CIPHER-SPECS-LENGTH-MSB
%% char CIPHER-SPECS-LENGTH-LSB
      CiphersSize:16,
%% char CONNECTION-ID-LENGTH-MSB
%% char CONNECTION-ID-LENGTH-LSB
      ConnectionIdSize:16,
%% char CERTIFICATE-DATA[MSB<<8|LSB]
      Cert:CertSize/binary,
%% char CIPHER-SPECS-DATA[MSB<<8|LSB]
      Ciphers:CiphersSize/binary,
%% char CONNECTION-ID-DATA[MSB<<8|LSB]
      ConnectionId:ConnectionIdSize/binary>>) ->
    #server_hello{
        cert = Cert,
        ciphers = decode_ciphers(Ciphers),
        connection_id = ConnectionId}.

decode_ciphers(Ciphers) ->
    [cipher_name(Cipher) || <<Cipher:3/binary>> <= Ciphers].
    
%% {encryption, exchange, hash}
cipher_name(<<?SSL_CK_RC4_128_WITH_MD5>>) ->
    %% Encryption is RSA, Exchange is RC4, Hash is 128
    'SSL_CK_RC4_128_WITH_MD5';
cipher_name(<<?SSL_CK_RC4_128_EXPORT40_WITH_MD5>>) ->
    'SSL_CK_RC4_128_EXPORT40_WITH_MD5';
cipher_name(<<?SSL_CK_RC2_128_CBC_WITH_MD5>>) ->
    'SSL_CK_RC2_128_CBC_WITH_MD5';
cipher_name(<<?SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5>>) ->
    'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5';
cipher_name(<<?SSL_CK_IDEA_128_CBC_WITH_MD5>>) ->
    'SSL_CK_IDEA_128_CBC_WITH_MD5';
cipher_name(<<?SSL_CK_DES_64_CBC_WITH_MD5>>) ->
    'SSL_CK_DES_64_CBC_WITH_MD5';
cipher_name(<<?SSL_CK_DES_192_EDE3_CBC_WITH_MD5>>) ->
    %% Exchange is 3DES
    'SSL_CK_DES_192_EDE3_CBC_WITH_MD5'.

