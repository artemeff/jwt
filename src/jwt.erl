%% @doc JWT Library for Erlang.
%%
%% Written by Peter Hizalev at Kato (http://kato.im)
%%
%% Rewritten by Yuri Artemev (http://artemff.com)
%%
%% @end
-module(jwt).

-export([decode/2, decode/3]).
-export([encode/3, encode/4]).

-define(HOUR, 3600).
-define(DAY, (?HOUR * 24)).

-type expiration() :: {hourly, non_neg_integer()} | {daily, non_neg_integer()} | non_neg_integer().
-type context() :: map().

%%
%% API
%%
-spec encode(
    Alg :: binary(),
    ClaimsSet :: map() | list(),
    Key :: binary() | public_key:private_key()
) -> {ok, Token :: binary()} | {error, any()}.
%% @doc Creates a token from given data and signs it with a given secret
%%
%% Parameters are
%% <ul>
%%   <li>
%%      `Alg' is a binary one of
%%
%%      [HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512]
%%
%%      But only [HS256, HS384, HS512, RS256] are supported
%%  </li>
%%  <li>`ClaimsSet' the payload of the token. Can be both map and proplist</li>
%%  <li>`Key' binary in case of hmac encryption and private key if rsa</li>
%% </ul>
%%
%% @end
encode(Alg, ClaimsSet, Key) ->
    Claims = base64url:encode(jsx:encode(ClaimsSet)),
    Header = base64url:encode(jsx:encode(jwt_header(Alg))),
    Payload = <<Header/binary, ".", Claims/binary>>,
    case jwt_sign(Alg, Payload, Key) of
        undefined -> {error, algorithm_not_supported};
        Signature -> {ok, <<Payload/binary, ".", Signature/binary>>}
    end.

-spec encode(
    Alg :: binary(),
    ClaimsSet :: map() | list(),
    Expiration :: expiration(),
    Key :: binary() | public_key:private_key()
) -> {ok, Token :: binary()} | {error, any()}.
%% @doc Creates a token from given data and signs it with a given secret
%%
%% and also adds `exp' claim to payload
%%
%% `Expiration' can be one of the tuples:
%%    `{hourly, SecondsAfterBeginningOfCurrentHour}',
%%    `{daily, SecondsAfterBeginningOfCurrentDay}'
%% or can be just an integer representing the amount of seconds
%% the token will live
%%
%% @end
encode(Alg, ClaimsSet, Expiration, Key) ->
    Claims = jwt_add_exp(ClaimsSet, Expiration),
    encode(Alg, Claims, Key).

-spec decode(
    Token :: binary(),
    Key :: binary() | public_key:public_key() | public_key:private_key()
) -> {ok, Claims :: map()} | {error, any()}.
%% @doc Decodes a token, checks the signature and returns the content of the token
%%
%% <ul>
%%   <li>`Token' is a JWT itself</li>
%%   <li>`Key' is a secret phrase or public/private key depend on encryption algorithm</li>
%% </ul>
%%
%% @end
decode(Token, Key) ->
    decode(Token, Key, #{}).

% When there are multiple issuers and keys are on a per issuer bases
% then apply those keys instead
-spec decode(
    Token :: binary(),
    DefaultKey :: binary() | public_key:public_key() | public_key:private_key(),
    IssuerKeyMapping :: map()
) -> {ok, Claims :: map()} | {error, any()}.
%% @doc Decode with an issuer key mapping
%%
%% Receives the issuer key mapping as the last parameter
%%
%% @end
decode(Token, DefaultKey, IssuerKeyMapping) ->
    result(run(#{token => Token}, [
        fun split_token/1,
        fun decode_jwt/1,
        fun (Context) ->
            get_key(Context, DefaultKey, IssuerKeyMapping)
        end,
        fun check_signature/1,
        fun check_expired/1
    ])).

result(#{claims_json := ClaimsJSON}) ->
    {ok, ClaimsJSON};
result({error, _} = Error) ->
    Error.

run(Acc, []) ->
    Acc;
run(Acc, [F|Funs]) ->
    case F(Acc) of
        {true, NewAcc} ->
            run(NewAcc, Funs);
        {false, Result} ->
            Result
    end.

-spec split_token(Context :: context()) ->
    {true, context()} | {false, {error, invalid_token}}.
%% @private
split_token(#{token := Token} = Context) ->
    case binary:split(Token, <<".">>, [global]) of
        [Header, Claims, Signature] ->
            {true, maps:merge(Context, #{
                header => Header,
                claims => Claims,
                signature => Signature
            })};
        _ ->
            {false, {error, invalid_token}}
    end.

-spec decode_jwt(context()) -> {true, context()} | {false, {error, invalid_token}}.
%% @private
decode_jwt(#{header := Header, claims := Claims} = Context) ->
    try
        [HeaderJSON, ClaimsJSON] =
            Decoded = [jsx_decode_safe(base64url:decode(X)) || X <- [Header, Claims]],
        case lists:any(fun(E) -> E =:= invalid end, Decoded) of
            false ->
                {true, maps:merge(Context, #{
                    header_json => HeaderJSON,
                    claims_json => ClaimsJSON
                })};
            true  ->
                {false, {error, invalid_token}}
        end
    catch _:_ ->
        {false, {error, invalid_token}}
    end.

%% @private
get_key(#{claims_json := Claims} = Context, DefaultKey, IssuerKeyMapping) ->
    Issuer = maps:get(<<"iss">>, Claims, undefined),
    Key = maps:get(Issuer, IssuerKeyMapping, DefaultKey),
    {true, maps:merge(Context, #{key => Key})}.

%% @private
check_signature(#{
    key         := Key,
    header      := Header,
    claims      := Claims,
    signature   := Signature,
    header_json := #{<<"alg">> := Alg}
} = Context) ->
    case jwt_check_sig(Alg, Header, Claims, Signature, Key) of
        true ->
            {true, Context};
        false ->
            {false, {error, invalid_signature}}
    end.

%% @private
check_expired(#{claims_json := ClaimsJSON} = Context) ->
    case jwt_is_expired(ClaimsJSON) of
        true  ->
            {false, {error, expired}};
        false ->
            {true, Context}
    end.

%%
%% Decoding helpers
%%
-spec jsx_decode_safe(binary()) -> map() | invalid.
%% @private
jsx_decode_safe(Bin) ->
    try
        jsx:decode(Bin, [return_maps])
    catch _ ->
        invalid
    end.

-spec jwt_is_expired(map()) -> boolean().
%% @private
jwt_is_expired(#{<<"exp">> := Exp} = _ClaimsJSON) ->
    case (Exp - epoch()) of
        DeltaSecs when DeltaSecs > 0 -> false;
        _ -> true
    end;
jwt_is_expired(_) ->
    false.

-spec jwt_check_sig(
    Alg :: binary(),
    Header :: binary(),
    Claims :: binary(),
    Signature :: binary(),
    Key :: binary() | public_key:public_key() | public_key:private_key()
) -> boolean().
%% @private
jwt_check_sig(Alg, Header, Claims, Signature, Key) ->
    jwt_check_sig(algorithm_to_crypto(Alg), <<Header/binary, ".", Claims/binary>>, Signature, Key).

-spec jwt_check_sig(
    {atom(), atom()},
    Payload :: binary(),
    Signature :: binary(),
    Key :: binary() | public_key:public_key() | public_key:private_key()
) -> boolean().
%% @private
jwt_check_sig({hmac, _} = Alg, Payload, Signature, Key) ->
    jwt_sign_with_crypto(Alg, Payload, Key) =:= Signature;

jwt_check_sig({Algo, Crypto}, Payload, Signature, Pem)
    when (Algo =:= rsa orelse Algo =:= ecdsa) andalso is_binary(Pem) ->
    jwt_check_sig({Algo, Crypto}, Payload, Signature, pem_to_key(Pem));

jwt_check_sig({rsa, Crypto}, Payload, Signature, Key) ->
    public_key:verify(Payload, Crypto, base64url:decode(Signature), Key);

jwt_check_sig({ecdsa, Crypto}, Payload, Signature, Key) ->
    public_key:verify(Payload, Crypto, jwt_ecdsa:signature(Signature), Key);

jwt_check_sig(_, _, _, _) ->
    false.

%%
%% Encoding helpers
%%
-spec jwt_add_exp(ClaimsSet :: map() | list(), Expiration :: expiration()) -> map() | list().
%% @private
jwt_add_exp(ClaimsSet, Expiration) ->
    Exp = expiration_to_epoch(Expiration),
    append_claim(ClaimsSet, <<"exp">>, Exp).

-spec jwt_header(Alg :: binary()) -> list().
jwt_header(Alg) ->
    [ {<<"alg">>, Alg}
    , {<<"typ">>, <<"JWT">>}
    ].

%%
%% Helpers
%%
-spec jwt_sign(
    Alg :: binary(),
    Payload :: binary(),
    Key :: binary() | public_key:private_key()
) -> binary() | undefined.
%% @private
jwt_sign(Alg, Payload, Key) ->
    jwt_sign_with_crypto(algorithm_to_crypto(Alg), Payload, Key).

jwt_sign_with_crypto({hmac, Crypto}, Payload, Key) ->
    base64url:encode(crypto:hmac(Crypto, Key, Payload));

jwt_sign_with_crypto({Algo, Crypto}, Payload, Pem)
    when (Algo =:= rsa orelse Algo =:= ecdsa) andalso is_binary(Pem) ->
    jwt_sign_with_crypto({Algo, Crypto}, Payload, pem_to_key(Pem));

jwt_sign_with_crypto({rsa, Crypto}, Payload, Key) ->
    base64url:encode(public_key:sign(Payload, Crypto, Key));

jwt_sign_with_crypto({ecdsa, Crypto}, Payload, Key) ->
    base64url:encode(jwt_ecdsa:signature(Payload, Crypto, Key));

jwt_sign_with_crypto(_, _Payload, _Key) ->
    undefined.

-spec algorithm_to_crypto(binary()) -> {atom(), atom()} | undefined.
%% @private
algorithm_to_crypto(<<"HS256">>) -> {hmac, sha256};
algorithm_to_crypto(<<"HS384">>) -> {hmac, sha384};
algorithm_to_crypto(<<"HS512">>) -> {hmac, sha512};
algorithm_to_crypto(<<"RS256">>) -> {rsa,  sha256};
algorithm_to_crypto(<<"ES256">>) -> {ecdsa, sha256};
algorithm_to_crypto(_)           -> undefined.

-spec epoch() -> non_neg_integer().
%% @private
epoch() -> erlang:system_time(seconds).

-spec expiration_to_epoch(Expiration :: expiration()) -> neg_integer().
%% @private
expiration_to_epoch(Expiration) ->
    expiration_to_epoch(Expiration, epoch()).

expiration_to_epoch(Expiration, Ts) ->
    case Expiration of
        {hourly, Expiration0} -> (Ts - (Ts rem ?HOUR)) + Expiration0;
        {daily, Expiration0} -> (Ts - (Ts rem ?DAY)) + Expiration0;
        _ -> epoch() + Expiration
    end.

-spec append_claim(ClaimsSet :: map() | list(), binary(), any()) -> map() | list().
%% @private
append_claim(ClaimsSet, Key, Val) when is_map(ClaimsSet) ->
  ClaimsSet#{ Key => Val };
append_claim(ClaimsSet, Key, Val) -> [{ Key, Val } | ClaimsSet].

pem_to_key(Pem) ->
    Decoded = case public_key:pem_decode(Pem) of
        [_, Key] ->
            Key;
        [Key] ->
            Key
    end,
    public_key:pem_entry_decode(Decoded).
