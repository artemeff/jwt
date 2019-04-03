-module(jwt_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(SECRET, <<"supas3cri7">>).

encoding_test() ->
    Claims = [{user_id, 42}, {user_name, <<"John Doe">>}],
    {ok, Token} = jwt:encode(<<"HS256">>, Claims, ?SECRET),

    ExpHeader = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    ExpPayload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBEb2UifQ">>,
    ExpSignature = <<"cDMB--ajYo0DWsX14wTkWmM385X9OAOPgIPSsJzKZ8E">>,

    ?assertEqual(makeToken(ExpHeader, ExpPayload, ExpSignature), Token).

encoding_with_exp_test() ->
    ExpirationSeconds = 86400,
    Result = jwt:encode(<<"HS256">>, [], ExpirationSeconds, ?SECRET),

    ?assertMatch({ok, _Token}, Result).

encoding_map_claimset_with_exp_test() ->
    ExpirationSeconds = 86400,
    Result = jwt:encode(<<"HS256">>, #{}, ExpirationSeconds, ?SECRET),

    ?assertMatch({ok, _Token}, Result).

encoding_with_undefined_algorithm_test() ->
    Error = jwt:encode(<<"HS128">>, [], ?SECRET),

    ?assertEqual({error, algorithm_not_supported}, Error).

encoding_with_all_algorithms_test_() ->
    [?_assertMatch({ok, _Token}, jwt:encode(<<"HS256">>, [], ?SECRET)),
    ?_assertMatch({ok, _Token}, jwt:encode(<<"HS384">>, [], ?SECRET)),
    ?_assertMatch({ok, _Token}, jwt:encode(<<"HS512">>, [], ?SECRET))].

decoding_simple_test() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({ok, #{ <<"user_id">> := 42
                       , <<"user_name">> := <<"John Snow">>
                       }}, Claims).

%%
%% "typ" (Type) Header Parameter is OPTIONAL
%% see https://tools.ietf.org/html/rfc7519#section-5.1
decoding_without_type_test() ->
    TokenWithoutTypHeder = <<
        "eyJhbGciOiJIUzI1NiJ9.",
        "eyJ1c2VyX2lkIjo0NCwidXNlcl9uYW1lIjoiSmFpbWUgTGFubmlzdGVyIn0.",
        "4OJ-MO3VMWaQ6zUVlDL_jq5hnRu-_nfPZvUuS32b3VE"
    >>,

    Claims = jwt:decode(TokenWithoutTypHeder, ?SECRET),

    ?assertMatch({ok, #{ <<"user_id">> := 44
                       , <<"user_name">> := <<"Jaime Lannister">>
                       }}, Claims).

decoding_header_error_test() ->
    Header = <<"...">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

decoding_payload_error_test() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"...">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

decoding_signature_error_test() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFa">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_signature}, Claims).

decoding_very_bad_token_test() ->
    Claims = jwt:decode(<<"very_bad">>, ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

%%
%% both encoding / decoding with none MUST not be supported
%% due to change the signature attack
encoding_with_none_test() ->
    Claims = #{sub => 1234567890, name => <<"John Doe">>, admin => true},
    Result = jwt:encode(<<"none">>, Claims, ?SECRET),

    ?assertMatch({error, algorithm_not_supported}, Result).


decoding_with_none_test() ->
    Header = <<"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0">>,
    Payload = <<"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9">>,
    Signature = <<"2XijNOVI9LXP9nWf-oj2SEWWNlcwmxzlQNGK1WdaWcQ">>,

    Result = jwt:decode(makeToken(Header, Payload, Signature), rsa_public()),

    ?assertMatch({error, invalid_signature}, Result).


%%
%%
encoding_with_rs256_test() ->
    Claims = #{sub => 1234567890, name => <<"John Doe">>, admin => true},
    {ok, Token} = jwt:encode(<<"RS256">>, Claims, rsa_secret()),

    ExpHeader = <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>,
    ExpPayload = <<"eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoxMjM0NTY3ODkwfQ">>,
    ExpSignature = <<"W4utVJa53XlPrfyd34NsTY16ONtUp0SG840enCKErSbMw5HPRW-4dO1OOAwSlNZy0L__5kH3733D7ooxEd_wLDRSNRhtq3CiVx6j5vOCW84xLL9U7ytQPubSruirt1L1eVnnxKmzMLM0d2wnog6wTeaNYUDsiLXUt2DRpT6XlWQ">>,

    ?assertEqual(makeToken(ExpHeader, ExpPayload, ExpSignature), Token).

decoding_with_rs256_test() ->
    Header = <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9">>,
    Signature = <<"EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), rsa_public()),

    ?assertMatch({ok, #{<<"sub">>   := <<"1234567890">>,
                        <<"name">>  := <<"John Doe">>,
                        <<"admin">> := true}}, Claims).

decoding_with_rs256_invalid_signature_test() ->
    Header = <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9">>,
    Signature = <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), rsa_public()),

    ?assertMatch({error, invalid_signature}, Claims).


encoding_with_ecdsa_test() ->
    Claims = #{
      <<"admin">> => true,
      <<"name">> => <<"Daenerys Targaryen">>
    },
    Key = ecdsa_private_key(),
    {ok, Token} = jwt:encode(<<"ES256">>, Claims, Key),
    ?assertMatch({ok, #{
        <<"admin">> := true,
        <<"name">> := <<"Daenerys Targaryen">>
    }}, jwt:decode(Token, Key)).

decoding_ecdsa_with_public_key_test() ->
    Header = <<"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvcmFoIE1vcm1vbnQifQ">>,
    Signature = <<
        "8jNpfVUBZd7Xhe9kFq5w6J86yWhow9C6ojrUv966KV2",
        "Z0xNAvru-yL97lXV-8AthqJrWqcjSxBZ7VNULM9NDEg"
    >>,
    Token = makeToken(Header, Payload, Signature),
    ?assertMatch({ok, #{
        <<"admin">> := true,
        <<"name">> := <<"Jorah Mormont">>
    }}, jwt:decode(Token, ecdsa_public_key())).

decoding_ecdsa_invalid_signature_test() ->
    Header = <<"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJuYW1lIjoiSm9yYWggTW9ybW9udCIsImFkbWluIjp0cnVlfQ">>,
    Signature = <<
        "BfI7j9Dv8KAMj0_u4-y9z7aW6-GMiujp8DlzW7P8Z5P",
        "SZrK2G3hRqBNYhgBpcd-RUm8qIb_kXIBWdgzf2mtCQQ"
    >>,
    ?assertMatch({error, invalid_signature},
        jwt:decode(makeToken(Header, Payload, Signature), ecdsa_public_key())).

expiration_to_epoch_when_daily_given_test() ->
    Now            = 1548616000,
    BeginningOfDay = 1548547200,
    ?assertEqual(BeginningOfDay, jwt:expiration_to_epoch({daily, 0}, Now)).

expired_token_test_() ->
    {ok, ExpiredToken} = jwt:encode(<<"HS256">>, #{}, -1, ?SECRET),
    {ok, UnexpiredToken} = jwt:encode(<<"HS256">>, #{}, 60, ?SECRET),
    [?_assertEqual({error, expired}, jwt:decode(ExpiredToken, ?SECRET)),
    ?_assertMatch({ok, #{<<"exp">> := _Exp }}, jwt:decode(UnexpiredToken, ?SECRET))].

pem_to_key_test() ->
    Pem = ecdsa_private_with_params(),
    Key = jwt:pem_to_key(Pem),
    ?assert(is_record(Key, 'ECPrivateKey')).

%%
%% Helpers
%%

makeToken(Header, Payload, Sign) ->
    <<Header/binary, ".", Payload/binary, ".", Sign/binary>>.

rsa_public() ->
    from_pem_file("./test/pem/rsa_public.pem").

rsa_secret() ->
    from_pem_file("./test/pem/rsa_private.pem").

ecdsa_private_key() ->
    from_pem_file("./test/pem/ecdsa_private.pem").

ecdsa_private_with_params() ->
    from_pem_file("./test/pem/ecdsa_private_with_params.pem").

ecdsa_public_key() ->
    from_pem_file("./test/pem/ecdsa_public.pem").

from_pem_file(FileName) ->
    {ok, Bin} = file:read_file(FileName),
    Bin.
