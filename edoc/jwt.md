

# Module jwt #
* [Description](#description)
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

JWT Library for Erlang.

<a name="description"></a>

## Description ##

Written by Peter Hizalev at Kato (http://kato.im)

Rewritten by Yuri Artemev (http://artemff.com)

<a name="types"></a>

## Data Types ##




### <a name="type-expiration">expiration()</a> ###


<pre><code>
expiration() = {hourly, non_neg_integer()} | {daily, non_neg_integer()} | non_neg_integer()
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#decode-2">decode/2</a></td><td>Decodes a token, checks the signature and returns the content of the token.</td></tr><tr><td valign="top"><a href="#decode-3">decode/3</a></td><td>Decode with an issuer key mapping.</td></tr><tr><td valign="top"><a href="#encode-3">encode/3</a></td><td>Creates a token from given data and signs it with a given secret.</td></tr><tr><td valign="top"><a href="#encode-4">encode/4</a></td><td>Creates a token from given data and signs it with a given secret.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="decode-2"></a>

### decode/2 ###

<pre><code>
decode(Token::binary(), Key::binary() | <a href="public_key.md#type-public_key">public_key:public_key()</a> | <a href="public_key.md#type-private_key">public_key:private_key()</a>) -&gt; {ok, Claims::map()} | {error, any()}
</code></pre>
<br />

Decodes a token, checks the signature and returns the content of the token

* `Token` is a JWT itself

* `Key` is a secret phrase or public/private key depend on encryption algorithm



<a name="decode-3"></a>

### decode/3 ###

<pre><code>
decode(Token::binary(), DefaultKey::binary() | <a href="public_key.md#type-public_key">public_key:public_key()</a> | <a href="public_key.md#type-private_key">public_key:private_key()</a>, IssuerKeyMapping::map()) -&gt; {ok, Claims::map()} | {error, any()}
</code></pre>
<br />

Decode with an issuer key mapping

Receives the issuer key mapping as the last parameter

<a name="encode-3"></a>

### encode/3 ###

<pre><code>
encode(Alg::binary(), ClaimsSet::map() | list(), Key::binary() | <a href="public_key.md#type-private_key">public_key:private_key()</a>) -&gt; {ok, Token::binary()} | {error, any()}
</code></pre>
<br />

Creates a token from given data and signs it with a given secret

Parameters are

*

`Alg` is a binary one of

[HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512]

But only [HS256, HS384, HS512, RS256] are supported

* `ClaimsSet` the payload of the token. Can be both map and proplist

* `Key` binary in case of hmac encryption and private key if rsa



<a name="encode-4"></a>

### encode/4 ###

<pre><code>
encode(Alg::binary(), ClaimsSet::map() | list(), Expiration::<a href="#type-expiration">expiration()</a>, Key::binary() | <a href="public_key.md#type-private_key">public_key:private_key()</a>) -&gt; {ok, Token::binary()} | {error, any()}
</code></pre>
<br />

Creates a token from given data and signs it with a given secret

and also adds `exp` claim to payload

`Expiration` can be one of the tuples:
`{hourly, SecondsAfterBeginningOfCurrentHour}`,
`{daily, SecondsAfterBeginningOfCurrentDay}`
or can be just an integer representing the amount of seconds
the token will live

