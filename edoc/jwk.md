

# Module jwk #
* [Description](#description)
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

RFC 7517: JSON Web Key (JWK).

<a name="types"></a>

## Data Types ##




### <a name="type-id">id()</a> ###


<pre><code>
id() = binary()
</code></pre>




### <a name="type-json">json()</a> ###


<pre><code>
json() = binary()
</code></pre>




### <a name="type-pem">pem()</a> ###


<pre><code>
pem() = binary()
</code></pre>




### <a name="type-public_key">public_key()</a> ###


<pre><code>
public_key() = #RSAPublicKey{} | <a href="#type-pem">pem()</a>
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#decode-2">decode/2</a></td><td>decode JWK to Erlang/OTP Key.</td></tr><tr><td valign="top"><a href="#encode-2">encode/2</a></td><td>encode Erlang/OTP Key to JWK.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="decode-2"></a>

### decode/2 ###

<pre><code>
decode(Id::<a href="#type-id">id()</a>, Json::<a href="#type-json">json()</a>) -&gt; {ok, <a href="#type-public_key">public_key()</a>} | {error, term()}
</code></pre>
<br />

decode JWK to Erlang/OTP Key

<a name="encode-2"></a>

### encode/2 ###

<pre><code>
encode(Id::<a href="#type-id">id()</a>, PEM::<a href="#type-public_key">public_key()</a>) -&gt; {ok, <a href="#type-json">json()</a>} | {error, term()}
</code></pre>
<br />

encode Erlang/OTP Key to JWK

