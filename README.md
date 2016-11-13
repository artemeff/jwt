### jwt &mdash; Erlang JWT Library

---

[![Hex.pm](https://img.shields.io/hexpm/v/jwt.svg)](https://hex.pm/packages/jwt)

---

JWT is a simple authorization token [format](http://jwt.io/) based on JSON.

#### Installation

If you use rebar (supports both 2 and 3 versions) or mix (Elixir):

```erlang
% in rebar.config for rebar3
{deps, [{jwt}]}.

% or for rebar2
{deps, [{jwt, ".*", {git, "https://github.com/artemeff/jwt", {tag, "0.1.0"}}}]}
```

```elixir
% mix.exs
def deps do
  [{:jwt, "~> 0.1"}]
end
```

Or use it as git dependency.

#### Usage example

```erlang
%% Create JWT token
> application:ensure_all_started(jwt).
> Key = <<"supas3cri7">>.
> Claims = [
    {user_id, 42},
    {user_name, <<"Bob">>}
  ].
> {ok, Token} = jwt:encode(<<"HS256">>, Claims, Key).
%% or with expiration
> ExpirationSeconds = 86400.
> {ok, Token} = jwt:encode(<<"HS256">>, Claims, ExpirationSeconds, Key).

%% Parse JWT token
> {ok, Claims} = jwt:decode(Token, Key).



%% Issuer specific keys workflow

%% The encoder just knows about itself
> Issuer = <<"iss1">>.
> IssuerKey = <<"Issuer-1-Key">>.
> Claims2 = [
    {iss, Issuer},
    {user_id, 42},
    {user_name, <<"Bob">>}
  ].
> {ok, Token2} = jwt:encode(<<"HS256">>, Claims, ExpirationSeconds, IssuerKey).

%% Decoder Workflow
%% The decoder knows about all encoder keys (issuer specific)
> IssuerKeyMapping = #{ Issuer => IssuerKey,
                        <<"iss2">> => <<"Issuer2Key">>}.
> {ok, Claims} = jwt:decode(Token, <<"default-key">>, IssuerKeyMapping).
```

---

### Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
