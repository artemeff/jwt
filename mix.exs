defmodule JwtDoc.MixProject do
  use Mix.Project

  def project do
    [
      app: :jwt_doc,
      version: "0.1.8",
      elixir: "~> 1.7",
      deps: deps(),
      compilers: [:app],

      # Docs
      name: "JWT",
      source_url: "https://github.com/artemeff/jwt",
      homepage_url: "https://github.com/artemeff/jwt",
      docs: [
        # logo: "path/to/logo.png",
        main: "readme",
        extras: ["README.md"],
        output: "docs",
        source_beam: ["_build/eep48/lib/jwt/ebin"],
        filter_prefix: false
      ]
    ]
  end

  defp deps do
    [
      {:jwt, path: "_build/eep48/lib/jwt", only: :dev, compile: false, runtime: false},
      {:ex_doc, github: "tank-bohr/ex_doc", branch: :master, only: :dev, runtime: false}
    ]
  end
end
