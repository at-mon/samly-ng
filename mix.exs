defmodule Samly.Mixfile do
  use Mix.Project

  @version "2.0.1"
  @description "SAML Single-Sign-On Authentication for Plug/Phoenix Applications"
  @source_url "https://github.com/at-mon/samly-ng"

  def project do
    [
      app: :samly,
      version: @version,
      description: @description,
      docs: docs(),
      package: package(),
      elixir: "~> 1.20.0",
      elixirc_options: [warnings_as_errors: true],
      start_permanent: Mix.env() == :prod,
      test_ignore_filters: [&String.starts_with?(&1, "test/support/")],
      aliases: ["security.check": ["deps.audit", "hex.audit", "sobelow --config"]],
      deps: deps()
    ]
  end

  def cli do
    [preferred_envs: ["test.json": :test, "dialyzer.json": :dev]]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {Samly.Application, []},
      extra_applications: [:logger, :eex, :crypto, :public_key]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.20"},
      {:saxy, "~> 1.6"},
      {:bandit, "~> 1.14", only: :test},
      {:stream_data, "~> 1.4", only: :test},
      {:ex_unit_json, "~> 0.4", only: [:dev, :test], runtime: false},
      {:dialyzer_json, "~> 0.1", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:sobelow, "~> 0.16", only: [:dev, :test], runtime: false},
      {:styler, "~> 1.12", only: [:dev, :test], runtime: false},
      {:ex_quality, "~> 0.16", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false}
    ]
  end

  defp docs do
    [
      extras: ["README.md", "docs/phoenix_setup.md", "docs/microsoft_entra_id.md", "docs/configuration.md", "docs/MIGRATION.md", "docs/SECURITY_REVIEW.md"],
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp package do
    [
      maintainers: ["dropbox", "KMC"],
      files: ["config", "lib", "docs", "LICENSE", "mix.exs", "README.md"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end
end
