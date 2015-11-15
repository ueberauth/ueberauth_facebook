defmodule UeberauthFacebook.Mixfile do
  use Mix.Project

  @version "0.1.0"

  def project do
    [app: :ueberauth_facebook,
     version: @version,
     name: "Überauth Facebook Strategy",
     package: package,
     elixir: "~> 1.1",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     source_url: "https://github.com/doomspork/ueberauth_facebook",
     homepage_url: "https://github.com/doomspork/ueberauth_facebook",
     description: description,
     deps: deps,
     docs: docs]
  end

  def application do
    [applications: [:logger]]
  end

  defp deps do
    [
     {:ueberauth, "~> 0.1"},
     {:oauth2, "~> 0.5"},
     {:ex_doc, "~> 0.1", only: :dev}
    ]
  end

  defp docs do
    [extras: docs_extras, main: "extra-readme"]
  end

  defp docs_extras do
    ["README.md"]
  end

  defp description do
    "An Überauth strategy Facebook authentication."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Sean Callan"],
      licenses: ["MIT"],
      links: %{"GitHub": "https://github.com/doomspork/ueberauth_facebook"}
    ]
  end
end