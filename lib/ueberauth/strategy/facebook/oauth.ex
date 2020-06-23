defmodule Ueberauth.Strategy.Facebook.OAuth do
  @moduledoc """
  OAuth2 for Facebook.

  Add `client_id` and `client_secret` to your configuration:

  config :ueberauth, Ueberauth.Strategy.Facebook.OAuth,
    client_id: System.get_env("FACEBOOK_APP_ID"),
    client_secret: System.get_env("FACEBOOK_APP_SECRET")
  """
  use OAuth2.Strategy

  require Logger

  @defaults [
    strategy: __MODULE__,
    site: "https://graph.facebook.com",
    authorize_url: "https://www.facebook.com/dialog/oauth",
    token_url: "/v2.8/oauth/access_token",
    token_method: :get
  ]

  @doc """
  Construct a client for requests to Facebook.

  This will be setup automatically for you in `Ueberauth.Strategy.Facebook`.
  These options are only useful for usage outside the normal callback phase
  of Ueberauth.
  """
  def client(opts \\ []) do
    Logger.warn("****Ueberauth *Òauth Facebook*******************")
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Facebook.OAuth)
             |> compute_config(opts)

    Logger.warn("****Ueberauth *Òauth Facebook*************config****** #{inspect(config, pretty: true)}")
    opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    json_library = Ueberauth.json_library()

    Logger.warn("****Ueberauth *Òauth Facebook*************opts****** #{inspect(opts, pretty: true)}")
    OAuth2.Client.new(opts)
    |> OAuth2.Client.put_serializer("application/json", json_library)
  end

  defp compute_config(config, opts) do
    case Keyword.get(opts, :conn) do
      %Plug.Conn{} = conn ->
        with {:ok, client_id} <- Keyword.get(config, :client_id) |> ensure_exists(:get_client_id, 1, [conn]),
             config1 <- config |> Keyword.put(:client_id, client_id),
             {:ok, client_secret}  <- Keyword.get(config, :client_secret) |> ensure_exists(:get_client_secret, 1, [conn]),
             config2 <- config1 |> Keyword.put(:client_secret, client_secret)
        do
          config2
        else
          _ -> config
        end
      _ ->
        config
    end
  end

  defp ensure_exists(module, fun, arity, args) when is_atom(module) or is_bitstring(module) do
    atom_module = case module do
      bitstring_module when is_bitstring(bitstring_module) -> String.to_atom(bitstring_module)
      atom_module when is_atom(atom_module) -> atom_module
    end

    {:module, _} = Code.ensure_loaded(atom_module)
    case function_exported?(atom_module, fun, arity) do
      true -> {:ok, apply(atom_module, fun, args)}
      _ -> :error
    end
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth.
  No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get_token!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.get_token!(params)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param(:client_secret, client.client_secret)
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end
end
