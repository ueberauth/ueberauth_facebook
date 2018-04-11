defmodule Ueberauth.Strategy.Facebook.OAuth do
  @moduledoc """
  OAuth2 for Facebook.

  Add `client_id` and `client_secret` to your configuration:

  config :ueberauth, Ueberauth.Strategy.Facebook.OAuth,
    client_id: System.get_env("FACEBOOK_APP_ID"),
    client_secret: System.get_env("FACEBOOK_APP_SECRET")
  """
  use OAuth2.Strategy

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
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Facebook.OAuth)
    config = compute_config(config, opts)

    opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    OAuth2.Client.new(opts)
  end

  defp compute_config(config, opts) do
    case Keyword.get(opts, :conn) do
      %Plug.Conn{} = conn ->
        with module when is_atom(module) <- Keyword.get(config, :config_from),
             true <- function_exported?(module, :get_client_id, 1),
             true <- function_exported?(module, :get_client_secret, 1)
        do
          config |> Keyword.merge([
            client_id: apply(module, :get_client_id, [conn]),
            client_secret: apply(module, :get_client_secret, [conn])
          ])
        else
          _ -> config
        end
      _ ->
        config
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
