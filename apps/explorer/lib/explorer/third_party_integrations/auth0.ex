defmodule Explorer.ThirdPartyIntegrations.Auth0 do
  @moduledoc """
    Module for fetching jwt Auth0 Management API (https://auth0.com/docs/api/management/v2) jwt
  """
  require Logger

  alias Explorer.Account.Identity
  alias Explorer.Helper
  alias OAuth2.{AccessToken, Client}
  alias Ueberauth.Auth
  alias Ueberauth.Strategy.Auth0
  alias Ueberauth.Strategy.Auth0.OAuth

  @redis_key "auth0"

  @doc """
    Function responsible for retrieving machine to machine JWT for interacting with Auth0 Management API.
    Firstly it tries to access cached token and if there is no cached one, token will be requested from Auth0
  """
  @spec get_m2m_jwt() :: nil | String.t()
  def get_m2m_jwt do
    get_m2m_jwt_inner(Redix.command(:redix, ["GET", cookie_key(@redis_key)]))
  end

  def get_m2m_jwt_inner({:ok, token}) when not is_nil(token), do: token

  def get_m2m_jwt_inner(_) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Auth0.OAuth)

    body = %{
      "client_id" => config[:client_id],
      "client_secret" => config[:client_secret],
      "audience" => "https://#{config[:domain]}/api/v2/",
      "grant_type" => "client_credentials"
    }

    headers = [{"Content-type", "application/json"}]

    case HTTPoison.post("https://#{config[:domain]}/oauth/token", Jason.encode!(body), headers, []) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        case Jason.decode!(body) do
          %{"access_token" => token, "expires_in" => ttl} ->
            cache_token(token, ttl - 1)

          _ ->
            nil
        end

      _ ->
        nil
    end
  end

  @doc """
    Generates key from chain_id and cookie hash for storing in Redis
  """
  @spec cookie_key(binary) :: String.t()
  def cookie_key(hash) do
    chain_id = Application.get_env(:block_scout_web, :chain_id)

    if chain_id do
      chain_id <> "_" <> hash
    else
      hash
    end
  end

  defp cache_token(token, ttl) do
    Redix.command(:redix, ["SET", cookie_key(@redis_key), token, "EX", ttl])
    token
  end

  @spec link_email(String.t(), String.t(), String.t()) :: :error | {:ok, Auth.t()} | {:error, String.t()}
  def link_email(primary_user_id, email, otp) do
    case find_accounts_by_email(email) do
      {:ok, []} ->
        with {:ok, token} <- confirm_otp(email, otp),
             {:ok, %{"sub" => "email|" <> identity_id}} <- get_userinfo(OAuth.client(token: token)),
             :ok <- link_accounts(primary_user_id, identity_id, "email"),
             {:ok, user} <- update_account_email(primary_user_id, email) do
          {:ok, create_auth(user, "user_id")}
        end

      {:ok, users} when is_list(users) ->
        {:error, "Account with this email already exists"}

      error ->
        error
    end
  end

  @spec send_otp_for_linking(String.t(), String.t()) :: :error | :ok | {:error, String.t()}
  def send_otp_for_linking(email, ip) do
    case find_accounts_by_email(email) do
      {:ok, []} ->
        do_send_otp(email, ip)

      {:ok, users} when is_list(users) and length(users) > 0 ->
        {:error, "Account with this email already exists"}

      error ->
        error
    end
  end

  @spec send_otp(String.t(), String.t()) :: :error | :ok | {:interval, integer()}
  def send_otp(email, ip) do
    case find_accounts_by_email(email) do
      {:ok, []} ->
        do_send_otp(email, ip)

      {:ok, [user | _]} ->
        handle_existing_user(user, email, ip)

      error ->
        error
    end
  end

  defp handle_existing_user(user, email, ip) do
    user
    |> create_auth("user_id")
    |> Identity.find_identity()
    |> handle_identity(email, ip)
  end

  defp handle_identity(nil, email, ip), do: do_send_otp(email, ip)

  defp handle_identity(%Identity{otp_sent_at: otp_sent_at}, email, ip) do
    otp_resend_interval = Application.get_env(:explorer, Account, :otp_resend_interval)

    case Helper.check_time_interval(otp_sent_at, otp_resend_interval) do
      true -> do_send_otp(email, ip)
      interval -> {:interval, interval}
    end
  end

  defp do_send_otp(email, ip) do
    auth0_config = Application.get_env(:ueberauth, Ueberauth.Strategy.Auth0.OAuth)

    body = %{
      email: email,
      connection: :email,
      send: :code,
      client_id: auth0_config[:client_id],
      client_secret: auth0_config[:client_secret]
    }

    headers = ["Content-type": "application/json", "auth0-forwarded-for": ip]

    case HTTPoison.post("https://" <> auth0_config[:domain] <> "/passwordless/start", Jason.encode!(body), headers) do
      {:ok, %HTTPoison.Response{status_code: 200}} ->
        :ok

      other ->
        Logger.error(fn -> ["Error while sending otp: ", inspect(other)] end)

        :error
    end
  end

  @spec confirm_otp_and_get_auth(String.t(), String.t()) :: :error | {:error, String.t()} | {:ok, Ueberauth.Auth.t()}
  def confirm_otp_and_get_auth(email, otp) do
    with {:ok, token} <- confirm_otp(email, otp),
         {:ok, user} <- get_userinfo(OAuth.client(token: token)) do
      maybe_link_email_and_get_auth(user)
    end
  end

  defp confirm_otp(email, otp) do
    client = OAuth.client()

    body =
      %{
        username: email,
        otp: otp,
        realm: :email,
        grant_type: :"http://auth0.com/oauth/grant-type/passwordless/otp"
      }
      |> Map.merge(get_client_id_and_secret())

    headers = [{"Content-type", "application/json"}]

    case Client.post(client, "/oauth/token", body, headers) do
      {:ok, %OAuth2.Response{status_code: 200, body: body}} ->
        {:ok, AccessToken.new(body)}

      {:error,
       %OAuth2.Response{
         status_code: 403,
         body:
           %{
             "error" => "unauthorized_client",
             "error_description" =>
               "Grant type 'http://auth0.com/oauth/grant-type/passwordless/otp' not allowed for the client.",
             "error_uri" => "https://auth0.com/docs/clients/client-grant-types"
           } = body
       }} ->
        Logger.error(fn -> ["Need to enable OTP: ", inspect(body)] end)
        {:error, "Misconfiguration detected, please contact support."}

      other ->
        Logger.error(fn -> ["Error while confirming otp: ", inspect(other)] end)

        :error
    end
  end

  defp find_accounts_by_email(email) do
    case get_m2m_jwt() do
      token when is_binary(token) ->
        client = OAuth.client(token: token)

        case Client.get(client, "/api/v2/users", [], params: %{"q" => ~s(email:"#{email}")}) do
          {:ok, %OAuth2.Response{status_code: 200, body: users}} when is_list(users) ->
            {:ok, users}

          {:error, %OAuth2.Response{status_code: 403, body: %{"errorCode" => "insufficient_scope"} = body}} ->
            Logger.error(["Failed to get web3 user. Insufficient scope: ", inspect(body)])
            {:error, "Misconfiguration detected, please contact support."}

          other ->
            Logger.error(["Error while getting web3 user: ", inspect(other)])
            :error
        end

      nil ->
        Logger.error("Failed to get M2M JWT")
        {:error, "Misconfiguration detected, please contact support."}
    end
  end

  defp maybe_link_email_and_get_auth(%{"email" => email, "sub" => "email|" <> identity_id = user_id} = user) do
    case get_m2m_jwt() do
      token when is_binary(token) ->
        client = OAuth.client(token: token)

        case Client.get(client, "/api/v2/users", [],
               params: %{"q" => ~s(email:"#{email}" AND NOT user_id:"#{user_id}")}
             ) do
          {:ok, %OAuth2.Response{status_code: 200, body: []}} ->
            {:ok, create_auth(user, "sub")}

          {:ok, %OAuth2.Response{status_code: 200, body: [%{"user_id" => primary_user_id} = user]}} ->
            link_accounts(primary_user_id, identity_id, "email")
            {:ok, create_auth(user, "user_id")}

          {:ok, %OAuth2.Response{status_code: 200, body: users}} when is_list(users) and length(users) > 1 ->
            Logger.error(["Found multiple users with the same email: ", inspect(users)])
            :error

          {:error, %OAuth2.Response{status_code: 403, body: %{"errorCode" => "insufficient_scope"} = body}} ->
            Logger.error(["Failed to get web3 user. Insufficient scope: ", inspect(body)])
            {:error, "Misconfiguration detected, please contact support."}

          other ->
            Logger.error(["Error while getting web3 user: ", inspect(other)])
            :error
        end

      nil ->
        Logger.error("Failed to get M2M JWT")
        {:error, "Misconfiguration detected, please contact support."}
    end
  end

  defp maybe_link_email_and_get_auth(user) do
    {:ok, create_auth(user, "sub")}
  end

  @spec generate_siwe_message(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def generate_siwe_message(address) do
    nonce = Siwe.generate_nonce()
    cache_nonce_for_address(nonce, address)

    {int_chain_id, _} = Integer.parse(Application.get_env(:block_scout_web, :chain_id))

    message = %Siwe.Message{
      domain: Application.get_env(:block_scout_web, BlockScoutWeb.Endpoint)[:url][:host],
      address: address,
      statement: "Sign in to Blockscout Account V2 via Ethereum account",
      uri:
        Application.get_env(:block_scout_web, BlockScoutWeb.Endpoint)[:url][:scheme] <>
          "://" <> Application.get_env(:block_scout_web, BlockScoutWeb.Endpoint)[:url][:host],
      version: "1",
      chain_id: int_chain_id,
      nonce: nonce,
      issued_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      expiration_time: DateTime.utc_now() |> DateTime.add(300, :second) |> DateTime.to_iso8601()
    }

    case Siwe.to_str(message) do
      {:ok, message} ->
        {:ok, message}

      {:error, error} ->
        Logger.error(fn -> "Error while generating Siwe Message: #{inspect(error)}" end)
        {:error, error}
    end
  end

  defp cache_nonce_for_address(nonce, address) do
    Redix.command(:redix, ["SET", cookie_key(address <> "siwe_nonce"), nonce, "EX", 300])
    nonce
  end

  def link_address(user_id, address, message, signature) do
    with {:nonce, {:ok, nonce}} <-
           {:nonce, Redix.command(:redix, ["GET", cookie_key(address <> "siwe_nonce")])},
         {:signature, {:ok, %{nonce: ^nonce}}} <-
           {:signature, message |> String.trim() |> Siwe.parse_if_valid(signature)},
         Redix.command(:redix, ["DEL", cookie_key(address <> "siwe_nonce")]),
         {:account, {:ok, []}} <- {:account, find_web3_users_by_address(address)},
         {:ok, account} <- update_account_with_eth_address(user_id, address) do
      {:ok, create_auth(account, "user_id")}
    else
      {:nonce, _} ->
        {:error, "Request siwe message via /api/account/v2/siwe_message"}

      {:signature, {:ok, _}} ->
        {:error, "Wrong nonce in message"}

      {:signature, error} ->
        error

      {:account, {:ok, _accounts}} ->
        {:error, "Account with this address already exists"}

      {:account, error} ->
        error

      other ->
        other
    end
  end

  @spec get_auth_with_web3(String.t(), String.t(), String.t()) ::
          :error | {:error, String.t()} | {:ok, Ueberauth.Auth.t()}
  def get_auth_with_web3(address, message, signature) do
    with {:nonce, {:ok, nonce}} <-
           {:nonce, Redix.command(:redix, ["GET", cookie_key(address <> "siwe_nonce")])},
         {:signature, {:ok, %{nonce: ^nonce}}} <-
           {:signature, message |> String.trim() |> Siwe.parse_if_valid(signature)},
         {:account, {:ok, account}} <- {:account, find_or_create_web3_account(address, signature)} do
      Redix.command(:redix, ["DEL", cookie_key(address <> "siwe_nonce")])
      {:ok, create_auth(account, "user_id")}
    else
      {:nonce, _} ->
        {:error, "Request siwe message via /api/account/v2/siwe_message"}

      {:signature, {:ok, _}} ->
        {:error, "Wrong nonce in message"}

      {:signature, error} ->
        error

      {:account, error} ->
        error
    end
  end

  defp find_or_create_web3_account(address, signature) do
    case find_web3_users_by_address(address) do
      {:ok, [%{"user_metadata" => %{"eth_address" => ^address}} = user]} ->
        {:ok, user}

      {:ok, [%{"user_id" => user_id}]} ->
        update_account_with_eth_address(user_id, address)

      {:ok, []} ->
        create_web3_user(address, signature)

      {:ok, users} when is_list(users) and length(users) > 1 ->
        Logger.error(["Failed to get web3 user. Multiple accounts with the same address found: ", inspect(users)])
        :error

      other ->
        other
    end
  end

  defp find_web3_users_by_address(address) do
    with token when is_binary(token) <- get_m2m_jwt(),
         client = OAuth.client(token: token),
         {:ok, %OAuth2.Response{status_code: 200, body: users}} when is_list(users) <-
           Client.get(
             client,
             "/api/v2/users",
             [],
             params: %{
               "q" =>
                 ~s(user_id:*siwe*#{address} OR user_id:*Passkey*#{address} OR user_metadata.eth_address:"#{address}")
             }
           ) do
      {:ok, users}
    else
      error -> handle_common_errors(error, "Failed to search user by address")
    end
  end

  defp update_account_email(user_id, email) do
    with token when is_binary(token) <- get_m2m_jwt(),
         client = OAuth.client(token: token),
         body = %{"email" => email, "email_verified" => true},
         headers = [{"Content-type", "application/json"}],
         {:ok, %OAuth2.Response{status_code: 200, body: user}} <-
           Client.patch(client, "/api/v2/users/#{user_id}", body, headers) do
      {:ok, user}
    else
      error -> handle_common_errors(error, "Failed to update user email")
    end
  end

  defp update_account_with_eth_address(user_id, address) do
    with token when is_binary(token) <- get_m2m_jwt(),
         client = OAuth.client(token: token),
         body = %{"user_metadata" => %{"eth_address" => address}},
         headers = [{"Content-type", "application/json"}],
         {:ok, %OAuth2.Response{status_code: 200, body: user}} <-
           Client.patch(client, "/api/v2/users/#{user_id}", body, headers) do
      {:ok, user}
    else
      error -> handle_common_errors(error, "Failed to update user address")
    end
  end

  defp create_web3_user(address, signature) do
    with token when is_binary(token) <- get_m2m_jwt(),
         client = OAuth.client(token: token),
         body = %{
           email: address <> "@eth.eth",
           password: signature,
           email_verified: true,
           connection: :"Username-Password-Authentication",
           user_metadata: %{eth_address: address}
         },
         headers = [{"Content-type", "application/json"}],
         {:ok, %OAuth2.Response{status_code: 201, body: user}} <-
           Client.post(client, "/api/v2/users", body, headers) do
      {:ok, user}
    else
      error -> handle_common_errors(error, "Failed to create web3 user")
    end
  end

  defp link_accounts(primary_user_id, secondary_identity_id, provider) do
    with token when is_binary(token) <- get_m2m_jwt(),
         client = OAuth.client(token: token),
         body = %{
           provider: provider,
           user_id: secondary_identity_id
         },
         headers = [{"Content-type", "application/json"}],
         {:ok, %OAuth2.Response{status_code: 201}} <-
           Client.post(client, "/api/v2/users/#{primary_user_id}/identities", body, headers) do
      :ok
    else
      error -> handle_common_errors(error, "Failed to link accounts")
    end
  end

  defp get_userinfo(client) do
    case Client.get(client, "/userinfo") do
      {:ok, %OAuth2.Response{status_code: 200, body: user}} ->
        {:ok, user}

      {:ok, %OAuth2.Response{status_code: 401, body: body}} ->
        Logger.error(["Failed to get auth via /userinfo. Unauthorized: ", inspect(body)])
        {:error, "Unauthorized"}

      other ->
        Logger.error(["Error while getting auth via /userinfo: ", inspect(other)])
        :error
    end
  end

  defp create_auth(user, uid_key) do
    conn_stub = %{private: %{auth0_user: user, auth0_token: nil}}

    %Auth{
      uid: user[uid_key],
      provider: :auth0,
      strategy: Auth0,
      info: Auth0.info(conn_stub),
      credentials: %Ueberauth.Auth.Credentials{},
      extra: Auth0.extra(conn_stub)
    }
  end

  defp get_client_id_and_secret do
    auth0_config = Application.get_env(:ueberauth, Ueberauth.Strategy.Auth0.OAuth)

    %{
      client_id: auth0_config[:client_id],
      client_secret: auth0_config[:client_secret]
    }
  end

  defp handle_common_errors(error, error_msg) do
    case error do
      nil ->
        Logger.error("Failed to get M2M JWT")
        {:error, "Misconfiguration detected, please contact support."}

      {:error, %OAuth2.Response{status_code: 403, body: %{"errorCode" => "insufficient_scope"} = body}} ->
        Logger.error(["#{error_msg}. Insufficient scope: ", inspect(body)])
        {:error, "Misconfiguration detected, please contact support."}

      other ->
        Logger.error(["#{error_msg}: ", inspect(other)])
        :error
    end
  end
end
