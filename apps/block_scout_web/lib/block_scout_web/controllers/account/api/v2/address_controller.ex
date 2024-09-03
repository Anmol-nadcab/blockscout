defmodule BlockScoutWeb.Account.Api.V2.AddressController do
  use BlockScoutWeb, :controller

  import BlockScoutWeb.Account.AuthController, only: [current_user: 1]

  alias BlockScoutWeb.Account.Api.V2.AuthenticateController
  alias BlockScoutWeb.API.V2.ApiView
  alias Explorer.Chain
  alias Explorer.Chain.Address
  alias Explorer.ThirdPartyIntegrations.Auth0
  alias Plug.Conn

  action_fallback(BlockScoutWeb.Account.Api.V2.FallbackController)

  def link_address(conn, %{"address" => address, "message" => message, "signature" => signature} = params) do
    case conn |> Conn.fetch_session() |> current_user() do
      %{address: ^address} ->
        conn |> put_status(500) |> put_view(ApiView) |> render(:message, %{message: "Already linked to this account"})

      %{uid: id} ->
        with {:format, {:ok, address_hash}} <- {:format, Chain.string_to_address_hash(address)},
             {:ok, auth} <- Auth0.link_address(id, Address.checksum(address_hash), message, signature) do
          AuthenticateController.put_auth_to_session(conn, params, auth)
        end

      _ ->
        {:auth, nil}
    end
  end
end
