defmodule Explorer.Account.Identity do
  @moduledoc """
    Identity of user fetched via Oauth
  """
  use Explorer.Schema

  require Logger
  require Poison

  alias Explorer.Account.Api.Plan
  alias Explorer.Account.{TagAddress, Watchlist}
  alias Explorer.Repo
  alias Ueberauth.Auth

  typed_schema "account_identities" do
    field(:uid_hash, Cloak.Ecto.SHA256) :: binary() | nil
    field(:uid, Explorer.Encrypted.Binary, null: false)
    field(:email, Explorer.Encrypted.Binary, null: false)
    field(:name, Explorer.Encrypted.Binary, null: false)
    field(:nickname, Explorer.Encrypted.Binary)
    field(:avatar, Explorer.Encrypted.Binary)
    field(:verification_email_sent_at, :utc_datetime_usec)
    field(:otp_sent_at, :utc_datetime_usec)
    field(:migrated_to_v2, :boolean)

    has_many(:tag_addresses, TagAddress)
    has_many(:watchlists, Watchlist)

    belongs_to(:plan, Plan)

    timestamps()
  end

  @doc false
  def changeset(identity, attrs) do
    identity
    |> cast(attrs, [:uid, :email, :name, :nickname, :avatar, :verification_email_sent_at])
    |> validate_required([:uid, :email, :name])
    |> put_hashed_fields()
  end

  defp put_hashed_fields(changeset) do
    # Using force_change instead of put_change due to https://github.com/danielberkompas/cloak_ecto/issues/53
    changeset
    |> force_change(:uid_hash, get_field(changeset, :uid))
  end

  def find_or_create(%Auth{} = auth) do
    case find_identity(auth) do
      nil ->
        case create_identity(auth) do
          %__MODULE__{} = identity ->
            {:ok, session_info(auth, identity)}

          {:error, changeset} ->
            {:error, changeset}
        end

      %{} = identity ->
        update_identity(identity, update_identity_map(auth))
        {:ok, session_info(auth, identity)}
    end
  end

  defp create_identity(auth) do
    with {:ok, %__MODULE__{} = identity} <- Repo.account_repo().insert(new_identity(auth)),
         {:ok, _watchlist} <- add_watchlist(identity) do
      identity
    end
  end

  defp update_identity(identity, attrs) do
    identity
    |> changeset(attrs)
    |> Repo.account_repo().update()
  end

  defp new_identity(auth) do
    %__MODULE__{
      uid: auth.uid,
      uid_hash: auth.uid,
      email: email_from_auth(auth),
      name: name_from_auth(auth),
      nickname: nickname_from_auth(auth),
      avatar: avatar_from_auth(auth)
    }
  end

  defp add_watchlist(identity) do
    watchlist = Ecto.build_assoc(identity, :watchlists, %{})

    with {:ok, _} <- Repo.account_repo().insert(watchlist),
         do: {:ok, identity}
  end

  def find_identity(auth_or_uid) do
    Repo.account_repo().one(query_identity(auth_or_uid))
  end

  def query_identity(%Auth{} = auth) do
    from(i in __MODULE__, where: i.uid_hash == ^auth.uid)
  end

  def query_identity(id) do
    from(i in __MODULE__, where: i.id == ^id)
  end

  defp session_info(
         %Auth{extra: %Ueberauth.Auth.Extra{raw_info: %{user: %{"email_verified" => false}}}} = auth,
         identity
       ) do
    %{
      id: identity.id,
      uid: auth.uid,
      email: email_from_auth(auth),
      nickname: nickname_from_auth(auth),
      avatar: avatar_from_auth(auth),
      email_verified: false
    }
  end

  defp session_info(auth, identity) do
    %{watchlists: [watchlist | _]} = Repo.account_repo().preload(identity, :watchlists)

    %{
      id: identity.id,
      uid: auth.uid,
      email: email_from_auth(auth),
      name: name_from_auth(auth),
      nickname: nickname_from_auth(auth),
      avatar: avatar_from_auth(auth),
      watchlist_id: watchlist.id,
      email_verified: true
    }
  end

  defp update_identity_map(auth) do
    %{
      email: email_from_auth(auth),
      name: name_from_auth(auth),
      nickname: nickname_from_auth(auth),
      avatar: avatar_from_auth(auth)
    }
  end

  # github does it this way
  defp avatar_from_auth(%{info: %{urls: %{avatar_url: image}}}), do: image

  # facebook does it this way
  defp avatar_from_auth(%{info: %{image: image}}), do: image

  # default case if nothing matches
  defp avatar_from_auth(auth) do
    Logger.warning(auth.provider <> " needs to find an avatar URL!")
    Logger.debug(Poison.encode!(auth))
    nil
  end

  defp email_from_auth(%{info: %{email: email}}), do: email

  defp nickname_from_auth(%{info: %{nickname: nickname}}), do: nickname

  defp name_from_auth(%{info: %{name: name}})
       when name != "" and not is_nil(name),
       do: name

  defp name_from_auth(%{info: info}) do
    [info.first_name, info.last_name, info.nickname]
    |> Enum.map(&(&1 |> to_string() |> String.trim()))
    |> case do
      ["", "", nick] -> nick
      ["", lastname, _] -> lastname
      [name, "", _] -> name
      [name, lastname, _] -> name <> " " <> lastname
    end
  end
end
