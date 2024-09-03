defmodule Explorer.Repo.Account.Migrations.AccountV2 do
  use Ecto.Migration

  def change do
    alter table(:account_identities) do
      add(:otp_sent_at, :"timestamp without time zone", null: true)
      add(:migrated_to_v2, :boolean, default: false)
    end
  end
end
