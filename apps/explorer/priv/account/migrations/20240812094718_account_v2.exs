defmodule Explorer.Repo.Account.Migrations.AccountV2 do
  use Ecto.Migration

  def change do
    alter table(:account_identities) do
      remove(:name)
      remove(:nickname)
      add(:otp_sent_at, :"timestamp without time zone", null: true)
    end
  end
end
