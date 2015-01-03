class CreateSupports < ActiveRecord::Migration
  def change
    create_table :supports do |t|
      t.string :name
      t.integer :year
      t.string :phone
      t.string :email
      t.integer :mailbox
      t.string :signature

      t.timestamps
    end
  end
end
