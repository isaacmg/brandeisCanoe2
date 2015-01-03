class CreateMembers < ActiveRecord::Migration
  def change
    create_table :members do |t|
      t.string :name
      t.string :email
      t.integer :phone
      t.integer :year
      t.integer :mailbox
      t.string :experience
      t.string :car

      t.timestamps
    end
  end
end
