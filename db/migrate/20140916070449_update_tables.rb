class UpdateTables < ActiveRecord::Migration
  def change
       add_column :members, :json, :text
       change_column :members, :phone, :string 
  end
end
