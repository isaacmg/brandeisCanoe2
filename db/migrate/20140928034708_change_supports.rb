class ChangeSupports < ActiveRecord::Migration
  def change
      change_column :supports, :signature, :text
  end
end
