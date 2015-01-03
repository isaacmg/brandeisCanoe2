json.array!(@members) do |member|
  json.extract! member, :id, :name, :email, :phone, :year, :mailbox, :experience, :car
  json.url member_url(member, format: :json)
end
