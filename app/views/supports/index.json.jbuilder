json.array!(@supports) do |support|
  json.extract! support, :id, :name, :year, :phone, :email, :mailbox, :signature
  json.url support_url(support, format: :json)
end
