class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
  :recoverable, :confirmable, :rememberable, :trackable, :validatable
         validate :password_complexity, :brandeis_email
 def forem_name
  email 
end
def forem_email
  email_address
end
def password_complexity
    puts password
    if password.present? and not password.match(/^(?=[^\d_].*?\d)\w(\w|[!@#$%]){7,20}/)
      errors.add :password, "must include at least one lowercase letter, one uppercase letter, and one digit"
    end
  end
  def  brandeis_email 
  		if email.present? and not email.include? "brandeis.edu"
  		errors.add :email, "Must use a Brandeis Email Address. If you would like access to our web forums but don't have a Brandeis email please contact igodfrie@brandeis.edu"
  		end
  end 

end
