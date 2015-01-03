class MemberList < ActionMailer::Base
  default from: "noreply@brandeiscanoe.com"
  def send_signup_email(member)
      @member = member
      mail( :to => @member.email,
           :subject => 'Thanks for signing up' )
  end
end
