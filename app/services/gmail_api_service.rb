require 'googleauth'
require 'google/apis/gmail_v1'

class GmailApiService
  def initialize(access_token_hash)
    @access_token_hash = access_token_hash
  end

  def call(page_token)
    begin
      inbox_messages = gmail_service_init.list_user_messages('me', page_token: page_token)
      next_page_token = inbox_messages.next_page_token
      messages = inbox_messages.messages.map do |message|
        message_detail = get_message_detail(message.id)
        from_header = message_detail.payload.headers.find{|header| header.name == 'From'}
        to_header = message_detail.payload.headers.find{|header| header.name == 'To'}
        subject_header = message_detail.payload.headers.find{|header| header.name == 'Subject'}
        {
          from: from_header,
          to: to_header,
          subject: subject_header
        }
      end
      {
        next_page_token: next_page_token,
        messages: messages
      }
    rescue Google::Apis::AuthorizationError => exception
      client.refresh!
      retry
    end
  end

  def get_message_detail(message_id)
    gmail_service_init.get_user_message('me', message_id)
  end

  # def get_my_info
  #   MultiJson.load(
  #       client.fetch_protected_resource(
  #         uri: 'https://people.googleapis.com/v1/people/me?personFields=emailAddresses,names'
  #       ).body
  #   )
  # end

  private

  def secrets
    @secrets ||= Google::Auth::ClientId.from_file(Rails.root.join('config/client_secret.json'))
  end

  def client
    @client ||= Google::Auth::UserRefreshCredentials.new(
      client_id: secrets.id,
      client_secret: secrets.secret,
      redirect_uri: 'http://localhost:3000/google/oauth2/callback',
      scope: 'https://www.googleapis.com/auth/gmail.readonly openid email profile',
      access_token: @access_token_hash['access_token'],
      refresh_token: @access_token_hash['refresh_token'],
      expires_at: Time.now + @access_token_hash['expires_in']
    )
  end

  def gmail_service_init
    @gmail_service ||= Google::Apis::GmailV1::GmailService.new
    @gmail_service.authorization = client
    @gmail_service
  end
end
