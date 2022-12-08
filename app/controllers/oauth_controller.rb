class OauthController < ApplicationController
  def index
    # TODO: Implement first leg of OAuth2 credential exchange here.
    redirect_to client.authorization_uri.to_s
  end

  def callback
    # TODO: Implement second leg of OAuth2 credential exchange here.
    client.code = params[:code]
    access_token_hash = client.fetch_access_token!
    session[:access_token_hash] = access_token_hash

    redirect_to root_path
  end

  private

  def secrets
    @secrets ||= Google::Auth::ClientId.from_file(Rails.root.join('config/client_secret.json'))
  end

  def client
    @client ||= Google::Auth::UserRefreshCredentials.new(
      client_id: secrets.id,
      client_secret: secrets.secret,
      redirect_uri: 'http://localhost:3000/google/oauth2/callback',
      scope: 'https://www.googleapis.com/auth/gmail.readonly openid email profile'
    )
  end
end
