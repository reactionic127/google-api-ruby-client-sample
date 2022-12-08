class MessagesController < ApplicationController
  def index
    if session[:access_token_hash].blank?
      redirect_to google_oauth_path
      return
    end

    @payload = GmailApiService.new(session[:access_token_hash]).call(params[:next_page_token])
  end
end
