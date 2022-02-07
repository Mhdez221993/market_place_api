class Api::V1::TokensController < ApplicationController
  def create
    @user = User.find_by_email(user_params[:email])
    if @user&.authenticate(user_params[:password])
      render json: {
        token: JsonWebToken.encode(user_id: @user.id),
        email: @user.email
      }
    else
      head :unauthorized
    end
  end
  private
  # Only allow a trusted parameter "white list" through.
  def user_params
    params.require(:user).permit(:email, :password)
  end
end

class JsonWebToken
  SECRET_KEY = Rails.application.secrets.secret_key_base.to_s
  def self.encode(payload, exp = 24.hours.from_now)
    payload[:exp] = exp.to_i
    JWT.encode(payload, SECRET_KEY)
  end
  def self.decode(token)
    decoded = JWT.decode(token, SECRET_KEY).first
    HashWithIndifferentAccess.new decoded
  end
end
