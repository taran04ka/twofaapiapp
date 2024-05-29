# frozen_string_literal: true

class Users::SessionsController < Devise::SessionsController
  include RackSessionsFix
  respond_to :json

  def create
    self.resource = warden.authenticate!(auth_options.merge(strategy: :password_authenticatable))
    if resource && resource.active_for_authentication?
      if resource.otp_required_for_login
        verifier = Rails.application.message_verifier(:otp_session)
        token = verifier.generate(resource.id)

        enc_token = TokenEncryptionService.encrypt(token)
        # Logout the user to wait for the 2FA verification
        sign_out(resource_name)

        render json: {
          status: {
            code: 202, message: 'User has 2FA enabled. OTP code is needed.',
            otp_token: enc_token
          }
        }, status: :accepted
      else
        # If 2FA is not required, log the user in
        sign_in(resource_name, resource)

        jwt_secret = SecureRandom.uuid
        resource.jwt_secret = jwt_secret
        resource.save!
        jwt_token = JWT.encode({
                                 jti: jwt_secret,
                                 sub: resource.id,
                                 scp: "user",
                                 aud: nil,
                                 iat: Time.now.to_i,
                                 exp: 30.minutes.from_now.to_i
                               }, Rails.application.credentials.dig(:jwt_secret_key), 'HS256')

        yield resource if block_given?
        response.headers['Authorization'] = "Bearer #{jwt_token}"
        render json: {
          status: {
            code: 200, message: 'Logged in successfully.',
            data: { user: UserSerializer.new(resource).serializable_hash[:data][:attributes] }
          }
        }, status: :ok
      end
    else
      render json: {
        status: {
          code: 403, message: 'Invalid email or password.'
        }
      }, status: :forbidden
    end
  end

  private
  def respond_with(resource, _opts = {})
    render json: {
      status: {
        code: 200, message: 'Logged in successfully.',
        data: { user: UserSerializer.new(resource).serializable_hash[:data][:attributes] }
      }
    }, status: :ok
  end
  def respond_to_on_destroy
    if request.headers['Authorization'].present?
      jwt_payload = JWT.decode(request.headers['Authorization'].split(' ').last, Rails.application.credentials.jwt_secret_key!).first
      if jwt_payload[:exp] < Time.now.to_i
        render json: {
          status: 401,
          message: "JWT token is expired."
        }, status: :unauthorized
      end
      current_user = User.find(jwt_payload['sub'])
    end

    if current_user
      if current_user.jwt_secret == jwt_payload['jti']
        current_user.jwt_secret = nil
        current_user.save!
        render json: {
          status: 200,
          message: 'Logged out successfully.'
        }, status: :ok
      else
        render json: {
          status: 401,
          message: "JWT token is invalid."
        }, status: :unauthorized
      end
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end
end
