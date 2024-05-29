# frozen_string_literal: true

class Users::SessionsController < Devise::SessionsController
  include RackSessionsFix
  respond_to :json

  def create
    # Authenticate user with just email and password.
    self.resource = warden.authenticate!(auth_options.merge(strategy: :password_authenticatable))
    if resource && resource.active_for_authentication?
      # If the user has 2FA enabled
      if resource.otp_required_for_login
        # Store the user ID temporarily. We're not saving the password in the session for security reasons.
        # Generate a signed token for the user ID.
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

        # jwt_token = JWT.encode({
        #                          jti: SecureRandom.uuid,
        #                          sub: resource.id,
        #                          scp: "user",
        #                          aud: nil,
        #                          iat: Time.now.to_i,
        #                          exp: 30.minutes.from_now.to_i
        #                        }, Rails.application.credentials.dig(:devise_jwt_secret_key), 'HS256')

        yield resource if block_given?
        response.headers['Authorization'] = nil
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
      jwt_payload = JWT.decode(request.headers['Authorization'].split(' ').last, Rails.application.credentials.devise_jwt_secret_key!).first
      current_user = User.find(jwt_payload['sub'])
    end

    if current_user
      # JWT::Revoker.revoke(
      #   decoded_token: current_user.jwt_payload,
      #   user: current_user
      # )

      render json: {
        status: 200,
        message: 'Logged out successfully.'
      }, status: :ok
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end


  # before_action :configure_sign_in_params, only: [:create]

  # GET /resource/sign_in
  # def new
  #   super
  # end

  # POST /resource/sign_in
  # def create
  #   super
  # end

  # DELETE /resource/sign_out
  # def destroy
  #   super
  # end

  # protected

  # If you have extra params to permit, append them to the sanitizer.
  # def configure_sign_in_params
  #   devise_parameter_sanitizer.permit(:sign_in, keys: [:attribute])
  # end
end
