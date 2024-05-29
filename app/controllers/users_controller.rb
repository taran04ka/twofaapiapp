class UsersController < ApplicationController
  include RackSessionsFix
  respond_to :json

  def verify_otp
    request_body = JSON.parse(request.body.string)
    verifier = Rails.application.message_verifier(:otp_session)
    otp_token = TokenEncryptionService.decrypt(request_body['otp_token'])
    user_id = verifier.verify(otp_token)
    user = User.find(user_id)

    if user.validate_and_consume_otp!(request_body['otp_attempt'])
      sign_in(:user, user)

      jwt_token = JWT.encode({
                               jti: SecureRandom.uuid,
                               sub: user.id,
                               scp: "user",
                               aud: nil,
                               iat: Time.now.to_i,
                               exp: 30.minutes.from_now.to_i
                             }, Rails.application.credentials.dig(:jwt_secret_key), 'HS256')
      response.headers['Authorization'] = "Bearer #{jwt_token}"

      render json: {
        status: {
          code: 200, message: 'Logged in successfully.',
          data: { user: UserSerializer.new(current_user).serializable_hash[:data][:attributes] }
        }
      }, status: :ok
    else
      render json: {
        status: 403,
        message: "Invalid OTP code."
      }, status: :forbidden
    end
  end

  def enable_otp_show_qr
    if request.headers['Authorization'].present?
      jwt_payload = JWT.decode(request.headers['Authorization'].split(' ').last, Rails.application.credentials.dig(:jwt_secret_key), algorithm: 'HS256').first
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
        if current_user.otp_required_for_login
          render json: {
            status: {
              code: 405, message: '2FA is already enabled.'
            }
          }, status: :ok
        else
          current_user.otp_secret = User.generate_otp_secret

          provisioning_uri = current_user.otp_provisioning_uri(current_user.email, issuer: "Devise-Two-Factor-Demo")
          current_user.save!
          render json: {
            status: {
              code: 200, message: 'QR code generated. Scan it and enter code to enable 2FA.',
              data: { uri: provisioning_uri }
            }
          }, status: :ok
        end
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

  def enable_otp_verify
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
        request_body = JSON.parse(request.body.string)
        if request_body
          if current_user.validate_and_consume_otp!(request_body['otp_attempt'])
            current_user.otp_required_for_login = true
            current_user.save!
            render json: {
              status: {
                code: 200, message: '2FA enabled successfully.'
              }
            }, status: :ok
          else
            render json: {
              status: 403,
              message: "Invalid OTP code."
            }, status: :forbidden
          end
        else
          render json: {
            status: 401,
            message: "JWT token is invalid."
          }, status: :unauthorized
        end
      end
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end

  def disable_otp_verify
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
        request_body = JSON.parse(request.body.string)
        if request_body
          if current_user.validate_and_consume_otp!(request_body['otp_attempt'])
            current_user.otp_required_for_login = false
            current_user.save!

            render json: {
              status: 200,
              message: "2FA disabled successfully."
            }, status: :ok
          else
            render json: {
              status: 403,
              message: "Invalid OTP code."
            }, status: :forbidden
          end
        end
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
