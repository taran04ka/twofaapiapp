# app/services/token_encryption_service.rb
class TokenEncryptionService
  ALGORITHM = 'aes-256-gcm'.freeze

  def self.encrypt(plain_text)
    cipher = OpenSSL::Cipher.new(ALGORITHM)
    cipher.encrypt
    key = fetch_key
    cipher.key = [key].pack('H*')

    iv = cipher.random_iv
    encrypted_data = cipher.update(plain_text) + cipher.final
    auth_tag = cipher.auth_tag

    {
      data: Base64.encode64(encrypted_data),
      iv: Base64.encode64(iv),
      auth_tag: Base64.encode64(auth_tag)
    }.to_json
  end

  def self.decrypt(encrypted_json)
    cipher = OpenSSL::Cipher.new(ALGORITHM)
    cipher.decrypt
    key = fetch_key
    cipher.key = [key].pack('H*')
    cipher.iv = Base64.decode64(encrypted_json['iv'])
    cipher.auth_tag = Base64.decode64(encrypted_json['auth_tag'])

    encrypted_data = Base64.decode64(encrypted_json['data'])
    cipher.update(encrypted_data) + cipher.final
  end

  def self.fetch_key
    key = Rails.application.credentials.encryption_key || ENV['ENCRYPTION_KEY']
    raise 'Encryption key not set' if key.blank?

    key
  end
end
