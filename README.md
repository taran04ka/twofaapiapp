# Rails 2FA API Application

This Rails application provides a secure API for user registration, login, and two-factor authentication (2FA). It leverages several powerful gems including Devise, Devise-Two-Factor, JWT, JSON:API Serializer, and RQRCode to deliver robust authentication features.

## Features

- **User Registration**: API endpoints for creating new user accounts.
- **User Login**: Secure login using email and password.
- **Two-Factor Authentication (2FA)**:
    - Enable 2FA for user accounts.
    - Verify 2FA codes during login.
    - Disable 2FA for user accounts.
- **JWT Authentication**: Secure token-based authentication for API access.
- **JSON:API Serialization**: Structured and standardized JSON responses.

## Gems Used

- **Devise**: Flexible authentication solution for Rails.
- **Devise-Two-Factor**: Adds 2FA capabilities to Devise.
- **JWT**: JSON Web Token implementation in Ruby.
- **JSONAPI::Serializer**: Fast JSON:API serialization for Rails.
- **RQRCode**: Generate QR codes for 2FA setup.

## Getting Started

### Prerequisites

- Ruby (version 3.0.0 or newer recommended)
- Rails (version 6.0 or newer)
- PostgreSQL or another supported database

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/taran04ka/twofaapiapp.git
   cd twofaapiapp
   ```
2. **Install Dependencies**
    ```bash
   bundle install
    ```
3. **Setup Database**
    ```bash
   rails db:setup
    ```
4. **Run Migrations**
    ```bash
    rails db:migrate
   ```
5. **Start the Server**
   ```bash
   rails server
   ```
   **Note:** The application uses ports 3000 and 3001, so they should not be taken by any other application in order to run the server successfully. Requests should be sent on port 3001.

### API Endpoints

1. **User Registration**
- Endpoint: `/users`
- Method: `POST`
- Payload:
```json
{
  "user": {
    "email": "user@example.com",
    "password": "password"
  }
}
```
- Headers:
```text
Content-Type: application/json
```
- Responses:
  - Successful
  ```json
  {
    "status": {
        "code": 200,
        "message": "Signed up successfully."
    },
    "data": {
        "id": 1,
        "email": "user@example.com"
    }
  }
  ```
  - Failure
  ```json
    {
      "status": {
        "message": "Error message"
      }
    }
  ```
  **Note:** Error messages could be different, depending on the problem that occurred during registration. To avoid problems, the user should have a unique email, both password and email shouldn't be blank, the password has to be a minimum of 6 characters long, and the email has to be valid.

2. **User Login**
- Endpoint: `/users/sign_in`
- Method: `POST`
- Payload:
```json
{
  "user": {
    "email": "user@example.com",
    "password": "password"
  }
}
```
- Headers:
```text
Content-Type: application/json
```
- Responses:
    
    User gets response with status 200 and JWT token, if their account has 2FA disabled. Otherwise, user receives response 202 and has to verify their OTP token to receive JWT token.
    - Successful
  ```json
  {
    "status": {
        "code": 200,
        "message": "Logged in successfully.",
        "data": {
            "user": {
                "id": 1,
                "email": "user@example.com"
            }
        }
    }
  }
  ```
  Headers:
  ```text
  authorization: Bearer [JWT token]
  ```
  **Note:** Headers of a successful response include the authorization bearer in the 'Authorization' header, which should be included (together with the Bearer attachment) in further requests that require authorization.
    - OTP required
  ```json
  {
    "status": {
        "code": 202,
        "message": "User has 2FA enabled. OTP code is needed.",
        "otp_token": "{\"data\":\"[OTP token]\",\"iv\":\"[IV]\",\"auth_tag\":\"[auth_tag]\"}"
    }
  }
  ```
  **Note:** The OTP token from the response body has to be attached to the body of the OTP verification request.
    - Failure
  ```text
    Invalid email or password
  ```
  Provided user should be registered previously.
3. **OTP verification**
- Endpoint: `/users/otp`
- Method: `POST`
- Payload:
  
Current OTP code from the Google Authenticator application, associated with the account, user wants to login with, should be provided in the request body as OTP attempt. The request should be sent before the expiration of the provided OTP code, otherwise it will be considered as invalid.
```json
{
  "otp_attempt": "[OTP code]",
  "otp_token": {
    "data":"[OTP token]","iv":"[IV]","auth_tag":"[auth_tag]"
  }
}
```
- Headers:
```text
Content-Type: application/json
```
- Responses:
  - Successful:
  ```json
  {
    "status": {
        "code": 200,
        "message": "Logged in successfully.",
        "data": {
            "user": {
                "id": 1,
                "email": "user@example.com"
            }
        }
    }
  }
  ```
  Headers:
    ```text
  authorization: Bearer [JWT token]
  ```
  **Note:** As for regular login, the JWT token from the authorization header (together with the Bearer attachment) should be added to further request headers.
  - Failure:
  ```json
  {
    "status": 403,
    "message": "Invalid OTP code."
  }
  ```
4. **Getting QR code for 2FA enabling**
- Endpoint: `/users/enable_otp_show_qr`
- Method: `GET`
- Payload: none
- Headers:
```text
Content-Type: application/json
Authorization: Bearer [JWT token]
```
- Responses:
  - Successful:
  ```json
  {
    "status": {
        "code": 200,
        "message": "QR code generated. Scan it and enter code to enable 2FA.",
        "data": {
            "uri": "otpauth://totp/Devise-Two-Factor-Demo:user%40example.com?secret=[secret]&issuer=Devise-Two-Factor-Demo"
        }
    }
  }
  ```
  **Note:** A QR code should be generated from the URI returned in the response data. This QR code should be scanned using the Google Authenticator app.

  - Failure:

  Failure occurs if the JWT token is invalid, not associated with the currently logged in account, or if it has expired.
  ```json
  {
    "status": 401,
    "message": "Couldn't find an active session."
  }
  ```
  ```json
  {
    "status": 401,
    "message": "JWT token is invalid."
  }
  ```
  ```json
  {
    "status": 401,
    "message": "JWT token is expired."
  }
  ```
  ```json
  {
    "status": {
      "code": 405,
      "message": "2FA is already enabled."
    }
  }  
  ```
5. **Verifying OTP for 2FA enabling**
- Endpoint: `/users/enable_otp_verify`
- Method: `POST`
- Payload:
```json
{
  "otp_attempt": "[OTP code]"
}
```
- Headers:
```text
Content-Type: application/json
Authorization: Bearer [JWT token]
```
- Responses:

  Current OTP code from the Google Authenticator application, associated with the account, user wants to enable 2FA for, should be provided in the request body as OTP attempt. The request should be sent before the expiration of the provided OTP code, otherwise it will be considered as invalid.
  
  User gets response with status 200 and 2FA for their account enables if provided OTP code is not expired and valid.
  - Successful
  ```json
  {
    "status":{
      "code": 200,
      "message": "2FA enabled successfully."
    }
  }
  ```
  - Failure

  Failure occurs if the OTP code is invalid, not associated with the account whose credentials were provided earlier, or if it has expired.

  Also, it occurs if the JWT token is invalid, not associated with the currently logged in account, or if it has expired.
  ```json
  {
    "status": 403,
    "message": "Invalid OTP code."
  }
  ```
  ```json
  {
    "status": 401,
    "message": "Couldn't find an active session."
  }
  ```
  ```json
  {
    "status": 401,
    "message": "JWT token is invalid."
  }
  ```
  ```json
  {
    "status": 401,
    "message": "JWT token is expired."
  }
  ```
6. **Verifying OTP for 2FA disabling**
- Endpoint: `/users/disable_otp_verify`
- Method: `POST`
- Payload:
```json
{
  "otp_attempt": "[OTP code]"
}
```
- Headers:
```text
Content-Type: application/json
Authorization: Bearer [JWT token]
```
- Responses:

  Current OTP code from the Google Authenticator application, associated with the account, user is logged in to, should be provided in the request body as OTP attempt. The request should be sent before the expiration of the provided OTP code, otherwise it will be considered as invalid.
  Also, JWT token has to be valid (associated with current account and not expired) and attached to request headers, otherwise request fails.
  - Successful:
  ```json
  {
    "status": 200,
    "message": "2FA disabled successfully."
  }
  ```
  - Failure:

  Failure occurs if the OTP code is invalid, not associated with currently logged in account, or if it has expired. 
  
  Also, it occurs if the JWT token is invalid, not associated with the currently logged in account, or if it has expired.
    ```json
  {
    "status": 403,
    "message": "Invalid OTP code."
  }
  ```
  ```json
  {
    "status": 401,
    "message": "JWT token is invalid."
  }
  ```
  ```json
  {
    "status": 401,
    "message": "JWT token is expired."
  }
  ```
7. **Logging out**
- Endpoint: `/users/sign_out`
- Method: `DELETE`
- Payload: none
- Headers:
```text
Authorization: Bearer [JWT token]
```
- Responses:

  Valid (associated with current account and not expired) JWT token has to be attached to request headers, otherwise request fails.
  - Successful:
  ```json
  {
    "status": 200,
    "message": "Logged out successfully."
  }
  ```
  **Note:** After a successful request, the JWT token is revoked and cannot be used for future requests.
  - Failure:
  Failure occurs if the JWT token is invalid, not associated with the currently logged in account, or if it has expired.
  ```json
  {
    "status": 401,
    "message": "JWT token is invalid."
  }
  ```
  ```json
  {
    "status": 401,
    "message": "JWT token is expired."
  }
  ```