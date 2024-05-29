Rails.application.routes.draw do
  devise_for :users,
  controllers: {
    sessions: 'users/sessions',
    registrations: 'users/registrations'
  }

  get 'users/enable_otp_show_qr', to: 'users#enable_otp_show_qr', as: 'enable_otp_show_qr'
  post 'users/otp', to: 'users#verify_otp', as: 'verify_user_otp'
  post 'verify_otp', to: 'users/sessions#verify_otp'
  post 'users/enable_otp_verify', to: 'users#enable_otp_verify', as: 'enable_otp_verify'
  post 'users/disable_otp_verify', to: 'users#disable_otp_verify', as: 'disable_otp_verify'
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
