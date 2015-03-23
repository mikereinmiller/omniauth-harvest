require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Harvest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        :site => 'https://api.harvestapp.com',
        :authorize_url => '/oauth2/authorize',
        :token_url => '/oauth2/token'
      }

      def authorize_params
        super.tap do |params|
          params[:response_type] = "code"
          params[:client_id] = client.id
          params[:redirect_uri] ||= callback_url
        end
      end

      uid { raw_info["user"]["id"] }

      info do
        {
          :email => raw_info["user"]["email"],
          :first_name => raw_info["user"]["first_name"],
          :last_name => raw_info["user"]["last_name"],
          :image => raw_info["user"]["avatar_url"]
        }
      end

      def raw_info
        @raw_info ||= access_token.get("/account/who_am_i.json").parsed
      end

      def request_phase
        super
      end

      def build_access_token
        token_params = {
          :code => request.params['code'],
          :redirect_uri => callback_url,
          :client_id => client.id,
          :client_secret => client.secret,
          :grant_type => 'authorization_code'
        }
        client.get_token(token_params)
      end
    end
  end
end
