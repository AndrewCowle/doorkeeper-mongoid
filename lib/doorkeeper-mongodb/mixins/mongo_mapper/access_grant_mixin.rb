module DoorkeeperMongodb
  module Mixins
    module MongoMapper
      module AccessGrantMixin
        extend ActiveSupport::Concern

        include Doorkeeper::OAuth::Helpers
        include Doorkeeper::Models::Expirable
        include Doorkeeper::Models::Revocable
        include Doorkeeper::Models::Accessible
        include Doorkeeper::Models::Scopes
        include BaseMixin

        included do
          belongs_to :application, class_name: 'Doorkeeper::Application'

          validates :resource_owner_id, :application_id, :token, :expires_in, :redirect_uri, presence: true
          validates :token, uniqueness: true

          before_validation :generate_token, on: :create
        end
        def uses_pkce?
          pkce_supported? && code_challenge.present?
        end
    
        def pkce_supported?
          respond_to? :code_challenge
        end

        module ClassMethods
          # Searches for Doorkeeper::AccessGrant record with the
          # specific token value.
          #
          # @param token [#to_s] token value (any object that responds to `#to_s`)
          #
          # @return [Doorkeeper::AccessGrant, nil] AccessGrant object or nil
          #   if there is no record with such token
          #
          def by_token(token)
            where(token: token.to_s).first
          end

          def pkce_supported?
            respond_to? :code_challenge
          end

          def generate_code_challenge(code_verifier)
            padded_result = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier))
            padded_result.split('=')[0] # Remove any trailing '='
          end
    
          def pkce_supported?
            new.pkce_supported?
          end
          
        end

        private

        # Generates token value with UniqueToken class.
        #
        # @return [String] token value
        #
        def generate_token
          self.token = UniqueToken.generate
        end
      end
    end
  end
end
