#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
module BeEF
  module Core
    module Handlers
      # Mounts the acknowledgement endpoint on the existing hook HTTP server.
      module RegisterSessionHandler
        BeEF::API::Registrar.instance.register(
          BeEF::Core::Handlers::RegisterSessionHandler,
          BeEF::API::Server,
          'mount_handler'
        )

        def self.mount_handler(beef_server)
          beef_server.mount('/ack', BeEF::Core::Handlers::Acknowledgements)
        end
      end

      # Background maintenance: passive session cleanup and delivery-timeout sweeps.
      # Disabled by default; enabled via beef.session_management.enable so the legacy
      # session model is untouched unless an operator opts in.
      module SessionReaper
        BeEF::API::Registrar.instance.register(
          BeEF::Core::Handlers::SessionReaper,
          BeEF::API::Server,
          'pre_http_start'
        )

        def self.config
          BeEF::Core::Configuration.instance
        end

        def self.enabled?
          config.get('beef.session_management.enable') == true
        end

        def self.pre_http_start(_server)
          return unless enabled?

          interval = config.get('beef.session_management.reap_interval').to_i
          timeout = config.get('beef.session_management.session_timeout').to_i
          max_attempts = config.get('beef.session_management.max_delivery_attempts').to_i

          Thread.new do
            loop do
              sleep interval
              begin
                BeEF::SessionManager.sweep_stale(timeout)
                BeEF::DeliveryManager.sweep_timeouts(max_attempts)
              rescue StandardError => e
                print_error "[SessionReaper] sweep failed: #{e.message}"
              end
            end
          end
        end
      end
    end
  end
end
