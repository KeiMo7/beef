#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
module BeEF
  module Core
    module Handlers
      # Receipt endpoint for command delivery. The hooked browser POSTs an
      # acknowledgement (instruction received / execution started) here using the
      # same beef.net.send transport and mount dispatch used by every other
      # handler, so no new channel or dependency is introduced.
      #
      # Execution results continue to flow through Commands; the ACK only closes
      # the gap between "sent" and "completed".
      class Acknowledgements
        def initialize(data)
          @data = data
          setup
        end

        def setup
          beefhook = param('beefhook') || param('bh')
          unless BeEF::Filters.is_valid_hook_session_id?(beefhook)
            print_error '[ACK] hook session id is invalid'
            return
          end

          command_id = param('cid')
          unless command_id.is_a?(Integer)
            print_error '[ACK] command id is invalid'
            return
          end

          command = BeEF::DeliveryManager.ack(beefhook, command_id)
          print_error "[ACK] no command #{command_id} for session #{beefhook}" if command.nil?
        end

        def param(key)
          return unless @data.is_a?(Hash) && @data.key?(key)

          value = @data[key]
          value = value.to_i if key == 'cid'
          value
        end
      end
    end
  end
end
