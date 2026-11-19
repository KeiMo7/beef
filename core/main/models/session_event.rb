#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
module BeEF
  module Core
    module Models
      # Audit trail for session lifecycle events (registration, reconnect,
      # identifier reallocation, active/passive closure, delivery loss).
      # Kept separate from BeEF::Core::Models::Log so loss-rate statistics never
      # mix operator-terminated sessions with passive timeouts.
      class SessionEvent < BeEF::Core::Model
        belongs_to :hooked_browser, optional: true

        TYPES = %w[
          registered
          reconnected
          identifier_reallocated
          operator_closed
          passive_timeout
          marked_lost
          delivery_ack
          delivery_completed
          delivery_failed
          permission_denied
        ].freeze
      end
    end
  end
end
