#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
require 'securerandom'

module BeEF
  # Stable, unique identity and lifecycle management for hooked browser sessions.
  #
  # The identifier is an opaque random token with no internal structure: it does
  # not encode the IP, fingerprint or database id. It is generated once, persisted
  # on the browser side (localStorage + cookies), and reused on reconnect so a
  # control-plane restart never orphans the browser. Multiple browsers behind the
  # same egress IP, or browsers with near-identical fingerprints, remain distinct.
  module SessionManager
    HB = BeEF::Core::Models::HookedBrowser
    EVENT = BeEF::Core::Models::SessionEvent

    # 32 random bytes rendered as 64 hex characters.
    SESSION_ID_BYTES = 32
    # Bounded retry when an improbable identifier collision occurs.
    MAX_ALLOCATION_ATTEMPTS = 5

    # Generate a fresh, unguessable session identifier.
    def self.generate_session_id
      SecureRandom.hex(SESSION_ID_BYTES)
    end

    # Allocate an identifier that is unique in the sessions table. On collision the
    # identifier is reallocated and the event is recorded for auditability.
    def self.allocate_session_id
      attempts = 0
      loop do
        candidate = generate_session_id
        return candidate unless HB.exists?(session: candidate)

        attempts += 1
        record_event(nil, candidate, 'identifier_reallocated',
                     "collision on allocation (attempt #{attempts})", nil)
        raise 'could not allocate a unique session identifier' if attempts >= MAX_ALLOCATION_ATTEMPTS
      end
    end

    # Resolve a reconnecting browser to a stable session.
    #
    # * a known session id  -> the existing row is touched and marked active again
    # * an unknown id        -> a brand new session is created (never keyed by IP/fingerprint)
    # * a closed session id   -> revived: the same browser keeps its identity and history
    #
    # @param [Hash] attrs :session, :persistent_id, :ip, plus optional ownership keys
    # @return [Array<HookedBrowser, Symbol>] the session and one of
    #   :restored, :reconnected, :revived, :created, :reallocated
    def self.register_or_restore(attrs = {})
      session_id = attrs[:session]
      hooked_browser = session_id && HB.where(session: session_id).first

      hooked_browser = HB.where(persistent_id: attrs[:persistent_id]).order(:id).first if hooked_browser.nil? && attrs[:persistent_id]

      if hooked_browser
        previous_state = hooked_browser.effective_state
        hooked_browser.state = 'active'
        hooked_browser.close_reason = nil
        hooked_browser.lastseen = Time.now.to_i
        hooked_browser.ip = attrs[:ip] if attrs[:ip]
        hooked_browser.persistent_id ||= attrs[:persistent_id] || session_id
        hooked_browser.save!

        outcome = case previous_state
                  when 'closed' then :revived
                  when 'stale' then :reconnected
                  else :restored
                  end
        record_event(hooked_browser, hooked_browser.session, outcome.to_s,
                     "session resolved for ip=#{attrs[:ip]}", attrs[:operator])
        return [hooked_browser, outcome]
      end

      new_sid = session_id.nil? ? allocate_session_id : resolve_unknown_identifier(session_id)
      hooked_browser = HB.create!(
        session: new_sid,
        persistent_id: attrs[:persistent_id] || new_sid,
        ip: attrs[:ip],
        firstseen: Time.now.to_i,
        lastseen: Time.now.to_i,
        state: 'active',
        owner: attrs[:owner],
        role: attrs[:role] || 'execute',
        operators_list: attrs[:owner] ? [attrs[:owner]] : []
      )
      record_event(hooked_browser, new_sid, 'registered', "new session for ip=#{attrs[:ip]}", attrs[:owner])
      [hooked_browser, new_sid == session_id ? :created : :reallocated]
    end

    # An identifier supplied by the browser that the server does not recognise.
    # Normally it is accepted as a fresh, client-generated id; a collision triggers
    # server-side reallocation and an audit record instead of silent merging.
    def self.resolve_unknown_identifier(session_id)
      return session_id unless HB.exists?(session: session_id)

      replacement = allocate_session_id
      record_event(nil, session_id, 'identifier_reallocated',
                   'client-supplied identifier collided; reallocated server-side', nil)
      replacement
    end

    # Mark the browser as seen. Reused by both the XHR poll and websocket alive path.
    def self.touch(hooked_browser, ip = nil)
      if hooked_browser.respond_to?(:stale?) && hooked_browser.stale?
        hooked_browser.state = 'active'
        hooked_browser.close_reason = nil
      end
      hooked_browser.lastseen = Time.now.to_i
      hooked_browser.ip = ip if ip
      hooked_browser.save!
      hooked_browser
    end

    # Operator-initiated termination. Recorded separately from passive timeouts so
    # loss-rate statistics never count manual closures as lost sessions.
    def self.close_session(session_id, operator, reason = 'operator')
      hooked_browser = HB.where(session: session_id).first
      return nil if hooked_browser.nil?

      hooked_browser.state = 'closed'
      hooked_browser.close_reason = reason
      hooked_browser.save!
      record_event(hooked_browser, session_id, 'operator_closed', "closed by #{operator}", operator)
      hooked_browser
    end

    # Passive cleanup: sessions silent for longer than the timeout are flagged stale.
    # Rows are retained for audit; the REST delete endpoint still performs hard removal.
    #
    # @return [Array<HookedBrowser>] the sessions marked stale in this sweep
    def self.sweep_stale(timeout_seconds)
      cutoff = Time.now.to_i - timeout_seconds.to_i
      stale = HB.where(state: ['active', nil]).where('lastseen < ?', cutoff).to_a
      stale.each do |hooked_browser|
        hooked_browser.state = 'stale'
        hooked_browser.close_reason = 'passive_timeout'
        hooked_browser.save!
        record_event(hooked_browser, hooked_browser.session, 'passive_timeout',
                     "no traffic for #{timeout_seconds}s", nil)
      end
    end

    # Permission model. Roles are hierarchical:
    # readonly < execute < owner. The owner can terminate the session.
    PERMISSIONS = {
      'readonly' => %i[view],
      'execute' => %i[view execute],
      'owner' => %i[view execute close]
    }.freeze

    def self.permit?(hooked_browser, operator, action)
      role = effective_role(hooked_browser, operator)
      PERMISSIONS.fetch(role, []).include?(action)
    end

    def self.effective_role(hooked_browser, operator)
      return 'owner' if operator && hooked_browser.owner == operator

      hooked_browser.role || 'execute'
    end

    # Grant another operator access and record the collaboration change.
    def self.attach_operator(hooked_browser, operator)
      list = hooked_browser.operators_list
      list << hooked_browser.owner if hooked_browser.owner && !list.include?(hooked_browser.owner)
      unless list.include?(operator)
        list << operator
        hooked_browser.operators_list = list
        hooked_browser.save!
      end
      hooked_browser
    end

    # Aggregate metrics used by drill reports. Active/passive/operator closures
    # are counted independently so the loss rate only reflects passive timeouts
    # and delivery failures.
    def self.stats
      all = HB.all.to_a
      passive = EVENT.where(event_type: 'passive_timeout').count
      manual = EVENT.where(event_type: 'operator_closed').count
      lost = HB.where(state: 'stale').count
      {
        total: all.size,
        active: all.count(&:active?),
        stale: all.count(&:stale?),
        closed: all.count(&:closed?),
        passive_timeouts: passive,
        operator_closures: manual,
        lost_rate: all.empty? ? 0.0 : lost.to_f / all.size
      }
    end

    def self.record_event(hooked_browser, session_id, event_type, detail, operator)
      EVENT.create!(
        hooked_browser_id: hooked_browser&.id,
        session: session_id,
        event_type: event_type,
        detail: detail,
        operator: operator,
        date: Time.now
      )
    end
  end
end
