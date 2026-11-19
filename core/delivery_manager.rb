#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
module BeEF
  # Reliable command delivery on top of the existing XHR-poll / WebSocket channels.
  #
  # The transport is unchanged: instructions still ride the hook poll response or
  # the websocket frame. This layer only adds explicit receipts:
  #
  #   pending --send--> sent --ack--> acked --results--> completed
  #                     |
  #                     +--timeout--> pending (bounded retries)
  #                     +--retries exhausted--> failed (session marked lost)
  module DeliveryManager
    HB = BeEF::Core::Models::HookedBrowser
    COMMAND = BeEF::Core::Models::Command
    EVENT = BeEF::Core::Models::SessionEvent

    # Record that an instruction has been put onto the existing channel.
    # The browser is expected to ACK within ack_timeout seconds.
    def self.mark_sent(command, ack_timeout)
      command.delivery_state = 'sent'
      command.attempts = (command.attempts || 0) + 1
      command.sent_at = Time.now
      command.ack_timeout = ack_timeout
      command.next_retry_at = Time.now + ack_timeout
      command.save!
      command
    end

    # Receipt from the browser confirming the instruction was received and began
    # executing. Works for both transports because both already carry cid+beefhook.
    def self.ack(beefhook, command_id)
      hb = HB.where(session: beefhook).first
      return nil if hb.nil?

      command = COMMAND.where(id: command_id, hooked_browser_id: hb.id).first
      return nil if command.nil?

      unless command.completed?
        command.delivery_state = 'acked'
        command.acked_at = Time.now
        command.next_retry_at = nil
        command.save!
        SessionManager.record_event(hb, beefhook, 'delivery_ack',
                                    "cid=#{command.id} acked", nil)
      end
      command
    end

    # Final receipt: the browser executed the instruction and returned results.
    # Invoked from Command.save_result so every existing module gets completion
    # tracking without changing module code.
    def self.mark_completed(command, hooked_browser)
      command.delivery_state = 'completed'
      command.completed_at = Time.now
      command.next_retry_at = nil
      command.save!
      SessionManager.record_event(hooked_browser, hooked_browser.session, 'delivery_completed',
                                  "cid=#{command.id} completed", nil)
      command
    end

    # Sweep instructions whose ACK never arrived. Each gets a bounded number of
    # redelivery attempts; after the last attempt it fails and the owning session
    # is flagged stale (lost) so operators can see which target stopped answering.
    #
    # @param [Integer] max_attempts
    # @return [Hash] { retried: [...], failed: [...] }
    def self.sweep_timeouts(max_attempts)
      now = Time.now
      overdue = COMMAND.where(delivery_state: 'sent')
                       .where('next_retry_at IS NOT NULL AND next_retry_at <= ?', now)
                       .to_a
      summary = { retried: [], failed: [] }

      overdue.each do |command|
        hooked_browser = HB.find_by(id: command.hooked_browser_id)
        if (command.attempts || 0) >= max_attempts
          fail_delivery(command, hooked_browser, summary)
        else
          command.delivery_state = 'pending'
          command.next_retry_at = now
          command.save!
          summary[:retried] << command.id
          SessionManager.record_event(hooked_browser, hooked_browser&.session, 'delivery_failed',
                                      "cid=#{command.id} ack timeout, requeued", nil)
        end
      end
      summary
    end

    def self.fail_delivery(command, hooked_browser, summary = { retried: [], failed: [] })
      command.delivery_state = 'failed'
      command.next_retry_at = nil
      command.save!
      summary[:failed] << command.id

      return unless hooked_browser

      hooked_browser.state = 'stale'
      hooked_browser.close_reason = 'delivery_lost'
      hooked_browser.delivery_failures = (hooked_browser.delivery_failures || 0) + 1
      hooked_browser.save!
      SessionManager.record_event(hooked_browser, hooked_browser.session, 'marked_lost',
                                  "cid=#{command.id} failed after #{command.attempts} attempts", nil)
    end

    # Commands still owed to this browser on its next poll/websocket alive message.
    def self.pending_for(hooked_browser, now = Time.now)
      COMMAND.where(hooked_browser_id: hooked_browser.id, instructions_sent: false)
             .deliverable(now)
             .to_a
    end

    # Drill/report metrics. Delivery success counts only instructions the browser
    # actually executed (results returned), never mere "sent".
    def self.delivery_stats
      all = COMMAND.all.to_a
      by_state = COMMAND::DELIVERY_STATES.to_h { |state| [state, 0] }
      all.each { |c| by_state[c.delivery_state_effective] += 1 }
      delivered = by_state['acked'] + by_state['completed']
      success_rate = all.empty? ? 0.0 : (by_state['completed'].to_f / all.size)
      ack_rate = all.empty? ? 0.0 : (delivered.to_f / all.size)
      {
        total: all.size,
        by_state: by_state,
        acknowledged: delivered,
        completed: by_state['completed'],
        failed: by_state['failed'],
        ack_rate: ack_rate,
        success_rate: success_rate
      }
    end
  end
end
