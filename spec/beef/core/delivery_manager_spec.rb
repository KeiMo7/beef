#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#

require 'spec_helper'

RSpec.describe BeEF::DeliveryManager do
  let(:hb_model) { BeEF::Core::Models::HookedBrowser }
  let(:command_model) { BeEF::Core::Models::Command }

  let(:hb) { hb_model.create!(session: 'deliver-sid', ip: '10.0.0.1', state: 'active') }
  let(:mod) { BeEF::Core::Models::CommandModule.create!(name: "mod_#{SecureRandom.hex(4)}", path: 'modules/test/') }

  before do
    # Neutralise any Notifications double leaked into the Logger singleton by an
    # earlier spec so completion logging stays isolated under random ordering.
    BeEF::Core::Logger.instance.instance_variable_set(:@notifications, nil)
  end

  def make_command
    command_model.create!(
      hooked_browser_id: hb.id,
      command_module_id: mod.id,
      instructions_sent: false,
      creationdate: Time.now.to_i
    )
  end

  describe '.mark_sent' do
    it 'moves a pending instruction to sent with an ack deadline' do
      command = make_command
      described_class.mark_sent(command, 60)

      expect(command.reload).to be_sent
      expect(command.attempts).to eq(1)
      expect(command.sent_at).not_to be_nil
      expect(command.next_retry_at).to be > Time.now
    end
  end

  describe '.ack' do
    it 'records a receipt from the browser' do
      command = make_command
      described_class.mark_sent(command, 60)

      acked = described_class.ack('deliver-sid', command.id)
      expect(acked.reload).to be_acked
      expect(acked.acked_at).not_to be_nil
      expect(acked.next_retry_at).to be_nil
    end

    it 'ignores an unknown session or command' do
      expect(described_class.ack('ghost', 999)).to be_nil
    end
  end

  describe '.mark_completed' do
    it 'marks the instruction completed once results are returned' do
      command = make_command
      described_class.mark_sent(command, 60)
      described_class.ack('deliver-sid', command.id)

      described_class.mark_completed(command.reload, hb)
      expect(command.reload).to be_completed
      expect(command.completed_at).not_to be_nil
    end
  end

  describe '.sweep_timeouts' do
    it 'requeues an unacknowledged instruction while attempts remain' do
      command = make_command
      described_class.mark_sent(command, 60)
      command.update!(next_retry_at: Time.now - 1)

      summary = described_class.sweep_timeouts(3)
      expect(summary[:retried]).to include(command.id)
      expect(command.reload).to be_pending
    end

    it 'fails and marks the session lost after exhausting attempts' do
      command = make_command
      described_class.mark_sent(command, 60)
      command.update!(attempts: 3, next_retry_at: Time.now - 1)

      summary = described_class.sweep_timeouts(3)
      expect(summary[:failed]).to include(command.id)
      expect(command.reload).to be_failed
      expect(hb.reload).to be_stale
      expect(hb.close_reason).to eq('delivery_lost')
      expect(BeEF::Core::Models::SessionEvent.where(event_type: 'marked_lost').count).to eq(1)
    end

    it 'leaves acknowledged instructions untouched' do
      command = make_command
      described_class.mark_sent(command, 60)
      described_class.ack('deliver-sid', command.id)
      command.update!(next_retry_at: Time.now - 1)

      summary = described_class.sweep_timeouts(3)
      expect(summary[:retried]).to be_empty
      expect(command.reload).to be_acked
    end
  end

  describe '.pending_for' do
    it 'only returns instructions still owed to the browser' do
      pending_cmd = make_command
      delivered = make_command
      described_class.mark_sent(delivered, 60)
      described_class.ack('deliver-sid', delivered.id)

      list = described_class.pending_for(hb)
      expect(list.map(&:id)).to include(pending_cmd.id)
      expect(list.map(&:id)).not_to include(delivered.id)
    end
  end

  describe '.delivery_stats' do
    it 'reports success based on completed instructions, not merely sent' do
      ok = make_command
      described_class.mark_sent(ok, 60)
      described_class.ack('deliver-sid', ok.id)
      described_class.mark_completed(ok.reload, hb)

      lost = make_command
      described_class.mark_sent(lost, 60)
      lost.update!(attempts: 3, next_retry_at: Time.now - 1, delivery_state: 'failed')

      stats = described_class.delivery_stats
      expect(stats[:total]).to eq(2)
      expect(stats[:completed]).to eq(1)
      expect(stats[:failed]).to eq(1)
      expect(stats[:success_rate]).to eq(0.5)
    end

    it 'returns zeroed metrics when there are no commands' do
      expect(described_class.delivery_stats[:success_rate]).to eq(0.0)
    end
  end
end
