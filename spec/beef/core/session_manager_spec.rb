#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#

require 'spec_helper'

RSpec.describe BeEF::SessionManager do
  let(:hb_model) { BeEF::Core::Models::HookedBrowser }
  let(:event_model) { BeEF::Core::Models::SessionEvent }

  describe '.generate_session_id' do
    it 'produces a 64 hex-character opaque identifier' do
      id = described_class.generate_session_id
      expect(id).to match(/\A[0-9a-f]{64}\z/)
    end

    it 'produces unique identifiers across draws' do
      ids = Array.new(100) { described_class.generate_session_id }
      expect(ids.uniq.size).to eq(100)
    end
  end

  describe '.allocate_session_id' do
    it 'returns an identifier that does not collide with existing sessions' do
      hb_model.create!(session: 'taken-session', ip: '10.0.0.1')
      allow(described_class).to receive(:generate_session_id).and_return(
        'taken-session', 'fresh-session'
      )

      expect(described_class.allocate_session_id).to eq('fresh-session')
      expect(event_model.where(event_type: 'identifier_reallocated').count).to eq(1)
    end

    it 'raises after exhausting allocation attempts' do
      allow(described_class).to receive(:generate_session_id).and_return('taken-session')
      hb_model.create!(session: 'taken-session', ip: '10.0.0.1')
      expect { described_class.allocate_session_id }.to raise_error(/unique session identifier/)
    end
  end

  describe '.register_or_restore' do
    it 'creates a brand new session keyed only by its random identifier' do
      hb, outcome = described_class.register_or_restore(session: 'new-id', ip: '10.1.1.1', owner: 'alice')
      expect(outcome).to eq(:created)
      expect(hb.session).to eq('new-id')
      expect(hb).to be_active
      expect(hb.owner).to eq('alice')
      expect(hb.operators_list).to eq(['alice'])
      expect(event_model.where(event_type: 'registered').count).to eq(1)
    end

    it 'distinguishes multiple browsers sharing one egress IP' do
      first, = described_class.register_or_restore(session: 'sid-a', ip: '203.0.113.7')
      second, = described_class.register_or_restore(session: 'sid-b', ip: '203.0.113.7')

      expect(first.session).not_to eq(second.session)
      expect(hb_model.where(ip: '203.0.113.7').count).to eq(2)
    end

    it 'restores the same session when the browser reconnects with its persistent id' do
      original, = described_class.register_or_restore(session: 'sid', persistent_id: 'pid-1', ip: '10.1.1.1')
      original.update!(state: 'closed', close_reason: 'operator')

      restored, outcome = described_class.register_or_restore(session: 'sid', persistent_id: 'pid-1', ip: '10.1.1.9')
      expect(restored.id).to eq(original.id)
      expect(restored).to be_active
      expect(restored.ip).to eq('10.1.1.9')
      expect(outcome).to eq(:revived)
    end

    it 'reconnects a stale session and revives it' do
      hb, = described_class.register_or_restore(session: 'sid-stale', ip: '10.1.1.1')
      hb.update!(state: 'stale', close_reason: 'passive_timeout')

      restored, outcome = described_class.register_or_restore(session: 'sid-stale', ip: '10.1.1.1')
      expect(restored.id).to eq(hb.id)
      expect(restored).to be_active
      expect(outcome).to eq(:reconnected)
    end

    it 'resolves an unknown browser-supplied id via persistent_id after a server restart' do
      original, = described_class.register_or_restore(session: 'sid-mem', persistent_id: 'pid-x', ip: '10.1.1.1')

      # Simulate the server no longer recognising the volatile session id but the
      # browser still holds its localStorage persistent identity.
      restored, = described_class.register_or_restore(session: 'unknown-volatile', persistent_id: 'pid-x', ip: '10.1.1.1')
      expect(restored.id).to eq(original.id)
      expect(restored.persistent_id).to eq('pid-x')
    end
  end

  describe '.sweep_stale' do
    it 'marks only sessions silent beyond the timeout as stale, separately audited' do
      fresh = hb_model.create!(session: 'fresh', ip: '10.0.0.1', lastseen: Time.now.to_i, state: 'active')
      quiet = hb_model.create!(session: 'quiet', ip: '10.0.0.2', lastseen: Time.now.to_i - 999, state: 'active')

      swept = described_class.sweep_stale(300)

      expect(swept.map(&:id)).to eq([quiet.id])
      expect(quiet.reload).to be_stale
      expect(quiet.close_reason).to eq('passive_timeout')
      expect(fresh.reload).to be_active
      expect(event_model.where(event_type: 'passive_timeout').count).to eq(1)
    end
  end

  describe '.close_session' do
    it 'records an operator closure distinct from passive timeouts' do
      hb = hb_model.create!(session: 'to-close', ip: '10.0.0.1', state: 'active')
      described_class.close_session('to-close', 'bob')

      expect(hb.reload).to be_closed
      expect(hb.close_reason).to eq('operator')
      expect(event_model.where(event_type: 'operator_closed').count).to eq(1)
      expect(event_model.where(event_type: 'passive_timeout').count).to eq(0)
    end

    it 'returns nil for an unknown session' do
      expect(described_class.close_session('nope', 'bob')).to be_nil
    end
  end

  describe 'permission model' do
    let(:hb) { hb_model.create!(session: 'perm', ip: '10.0.0.1', role: 'execute', owner: 'alice') }

    it 'lets the owner terminate a session' do
      expect(described_class.permit?(hb, 'alice', :close)).to be(true)
      expect(described_class.effective_role(hb, 'alice')).to eq('owner')
    end

    it 'blocks readonly operators from executing and closing' do
      hb.update!(role: 'readonly')
      expect(described_class.permit?(hb, 'carol', :execute)).to be(false)
      expect(described_class.permit?(hb, 'carol', :view)).to be(true)
    end

    it 'allows execute role to run commands but not close' do
      expect(described_class.permit?(hb, 'carol', :execute)).to be(true)
      expect(described_class.permit?(hb, 'carol', :close)).to be(false)
    end

    it 'attaches collaborating operators without duplicates' do
      described_class.attach_operator(hb, 'carol')
      described_class.attach_operator(hb, 'carol')
      expect(hb.reload.operators_list).to eq(%w[alice carol])
    end
  end

  describe '.stats' do
    it 'counts lifecycle states independently of closure reason' do
      described_class.register_or_restore(session: 'a', ip: '10.0.0.1')
      hb_b, = described_class.register_or_restore(session: 'b', ip: '10.0.0.2')
      described_class.close_session('b', 'alice')
      hb_model.create!(session: 'c', ip: '10.0.0.3', state: 'active', lastseen: Time.now.to_i - 999)
      described_class.sweep_stale(300)

      stats = described_class.stats
      expect(stats[:total]).to eq(3)
      expect(stats[:active]).to eq(1)
      expect(stats[:closed]).to eq(1)
      expect(stats[:stale]).to eq(1)
      expect(stats[:operator_closures]).to eq(1)
      expect(stats[:passive_timeouts]).to be >= 1
      expect(hb_b.id).to be_present
    end
  end
end
