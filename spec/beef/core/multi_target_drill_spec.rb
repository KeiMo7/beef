#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#

require 'spec_helper'

# End-to-end style exercise of the stable session model for a multi-target drill.
# It drives the same service objects the HTTP/WebSocket handlers call, including
# the shared-egress-IP scenario that caused cross-talk in the coarse pool model.
RSpec.describe 'multi-target drill', type: :model do
  let(:hb_model) { BeEF::Core::Models::HookedBrowser }
  let(:command_model) { BeEF::Core::Models::Command }

  before do
    # The Logger is a singleton; neutralise any Notifications double leaked by an
    # earlier spec so save_result logging stays isolated.
    BeEF::Core::Logger.instance.instance_variable_set(:@notifications, nil)
  end

  let(:mod) { BeEF::Core::Models::CommandModule.create!(name: "drill_#{SecureRandom.hex(4)}", path: 'modules/drill/') }
  let(:shared_ip) { '203.0.113.50' }

  def fire_command(hooked_browser)
    command_model.create!(
      hooked_browser_id: hooked_browser.id, command_module_id: mod.id,
      instructions_sent: false, creationdate: Time.now.to_i
    )
  end

  it 'keeps every target distinct and reports delivery accuracy without cross-talk' do
    # Three controlled machines, two of them behind the same egress IP.
    target_a, = BeEF::SessionManager.register_or_restore(session: 'target-a', persistent_id: 'pid-a', ip: shared_ip)
    target_b, = BeEF::SessionManager.register_or_restore(session: 'target-b', persistent_id: 'pid-b', ip: shared_ip)
    target_c, = BeEF::SessionManager.register_or_restore(session: 'target-c', persistent_id: 'pid-c', ip: '198.51.100.9')

    expect(hb_model.where(ip: shared_ip).map(&:session).sort).to eq(%w[target-a target-b])
    expect(hb_model.all.map(&:session).uniq.size).to eq(3)

    # One instruction per target.
    [target_a, target_b, target_c].each { |hooked_browser| fire_command(hooked_browser) }

    # Simulate the poll/websocket-alive delivery + browser ACK + result return
    # for the first two targets; the third goes dark and never acknowledges.
    [target_a, target_b].each do |hb|
      BeEF::DeliveryManager.pending_for(hb).each do |cmd|
        BeEF::DeliveryManager.mark_sent(cmd, 60)
        BeEF::DeliveryManager.ack(hb.session, cmd.id)
        command_model.save_result(
          hb.session, cmd.id, 'drill_mod',
          { 'data' => 'executed' }, 1
        )
      end
    end

    fire_command(target_c)
    dark = command_model.where(hooked_browser_id: target_c.id).order(:id).last
    BeEF::DeliveryManager.mark_sent(dark, 60)
    dark.update!(attempts: 3, next_retry_at: Time.now - 1)

    # Reaper eventually gives up on the dark target and flags it lost.
    BeEF::DeliveryManager.sweep_timeouts(3)

    # ---- Assertions mirroring the drill acceptance criteria ----

    # 1. No cross-talk: each completed command stays bound to its own target.
    completed_a = command_model.where(hooked_browser_id: target_a.id, delivery_state: 'completed')
    completed_b = command_model.where(hooked_browser_id: target_b.id, delivery_state: 'completed')
    expect(completed_a.count).to eq(1)
    expect(completed_b.count).to eq(1)
    expect(completed_a.pluck(:id) & completed_b.pluck(:id)).to be_empty

    # 2. The dark target's instruction failed and the session is marked lost.
    expect(dark.reload).to be_failed
    expect(target_c.reload).to be_stale

    # 3. Drill report numbers.
    delivery = BeEF::DeliveryManager.delivery_stats
    expect(delivery[:total]).to eq(4)
    expect(delivery[:completed]).to eq(2)
    expect(delivery[:failed]).to eq(1)
    expect(delivery[:success_rate]).to eq(0.5)

    sessions = BeEF::SessionManager.stats
    expect(sessions[:total]).to eq(3)
    expect(sessions[:active]).to eq(2)
    expect(sessions[:stale]).to eq(1)

    # 4. Same-IP multi-instance grouping proves distinct sessions, no merging.
    groups = hb_model.where(ip: shared_ip).group(:session).count
    expect(groups.keys.size).to eq(2)
  end

  it 'recovers sessions across a control-plane restart using browser-side identity' do
    original, = BeEF::SessionManager.register_or_restore(session: 'volatile-sid', persistent_id: 'stable-pid', ip: shared_ip)

    # Control plane restart: the in-memory websocket table is gone, but the browser
    # still holds its localStorage persistent id and reconnects.
    restored, outcome = BeEF::SessionManager.register_or_restore(
      session: 'volatile-sid', persistent_id: 'stable-pid', ip: shared_ip
    )
    expect(restored.id).to eq(original.id)
    expect(outcome).to eq(:restored)
    expect(BeEF::Core::Models::SessionEvent.where(event_type: %w[registered reconnected revived]).count).to be >= 1
  end

  it 'keeps operator closures out of the passive loss-rate count' do
    _hb, = BeEF::SessionManager.register_or_restore(session: 'manual', ip: shared_ip)
    BeEF::SessionManager.close_session('manual', 'alice')

    quiet, = BeEF::SessionManager.register_or_restore(session: 'quiet', ip: '198.51.100.10')
    quiet.update!(lastseen: Time.now.to_i - 999, state: 'active')
    BeEF::SessionManager.sweep_stale(300)

    stats = BeEF::SessionManager.stats
    expect(stats[:operator_closures]).to eq(1)
    expect(stats[:passive_timeouts]).to eq(1)
    expect(stats[:stale]).to eq(1)
    expect(stats[:closed]).to eq(1)
  end
end
