#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#

require 'spec_helper'

RSpec.describe BeEF::Core::Models::SessionEvent do
  it 'persists a lifecycle event bound to a hooked browser' do
    hb = BeEF::Core::Models::HookedBrowser.create!(session: 'evt-sid', ip: '127.0.0.1')
    event = described_class.create!(
      hooked_browser_id: hb.id,
      session: 'evt-sid',
      event_type: 'operator_closed',
      detail: 'closed by alice',
      operator: 'alice',
      date: Time.now
    )

    expect(event).to be_persisted
    expect(event.event_type).to eq('operator_closed')
    expect(event.hooked_browser_id).to eq(hb.id)
  end

  it 'declares the audited event type vocabulary' do
    expect(described_class::TYPES).to include('passive_timeout', 'operator_closed', 'marked_lost')
  end
end
