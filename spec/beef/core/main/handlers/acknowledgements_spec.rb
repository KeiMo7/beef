#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#

require 'spec_helper'

RSpec.describe BeEF::Core::Handlers::Acknowledgements do
  let(:hb) { BeEF::Core::Models::HookedBrowser.create!(session: 'ack-sid', ip: '10.0.0.1') }
  let(:mod) { BeEF::Core::Models::CommandModule.create!(name: "ack_mod_#{SecureRandom.hex(4)}", path: 'modules/test/') }
  let(:command) do
    BeEF::Core::Models::Command.create!(
      hooked_browser_id: hb.id, command_module_id: mod.id,
      delivery_state: 'sent', creationdate: Time.now.to_i
    )
  end

  it 'acks a command using the beefhook/cid envelope (XHR path)' do
    described_class.new('beefhook' => 'ack-sid', 'cid' => command.id)
    expect(command.reload).to be_acked
  end

  it 'accepts the websocket envelope (bh key)' do
    described_class.new('bh' => 'ack-sid', 'cid' => command.id)
    expect(command.reload).to be_acked
  end

  it 'rejects an invalid session id without raising' do
    allow(BeEF::Filters).to receive(:is_valid_hook_session_id?).and_return(false)
    expect { described_class.new('beefhook' => 'bad', 'cid' => command.id) }.not_to raise_error
    expect(command.reload).to be_sent
  end

  it 'rejects a non-integer command id' do
    expect { described_class.new('beefhook' => 'ack-sid', 'cid' => 'nope') }.not_to raise_error
    expect(command.reload).to be_sent
  end

  it 'silently ignores an unknown command' do
    expect { described_class.new('beefhook' => 'ack-sid', 'cid' => 999_999) }.not_to raise_error
  end
end
