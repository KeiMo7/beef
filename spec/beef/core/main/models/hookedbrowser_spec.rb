#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#

require 'spec_helper'

RSpec.describe BeEF::Core::Models::HookedBrowser do
  describe 'associations' do
    it 'has_many commands' do
      expect(described_class.reflect_on_association(:commands)).not_to be_nil
      expect(described_class.reflect_on_association(:commands).macro).to eq(:has_many)
    end

    it 'has_many results' do
      expect(described_class.reflect_on_association(:results)).not_to be_nil
      expect(described_class.reflect_on_association(:results).macro).to eq(:has_many)
    end

    it 'has_many logs' do
      expect(described_class.reflect_on_association(:logs)).not_to be_nil
      expect(described_class.reflect_on_association(:logs).macro).to eq(:has_many)
    end
  end

  describe '#count!' do
    it 'sets count to 1 when count is nil' do
      hb = described_class.create!(session: 'count_nil', ip: '127.0.0.1', count: nil)

      hb.count!

      expect(hb.count).to eq(1)
    end

    it 'increments count when count is already set' do
      hb = described_class.create!(session: 'count_set', ip: '127.0.0.1', count: 3)

      hb.count!

      expect(hb.count).to eq(4)
    end
  end

  describe 'lifecycle columns' do
    it 'defaults to the active legacy state' do
      hb = described_class.create!(session: 'lifecycle', ip: '127.0.0.1')
      expect(hb.effective_state).to eq('active')
      expect(hb).to be_active
    end

    it 'tracks stale and closed states' do
      hb = described_class.create!(session: 'states', ip: '127.0.0.1', state: 'stale')
      expect(hb).to be_stale
      hb.update!(state: 'closed')
      expect(hb.reload).to be_closed
    end

    it 'serializes the operator list as json' do
      hb = described_class.create!(session: 'owners', ip: '127.0.0.1', owner: 'alice')
      hb.operators_list = %w[alice bob]
      hb.save!
      expect(hb.reload.operators_list).to eq(%w[alice bob])
    end

    it 'tolerates malformed operator json' do
      hb = described_class.create!(session: 'bad-json', ip: '127.0.0.1', operators: 'not-json')
      expect(hb.operators_list).to eq([])
    end
  end
end
