#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#

# Standalone multi-target drill for the stable session model. Runs against an
# in-memory SQLite database and prints the acceptance record:
#   * session count and lifecycle states
#   * command delivery success rate (completed vs merely sent)
#   * same-egress-IP multi-instance cross-talk check
#
# Usage:
#   bundle exec ruby tools/drill_session_management.rb

require 'securerandom'

ENV['RACK_ENV'] = 'test'
$LOAD_PATH.unshift(File.expand_path('..', __dir__))

# Avoid pulling in the full console/bootstrap; provide the print helpers the
# models call during logging.
def print_debug(_msg); end
def print_info(_msg); end
def print_error(_msg); end

require 'otr-activerecord'
require 'active_record'
require 'erubis'

ActiveRecord::Base.logger = nil
OTR::ActiveRecord.configure_from_hash!(adapter: 'sqlite3', database: ':memory:')
OTR::ActiveRecord.establish_connection!

ActiveRecord::Migration.verbose = false
ActiveRecord::Migrator.migrations_paths = [File.join(__dir__, '..', 'core', 'main', 'ar-migrations')]
context = ActiveRecord::MigrationContext.new(ActiveRecord::Migrator.migrations_paths)
ActiveRecord::Migrator.new(:up, context.migrations, context.schema_migration, context.internal_metadata).migrate

require 'core/core'
require 'core/hbmanager'
require 'core/session_manager'
require 'core/delivery_manager'

# The Logger singleton resolves configuration through the Configuration singleton.
BeEF::Core::Configuration.new(File.expand_path('../config.yaml', __dir__))

HB = BeEF::Core::Models::HookedBrowser
COMMAND = BeEF::Core::Models::Command
mod = BeEF::Core::Models::CommandModule.create!(name: "drill_#{SecureRandom.hex(4)}", path: 'modules/drill/')

shared_ip = '203.0.113.50'

# 5 targets: three machines behind one egress IP, two on distinct IPs.
targets = [
  ['t-alpha', 'pid-alpha', shared_ip],
  ['t-bravo', 'pid-bravo', shared_ip],
  ['t-charlie', 'pid-charlie', shared_ip],
  ['t-delta', 'pid-delta', '198.51.100.9'],
  ['t-echo', 'pid-echo', '198.51.100.10']
].map { |sid, pid, ip| BeEF::SessionManager.register_or_restore(session: sid, persistent_id: pid, ip: ip).first }

# Fire one instruction at every target.
targets.map do |hb|
  COMMAND.create!(hooked_browser_id: hb.id, command_module_id: mod.id,
                  instructions_sent: false, creationdate: Time.now.to_i)
end

# Targets 1-4 poll, ACK and return results. Target 5 goes dark (never ACKs).
responsive = targets.first(4)
responsive.each do |hb|
  BeEF::DeliveryManager.pending_for(hb).each do |cmd|
    BeEF::DeliveryManager.mark_sent(cmd, 60)
    BeEF::DeliveryManager.ack(hb.session, cmd.id)
    COMMAND.save_result(hb.session, cmd.id, 'drill_mod', { 'data' => 'executed' }, 1)
  end
end

dark_cmd = COMMAND.find_by(hooked_browser_id: targets.last.id)
BeEF::DeliveryManager.mark_sent(dark_cmd, 60)
dark_cmd.update!(attempts: 3, next_retry_at: Time.now - 1)
BeEF::DeliveryManager.sweep_timeouts(3)

# Control-plane restart simulation: drop and re-resolve via browser-side id.
restored, restore_outcome =
  BeEF::SessionManager.register_or_restore(session: 't-alpha', persistent_id: 'pid-alpha', ip: shared_ip)

delivery = BeEF::DeliveryManager.delivery_stats
sessions = BeEF::SessionManager.stats
ip_groups = HB.all.group_by(&:ip).transform_values { |list| list.map(&:session) }
cross_talk = ip_groups.values.any? { |sids| sids.size != sids.uniq.size }

report = {
  sessions: sessions,
  delivery: delivery,
  same_ip_multi_instance: {
    shared_ip => ip_groups[shared_ip],
    distinct_sessions_behind_shared_ip: ip_groups[shared_ip].size,
    cross_talk_detected: cross_talk
  },
  restart_recovery: {
    session: 't-alpha',
    restored_to_same_row: restored.session == 't-alpha',
    outcome: restore_outcome
  }
}

puts JSON.pretty_generate(report)
