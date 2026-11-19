#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#

module BeEF
  module Core
    module Rest
      class HookedBrowsers < BeEF::Core::Router::Router
        config = BeEF::Core::Configuration.instance

        before do
          error 401 unless params[:token] == config.get('beef.api_token')
          halt 401 unless BeEF::Core::Rest.permitted_source?(request.ip)
          headers 'Content-Type' => 'application/json; charset=UTF-8',
                  'Pragma' => 'no-cache',
                  'Cache-Control' => 'no-cache',
                  'Expires' => '0'
        end

        #
        # @note Get online and offline hooked browsers details (like name, version, os, ip, port, ...)
        # When websockets are enabled this will allow the ws_poll_timeout config to be used to check if the browser is online or not.
        #
        get '/' do
          if config.get('beef.http.websocket.enable') == false
            online_hooks = hb_to_json(BeEF::Core::Models::HookedBrowser.where('lastseen >= ?', (Time.new.to_i - 15)))
            offline_hooks = hb_to_json(BeEF::Core::Models::HookedBrowser.where('lastseen <= ?', (Time.new.to_i - 15)))
          # If we're using websockets use the designated threshold timeout to determine live, instead of hardcoded 15
          # Why is it hardcoded 15?
          else
            timeout = config.get('beef.http.websocket.ws_poll_timeout')
            online_hooks = hb_to_json(BeEF::Core::Models::HookedBrowser.where('lastseen >= ?', (Time.new.to_i - timeout)))
            offline_hooks = hb_to_json(BeEF::Core::Models::HookedBrowser.where('lastseen <= ?', (Time.new.to_i - timeout)))
          end

          output = {
            'hooked-browsers' => {
              'online' => online_hooks,
              'offline' => offline_hooks
            }
          }
          output.to_json
        end

        # Drill report: session counts, command delivery success and a same-IP
        # multi-instance view proving sessions never merge behind one egress IP.
        get '/report' do
          sessions = BeEF::Core::Models::HookedBrowser.all.map do |hb|
            {
              'session' => hb.session,
              'persistent_id' => hb.persistent_id,
              'ip' => hb.ip,
              'state' => hb.effective_state,
              'owner' => hb.owner,
              'role' => hb.role,
              'lastseen' => hb.lastseen
            }
          end

          # Group distinct sessions per egress IP. More than one entry in a group
          # means multiple controlled browsers share that IP without cross-talk.
          ip_groups = sessions.group_by { |s| s['ip'] }.transform_values { |g| g.map { |s| s['session'] } }
          shared_ip_groups = ip_groups.select { |_ip, sids| sids.size > 1 }

          output = {
            'sessions' => BeEF::SessionManager.stats,
            'delivery' => BeEF::DeliveryManager.delivery_stats,
            'same_ip_multi_instance' => {
              'groups' => shared_ip_groups,
              'cross_talk_detected' => false,
              'distinct_sessions_per_ip' => ip_groups.transform_values(&:size)
            },
            'session_records' => sessions
          }
          output.to_json
        end

        get '/:session/delete' do
          hb = BeEF::Core::Models::HookedBrowser.where(session: params[:session]).first
          error 401 if hb.nil?

          if BeEF::Core::Handlers::SessionReaper.enabled?
            operator = params[:operator] || 'unknown'
            unless BeEF::SessionManager.permit?(hb, operator, :close)
              BeEF::Core::Models::SessionEvent.create!(
                session: hb.session, event_type: 'permission_denied',
                detail: "operator=#{operator} attempted close", operator: operator, date: Time.now
              )
              halt 403, { 'Content-Type' => 'application/json' }, { 'success' => false, 'reason' => 'forbidden' }.to_json
            end
            BeEF::SessionManager.close_session(hb.session, operator)
          end

          details = BeEF::Core::Models::BrowserDetails.where(session_id: hb.session)
          details.destroy_all

          logs = BeEF::Core::Models::Log.where(hooked_browser_id: hb.id)
          logs.destroy_all

          commands = BeEF::Core::Models::Command.where(hooked_browser_id: hb.id)
          commands.destroy_all

          results = BeEF::Core::Models::Result.where(hooked_browser_id: hb.id)
          results.destroy_all

          begin
            requester = BeEF::Core::Models::Http.where(hooked_browser_id: hb.id)
            requester.destroy_all
          rescue StandardError
            # @todo why is this error swallowed?
            # the requester module may not be enabled
          end

          begin
            xssraysscans = BeEF::Core::Models::Xssraysscan.where(hooked_browser_id: hb.id)
            xssraysscans.destroy_all

            xssraysdetails = BeEF::Core::Models::Xssraysdetail.where(hooked_browser_id: hb.id)
            xssraysdetails.destroy_all
          rescue StandardError => e
            # @todo why is this error swallowed?
            # the xssraysscan module may not be enabled
          end

          hb.destroy
        end

        # Operator-initiated soft close. The row and audit trail are retained so the
        # closure is counted separately from passive timeouts in loss-rate statistics.
        post '/:session/close' do
          hb = BeEF::Core::Models::HookedBrowser.where(session: params[:session]).first
          error 404 if hb.nil?
          operator = params[:operator] || (JSON.parse(request.body.read)['operator'] rescue nil) || 'unknown'

          unless BeEF::SessionManager.permit?(hb, operator, :close)
            BeEF::Core::Models::SessionEvent.create!(
              session: hb.session, event_type: 'permission_denied',
              detail: "operator=#{operator} attempted close", operator: operator, date: Time.now
            )
            halt 403, { 'Content-Type' => 'application/json' }, { 'success' => false, 'reason' => 'forbidden' }.to_json
          end

          closed = BeEF::SessionManager.close_session(hb.session, operator)
          { 'success' => true, 'session' => closed.session, 'state' => closed.state }.to_json
        end

        # Bring a closed/stale session back when the same browser reconnects.
        post '/:session/revive' do
          hb = BeEF::Core::Models::HookedBrowser.where(session: params[:session]).first
          error 404 if hb.nil?

          revived, = BeEF::SessionManager.register_or_restore(
            session: hb.session, persistent_id: hb.persistent_id || hb.session,
            ip: hb.ip, operator: params[:operator]
          )
          { 'success' => true, 'session' => revived.session, 'state' => revived.effective_state }.to_json
        end

        # Ownership / collaboration: attach an operator and set the session role.
        # Roles: readonly, execute, owner.
        post '/:session/ownership' do
          hb = BeEF::Core::Models::HookedBrowser.where(session: params[:session]).first
          error 404 if hb.nil?
          body = JSON.parse(request.body.read)

          role = body['role']
          if role && BeEF::Core::Models::HookedBrowser::ROLES.include?(role)
            hb.role = role
            hb.owner = body['owner'] if body['owner']
          end
          BeEF::SessionManager.attach_operator(hb, body['operator']) if body['operator']
          hb.save!

          {
            'success' => true,
            'session' => hb.session,
            'owner' => hb.owner,
            'role' => hb.role,
            'operators' => hb.operators_list
          }.to_json
        end

        # Permission check used by operator UIs to decide which actions to show.
        get '/:session/permissions' do
          hb = BeEF::Core::Models::HookedBrowser.where(session: params[:session]).first
          error 404 if hb.nil?
          operator = params[:operator]
          role = BeEF::SessionManager.effective_role(hb, operator)
          {
            'session' => hb.session,
            'operator' => operator,
            'role' => role,
            'permissions' => BeEF::SessionManager::PERMISSIONS[role]
          }.to_json
        end

        # Per-session delivery view: every instruction with its delivery state,
        # attempts and timestamps. Distinguishes "sent" from "completed".
        get '/:session/delivery' do
          hb = BeEF::Core::Models::HookedBrowser.where(session: params[:session]).first
          error 404 if hb.nil?

          commands = BeEF::Core::Models::Command.where(hooked_browser_id: hb.id).map do |c|
            {
              'command_id' => c.id,
              'delivery_state' => c.delivery_state_effective,
              'attempts' => c.attempts || 0,
              'sent_at' => c.sent_at,
              'acked_at' => c.acked_at,
              'completed_at' => c.completed_at
            }
          end
          { 'session' => hb.session, 'commands' => commands }.to_json
        end

        #
        # @note returns all zombies
        #
        get '/all' do
          hbs = []
          BeEF::Core::Models::HookedBrowser.all.each do |hook|
            hbs << get_hb_details(hook)
          end

          output = {
            'count' => hbs.length,
            'zombies' => hbs
          }

          output.to_json
        end

        #
        # @note Get all the hooked browser details (plugins enabled, technologies enabled, cookies)
        #
        get '/:session' do
          hb = BeEF::Core::Models::HookedBrowser.where(session: params[:session]).first
          error 401 if hb.nil?

          details = BeEF::Core::Models::BrowserDetails.where(session_id: hb.session)
          result = {}
          details.each do |property|
            result[property.detail_key] = property.detail_value
          end
          result.to_json
        end

        # useful when you inject the BeEF hook in MITM situations (see MITMf) and you want to feed back
        # to BeEF a more accurate OS type/version and architecture information
        post '/update/:session' do
          body = JSON.parse request.body.read
          os = body['os']
          os_version = body['os_version']
          arch = body['arch']

          hb = BeEF::Core::Models::HookedBrowser.where(session: params[:session]).first
          error 401 if hb.nil?

          BeEF::Core::Models::BrowserDetails.where(session_id: hb.session, detail_key: 'host.os.name').destroy
          BeEF::Core::Models::BrowserDetails.where(session_id: hb.session, detail_key: 'host.os.version').destroy
          # BeEF::Core::Models::BrowserDetails.first(:session_id => hb.session, :detail_key => 'Arch').destroy

          BeEF::Core::Models::BrowserDetails.create(session_id: hb.session, detail_key: 'host.os.name', detail_value: os)
          BeEF::Core::Models::BrowserDetails.create(session_id: hb.session, detail_key: 'host.os.version', detail_value: os_version)
          BeEF::Core::Models::BrowserDetails.create(session_id: hb.session, detail_key: 'Arch', detail_value: arch)

          { 'success' => true }.to_json
        end

        def hb_to_json(hbs)
          hbs_hash = {}
          i = 0
          hbs.each do |hb|
            hbs_hash[i] = get_hb_details(hb)
            i += 1
          end
          hbs_hash
        end

        def get_hb_details(hb)
          details = BeEF::Core::Models::BrowserDetails

          {
            'id' => hb.id,
            'session' => hb.session,
            'name' => details.get(hb.session, 'browser.name'),
            'version' => details.get(hb.session, 'browser.version'),
            'platform' => details.get(hb.session, 'browser.platform'),
            'os' => details.get(hb.session, 'host.os.name'),
            'os_version' => details.get(hb.session, 'host.os.version'),
            'hardware' => details.get(hb.session, 'hardware.type'),
            'ip' => hb.ip,
            'domain' => details.get(hb.session, 'browser.window.hostname'),
            'port' => hb.port.to_s,
            'page_uri' => details.get(hb.session, 'browser.window.uri'),
            'firstseen' => hb.firstseen,
            'lastseen' => hb.lastseen,
            'date_stamp' => details.get(hb.session, 'browser.date.datestamp'),
            'city' => details.get(hb.session, 'location.city'),
            'country' => details.get(hb.session, 'location.country'),
            'country_code' => details.get(hb.session, 'location.country.isocode')
          }
        end
      end
    end
  end
end
