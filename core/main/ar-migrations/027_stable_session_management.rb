class StableSessionManagement < ActiveRecord::Migration[6.0]
  def change
    change_table :hooked_browsers do |t|
      # Lifecycle: active (default, preserves the legacy session model),
      # stale (passive cleanup candidate) or closed (operator terminated).
      t.text :state, default: 'active'
      # Why the session left the active set: 'passive_timeout' or 'operator'.
      t.text :close_reason
      # Stable per-browser identity persisted on the browser side (localStorage/cookies).
      t.text :persistent_id
      # Ownership / collaboration metadata.
      t.text :owner
      t.text :operators, default: '[]'
      t.text :role, default: 'execute'
      # How many delivery attempts were made before the browser was marked lost.
      t.integer :delivery_failures, default: 0
      t.index :session, unique: true
      t.index :persistent_id
      t.index :state
    end

    change_table :commands do |t|
      # Delivery state machine:
      # pending  -> queued, never put on the wire
      # sent     -> handed to the existing hook/websocket channel
      # acked    -> browser confirmed receipt
      # completed-> browser returned execution results
      # failed   -> retries exhausted, session declared lost
      t.text :delivery_state, default: 'pending'
      t.integer :attempts, default: 0
      t.integer :ack_timeout
      t.datetime :sent_at
      t.datetime :acked_at
      t.datetime :completed_at
      t.datetime :next_retry_at
      t.index :delivery_state
    end

    create_table :session_events do |t|
      t.references :hooked_browser
      t.text :session
      t.text :event_type
      t.text :detail
      t.text :operator
      t.datetime :date
      t.index :session
      t.index :event_type
    end
  end
end
