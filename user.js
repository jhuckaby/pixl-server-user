// Simple User Login Server Component
// A component for the pixl-server daemon framework.
// Copyright (c) 2015 Joseph Huckaby
// Released under the MIT License

var assert = require("assert");
var Class = require("pixl-class");
var Component = require("pixl-server/component");
var Tools = require("pixl-tools");
var Mailer = require('pixl-mail');

module.exports = Class.create({
	
	__name: 'User',
	__parent: Component,
	
	defaultConfig: {
		"smtp_hostname": "",
		"session_expire_days": 30,
		"max_failed_logins_per_hour": 5,
		"max_forgot_passwords_per_hour": 3,
		"free_accounts": 0,
		"sort_global_users": 1,
		"valid_username_match": "^[\\w\\-\\.]+$",
		"email_templates": {
			"welcome_new_user": "",
			"changed_password": "",
			"recover_password": ""
		},
		"default_privileges": {
			"admin": 0
		}
	},
	
	hooks: null,
	
	startup: function(callback) {
		// start user service
		this.logDebug(3, "User Manager starting up" );
		
		// register our class as an API namespace
		this.server.API.addNamespace( "user", "api_", this );
		
		// we'll need this frequently, so add a local reference
		this.storage = this.server.Storage;
		
		// setup SMTP mailer
		this.mail = new Mailer( this.config.get('smtp_hostname') || this.server.config.get('smtp_hostname') || "127.0.0.1" );
		
		// hook system for integrating with outer webapp
		this.hooks = {};
		
		// cache this from config
		this.usernameMatch = new RegExp( this.config.get('valid_username_match') );
		
		// startup complete
		callback();
	},
	
	normalizeUsername: function(username) {
		// lower-case, strip all non-alpha
		if (!username) return '';
		return username.toLowerCase().replace(/\W+/g, '');
	},
	
	api_create: function(args, callback) {
		// create new user account
		var self = this;
		var user = args.params;
		var path = 'users/' + this.normalizeUsername(user.username);
		
		if (!this.config.get('free_accounts')) {
			return this.doError('user', "Only administrators can create new users.", callback);
		}
		
		if (!this.requireParams(user, {
			username: this.usernameMatch,
			email: /^\S+\@\S+$/,
			full_name: /\S/,
			password: /.+/
		}, callback)) return;
		
		// first, make sure user doesn't already exist
		this.storage.get(path, function(err, old_user) {
			if (old_user) {
				return self.doError('user_exists', "User already exists: " + user.username, callback);
			}
			
			// now we can create the user
			user.active = 1;
			user.created = user.modified = Tools.timeNow(true);
			user.salt = Tools.generateUniqueID( 64, user.username );
			user.password = Tools.digestHex( '' + user.password + user.salt );
			user.privileges = self.config.get('default_privileges') || {};
			
			args.user = user;
			
			self.fireHook('before_create', args, function(err) {
				if (err) {
					return self.doError('user', "Failed to create user: " + err, callback);
				}
				
				self.logDebug(6, "Creating user", user);
				
				self.storage.put( path, user, function(err, data) {
					if (err) {
						return self.doError('user', "Failed to create user: " + err, callback);
					}
					else {
						self.logDebug(6, "Successfully created user: " + user.username);
						self.logTransaction('user_create', user.username, 
							self.getClientInfo(args, { user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } ) }));
						
						callback({ code: 0 });
						
						// add to master user list in the background
						if (self.config.get('sort_global_users')) {
							self.storage.listInsertSorted( 'global/users', { username: user.username }, ['username', 1], function(err) {
								if (err) self.logError( 1, "Failed to add user to master list: " + err );
								
								// fire after hook in background
								self.fireHook('after_create', args);
							} );
						}
						else {
							self.storage.listUnshift( 'global/users', { username: user.username }, function(err) {
								if (err) self.logError( 1, "Failed to add user to master list: " + err );
								
								// fire after hook in background
								self.fireHook('after_create', args);
							} );
						}
						
						// send e-mail in background (no callback)
						args.user = user;
						args.self_url = self.server.WebServer.getSelfURL(args.request, '/');
						self.sendEmail( 'welcome_new_user', args );
						
					} // success
				} ); // save user
			} ); // hook before
		} ); // check exists
	},
	
	api_login: function(args, callback) {
		// user login, validate password, create new session
		var self = this;
		var params = args.params;
		
		if (!this.requireParams(params, {
			username: this.usernameMatch,
			password: /.+/
		}, callback)) return;
		
		// load user first
		this.storage.get('users/' + this.normalizeUsername(params.username), function(err, user) {
			if (!user) {
				return self.doError('login', "Username or password incorrect.", callback); // deliberately vague
			}
			if (user.force_password_reset) {
				return self.doError('login', "Account is locked out.  Please reset your password to unlock it.", callback);
			}
			
			var phash = Tools.digestHex( '' + params.password + user.salt );
			if (phash != user.password) {
				// incorrect password
				// (throttle this to prevent abuse)
				var date_code = Math.floor( Tools.timeNow() / 3600 );
				if (date_code != user.fl_date_code) {
					user.fl_date_code = date_code;
					user.fl_count = 1;
				}
				else {
					user.fl_count++;
					if (user.fl_count > self.config.get('max_failed_logins_per_hour')) {
						// lockout until password reset
						self.logDebug(3, "Locking account due to too many failed login attempts: " + params.username);
						user.force_password_reset = 1;
					}
				}
				
				// save user to update counters
				self.storage.put( 'users/' + self.normalizeUsername(params.username), user, function(err, data) {
					return self.doError('login', "Username or password incorrect.", callback); // deliberately vague
				} );
				
				return;
			}
			if (!user.active) {
				return self.doError('login', "User account is disabled: " + session.username, callback);
			}
			
			args.user = user;
			
			self.fireHook('before_login', args, function(err) {
				if (err) {
					return self.doError('login', "Failed to login: " + err, callback);
				}
				
				// dates
				var now = Tools.timeNow(true);
				var expiration_date = Tools.normalizeTime(
					now + (86400 * self.config.get('session_expire_days')),
					{ hour: 0, min: 0, sec: 0 }
				);
				
				// create session id and object
				var session_id = Tools.generateUniqueID( 64, params.username );
				var session = {
					id: session_id,
					username: params.username,
					ip: args.ip,
					useragent: args.request.headers['user-agent'],
					created: now,
					modified: now,
					expires: expiration_date
				};
				self.logDebug(6, "Logging user in: " + params.username + ": New Session ID: " + session_id, session);
				
				// store session object
				self.storage.put('sessions/' + session_id, session, function(err, data) {
					if (err) {
						return self.doError('user', "Failed to create session: " + err, callback);
					}
					else {
						self.logDebug(6, "Successfully logged in");
						self.logTransaction('user_login', params.username, self.getClientInfo(args));
						
						// set session expiration
						self.storage.expire( 'sessions/' + session_id, expiration_date );
						
						callback( Tools.mergeHashes({ 
							code: 0, 
							username: user.username,
							user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } ), 
							session_id: session_id 
						}, args.resp || {}) );
						
						args.session = session;
						self.fireHook('after_login', args);
					} // success
				} ); // save session
			} ); // hook before
		} ); // load user
	},
	
	api_logout: function(args, callback) {
		// user logout, kill session
		var self = this;
		
		this.loadSession(args, function(err, session, user) {
			if (!session) {
				self.logDebug(6, "Session not found, but returning success anyway");
				callback({ code: 0 });
				return;
			}
			
			args.user = user;
			args.session = session;
			
			self.fireHook('before_logout', args, function(err) {
				if (err) {
					return self.doError('logout', "Failed to logout: " + err, callback);
				}
				
				self.logDebug(6, "Logging user out: " + session.username + ": Session ID: " + session.id);
				
				// delete session object
				self.storage.delete('sessions/' + session.id, function(err, data) {
					// deliberately ignoring error here
					
					self.logDebug(6, "Successfully logged out");
					self.logTransaction('user_logout', session.username, self.getClientInfo(args));
					
					callback({ code: 0 });
					
					self.fireHook('after_logout', args);
				} ); // delete
			} ); // hook before
		} ); // load session
	},
	
	api_resume_session: function(args, callback) {
		// validate existing session
		var self = this;
		
		this.loadSession(args, function(err, session, user) {
			if (!session) {
				return self.doError('session', "Session has expired or is invalid.", callback);
			}
			if (!user) {
				return self.doError('login', "User not found: " + session.username, callback);
			}
			if (!user.active) {
				return self.doError('login', "User account is disabled: " + session.username, callback);
			}
			if (user.force_password_reset) {
				return self.doError('login', "Account is locked out.  Please reset your password to unlock it.");
			}
			
			args.user = user;
			args.session = session;
			
			self.fireHook('before_resume_session', args, function(err) {
				if (err) {
					return self.doError('login', "Failed to login: " + err, callback);
				}
				
				// update session, modified, expiration, etc.
				var now = Tools.timeNow(true);
				var expiration_date = Tools.normalizeTime(
					now + (86400 * self.config.get('session_expire_days')),
					{ hour: 0, min: 0, sec: 0 }
				);
				session.modified = now;
				
				var new_exp_day = false;
				if (expiration_date != session.expires) {
					session.expires = expiration_date;
					new_exp_day = true;
				}
				
				self.logDebug(6, "Recovering session for: " + session.username, session);
				
				// store session object
				self.storage.put('sessions/' + session.id, session, function(err, data) {
					if (err) {
						return self.doError('user', "Failed to update session: " + err, callback);
					}
					else {
						self.logDebug(6, "Successfully logged in");
						self.logTransaction('user_login', session.username, self.getClientInfo(args));
						
						// set session expiration
						if (new_exp_day) {
							self.storage.expire( 'sessions/' + session.id, expiration_date );
						}
						
						callback( Tools.mergeHashes({ 
							code: 0, 
							username: session.username,
							user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } ), 
							session_id: session.id 
						}, args.resp || {}) );
						
						self.fireHook('after_resume_session', args);
					} // success
				} ); // save session
			} ); // hook before
		} ); // loaded session
	},
	
	api_update: function(args, callback) {
		// update existing user
		var self = this;
		var updates = args.params;
		var changed_password = false;
		
		this.loadSession(args, function(err, session, user) {
			if (!session) {
				return self.doError('session', "Session has expired or is invalid.", callback);
			}
			if (!user) {
				return self.doError('user', "User not found: " + session.username, callback);
			}
			if (!user.active) {
				return self.doError('user', "User account is disabled: " + session.username, callback);
			}
			if (updates.username != user.username) {
				// sanity check
				return self.doError('user', "Username mismatch.", callback);
			}
			
			var phash = Tools.digestHex( '' + updates.old_password + user.salt );
			if (phash != user.password) {
				return self.doError('login', "Your password is incorrect.", callback);
			}
			
			args.user = user;
			args.session = session;
			
			self.fireHook('before_update', args, function(err) {
				if (err) {
					return self.doError('user', "Failed to update user: " + err, callback);
				}
				
				// check for password change
				if (updates.new_password) {
					updates.salt = Tools.generateUniqueID( 64, user.username );
					updates.password = Tools.digestHex( '' + updates.new_password + updates.salt );
					changed_password = true;
				} // change password
				else delete updates.password;
				
				delete updates.new_password;
				delete updates.old_password;
				
				// don't allow user to update his own privs
				delete updates.privileges;
				
				// apply updates
				for (var key in updates) {
					user[key] = updates[key];
				}
				
				// update user record
				user.modified = Tools.timeNow(true);
				
				self.logDebug(6, "Updating user", user);
				
				self.storage.put( "users/" + self.normalizeUsername(user.username), user, function(err, data) {
					if (err) {
						return self.doError('user', "Failed to update user: " + err, callback);
					}
				
					self.logDebug(6, "Successfully updated user");
					self.logTransaction('user_update', user.username, 
						self.getClientInfo(args, { user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } ) }));
					
					callback({ 
						code: 0, 
						user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } )
					});
					
					if (changed_password) {
						// send e-mail in background (no callback)
						args.user = user;
						args.date_time = (new Date()).toLocaleString();
						self.sendEmail( 'changed_password', args );
					} // changed_password
					
					self.fireHook('after_update', args);
				} ); // updated user
			} ); // hook before
		} ); // loaded session
	},
	
	api_delete: function(args, callback) {
		// delete user account AND logout
		var self = this;
		var params = args.params;
		
		this.loadSession(args, function(err, session, user) {
			if (!session) {
				return self.doError('session', "Session has expired or is invalid.", callback);
			}
		
			// make sure user exists and is active
			if (!user) {
				return self.doError('user', "User not found: " + session.username, callback);
			}
			if (!user.active) {
				return self.doError('user', "User account is disabled: " + session.username, callback);
			}
			if (params.username != user.username) {
				// sanity check
				return self.doError('user', "Username mismatch.", callback);
			}
			
			var phash = Tools.digestHex( '' + params.password + user.salt );
			if (phash != user.password) {
				return self.doError('login', "Your password is incorrect.", callback);
			}
			
			args.user = user;
			args.session = session;
			
			self.fireHook('before_delete', args, function(err) {
				if (err) {
					return self.doError('login', "Failed to delete user: " + err, callback);
				}
				
				self.logDebug(6, "Deleting session: " + session.id);
				self.storage.delete('sessions/' + session.id, function(err, data) {
					// ignore session delete error, proceed
					
					self.logDebug(6, "Deleting user", user);
					self.storage.delete( "users/" + self.normalizeUsername(user.username), function(err, data) {
						if (err) {
							return self.doError('user', "Failed to delete user: " + err, callback);
						}
						else {
							self.logDebug(6, "Successfully deleted user");
							self.logTransaction('user_delete', user.username, self.getClientInfo(args));
							
							callback({ 
								code: 0
							});
							
							// remove from master user list in the background
							self.storage.listFindCut( 'global/users', { username: user.username }, function(err) {
								if (err) self.logError( 1, "Failed to remove user from master list: " + err );
								
								self.fireHook('after_delete', args);
							} );
							
						} // success
					} ); // delete user
				} ); // delete session
			} ); // hook before
		} ); // loaded session
	},
	
	api_forgot_password: function(args, callback) {
		// send forgot password e-mail to user
		var self = this;
		var params = args.params;
		
		if (!this.requireParams(params, {
			username: this.usernameMatch,
			email: /^\S+\@\S+$/
		}, callback)) return;
		
		// load user first
		this.storage.get('users/' + this.normalizeUsername(params.username), function(err, user) {
			if (!user) {
				return self.doError('login', "User account not found.", callback); // deliberately vague
			}
			if (user.email.toLowerCase() != params.email.toLowerCase()) {
				return self.doError('login', "User account not found.", callback); // deliberately vague
			}
			if (!user.active) {
				return self.doError('login', "User account is disabled: " + session.username, callback);
			}
			
			// check API throttle
			var date_code = Math.floor( Tools.timeNow() / 3600 );
			if (user.fp_date_code && (date_code == user.fp_date_code) && (user.fp_count > self.config.get('max_forgot_passwords_per_hour'))) {
				// lockout until next hour
				return self.doError('login', "This feature is locked due to too many requests. Please try again later.");
			}
			
			args.user = user;
			
			self.fireHook('before_forgot_password', args, function(err) {
				if (err) {
					return self.doError('login', "Forgot password failed: " + err, callback);
				}
				
				// create special recovery hash and expiration date for it
				var recovery_key = Tools.generateUniqueID( 64, user.username );
				
				// dates
				var now = Tools.timeNow(true);
				var expiration_date = Tools.normalizeTime( now + 86400, { hour:0, min:0, sec:0 } );
				
				// create object
				var recovery = {
					key: recovery_key,
					username: params.username,
					ip: args.ip,
					useragent: args.request.headers['user-agent'],
					created: now,
					modified: now,
					expires: expiration_date
				};
				self.logDebug(6, "Creating recovery key for: " + params.username + ": Key: " + recovery_key, recovery);
				
				// store recovery object
				self.storage.put('password_recovery/' + recovery_key, recovery, function(err, data) {
					if (err) {
						return self.doError('user', "Failed to create recovery key: " + err, callback);
					}
					
					self.logDebug(6, "Successfully created recovery key");
					
					// set session expiration
					self.storage.expire( 'password_recovery/' + recovery_key, expiration_date );
					
					// add some things to args for email body placeholder substitution
					args.user = user;
					args.self_url = self.server.WebServer.getSelfURL(args.request, '/');
					args.date_time = (new Date()).toLocaleString();
					args.recovery_key = recovery_key;
					
					// send e-mail to user
					self.sendEmail( 'recover_password', args, function(err) {
						if (err) {
							return self.doError('email', err.message, callback);
						}
						
						self.logTransaction('user_forgot_password', params.username, self.getClientInfo(args, { key: recovery_key }));
					 	callback({ code: 0 });
					 	
					 	// throttle this API to prevent abuse
					 	if (date_code != user.fp_date_code) {
					 		user.fp_date_code = date_code;
					 		user.fp_count = 1;
					 	}
					 	else {
					 		user.fp_count++;
					 	}
					 	
					 	// save user to update counters
					 	self.storage.put( 'users/' + self.normalizeUsername(params.username), user, function(err) {
					 		// fire async hook
					 		self.fireHook('after_forgot_password', args);
					 	} ); // save user
					 	
					} ); // email sent
				} ); // stored recovery object
			} ); // hook before
		} ); // loaded user
	},
	
	api_reset_password: function(args, callback) {
		// reset user password using recovery key
		var self = this;
		var params = args.params;
		
		if (!this.requireParams(params, {
			username: this.usernameMatch,
			new_password: /.+/,
			key: /^[A-F0-9]{64}$/i
		}, callback)) return;
		
		// load user first
		this.storage.get('users/' + this.normalizeUsername(params.username), function(err, user) {
			if (!user) {
				return self.doError('login', "User account not found.", callback);
			}
			if (!user.active) {
				return self.doError('login', "User account is disabled: " + session.username, callback);
			}
			
			// load recovery key, make sure it matches this user
			self.storage.get('password_recovery/' + params.key, function(err, recovery) {
				if (!recovery) {
					return self.doError('login', "Password reset failed.", callback); // deliberately vague
				}
				if (recovery.username != params.username) {
					return self.doError('login', "Password reset failed.", callback); // deliberately vague
				}
				
				args.user = user;
				
				self.fireHook('before_reset_password', args, function(err) {
					if (err) {
						return self.doError('login', "Failed to reset password: " + err, callback);
					}
					
					// update user record
					user.salt = Tools.generateUniqueID( 64, user.username );
					user.password = Tools.digestHex( '' + params.new_password + user.salt );
					user.modified = Tools.timeNow(true);
					
					// remove throttle lock
					delete user.force_password_reset;
					
					self.logDebug(6, "Updating user for password reset", user);
					
					self.storage.put( "users/" + self.normalizeUsername(user.username), user, function(err, data) {
						if (err) {
							return self.doError('user', "Failed to update user: " + err, callback);
						}
						self.logDebug(6, "Successfully updated user");
						self.logTransaction('user_update', user.username, 
							self.getClientInfo(args, { user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } ) }));
						
						// delete recovery key (one time use only!)
						self.logDebug(6, "Deleting recovery key: " + params.key);
						self.storage.delete('password_recovery/' + params.key, function(err, data) {
							
							// ignore error, call it done
							self.logTransaction('user_password_reset', params.username, self.getClientInfo(args, { key: params.key }));
						 	callback({ code: 0 });
							
							// send e-mail in background (no callback)
							args.user = user;
							args.date_time = (new Date()).toLocaleString();
							self.sendEmail( 'changed_password', args );
							
							// fire after hook
							self.fireHook('after_reset_password', args);
						} ); // deleted recovery key
					} ); // updated user
				} ); // hook before
			} ); // recovery key loaded
		} ); // user loaded
	},
	
	//
	// Administrator Level Calls:
	//
	
	api_admin_create: function(args, callback) {
		// admin only: create new user account
		var self = this;
		var new_user = args.params;
		var path = 'users/' + this.normalizeUsername(new_user.username);
		
		if (!this.requireParams(new_user, {
			username: this.usernameMatch,
			email: /^\S+\@\S+$/,
			full_name: /\S/,
			password: /.+/
		}, callback)) return;
		
		this.loadSession(args, function(err, session, admin_user) {
			if (!session) {
				return self.doError('session', "Session has expired or is invalid.", callback);
			}
			if (!admin_user) {
				return self.doError('user', "User not found: " + session.username, callback);
			}
			if (!admin_user.active) {
				return self.doError('user', "User account is disabled: " + session.username, callback);
			}
			if (!admin_user.privileges.admin) {
				return self.doError('user', "User is not an administrator: " + session.username, callback);
			}
			
			// first, make sure new user doesn't already exist
			self.storage.get(path, function(err, old_user) {
				if (old_user) {
					return self.doError('user_exists', "User already exists: " + new_user.username, callback);
				}
				
				// optionally send e-mail
				var send_welcome_email = new_user.send_email || false;
				delete new_user.send_email;
				
				// now we can create the user
				new_user.active = 1;
				new_user.created = new_user.modified = Tools.timeNow(true);
				new_user.salt = Tools.generateUniqueID( 64, new_user.username );
				new_user.password = Tools.digestHex( '' + new_user.password + new_user.salt );
				new_user.privileges = new_user.privileges || self.config.get('default_privileges') || {};
				
				args.admin_user = admin_user;
				args.session = session;
				args.user = new_user;
				
				self.fireHook('before_create', args, function(err) {
					if (err) {
						return self.doError('user', "Failed to create user: " + err, callback);
					}
					
					self.logDebug(6, "Creating user", new_user);
					
					self.storage.put( path, new_user, function(err, data) {
						if (err) {
							return self.doError('user', "Failed to create user: " + err, callback);
						}
						else {
							self.logDebug(6, "Successfully created user: " + new_user.username);
							self.logTransaction('user_create', new_user.username, 
								self.getClientInfo(args, { user: Tools.copyHashRemoveKeys( new_user, { password: 1, salt: 1 } ) }));
							
							callback({ code: 0 });
							
							// add to master user list in the background
							if (self.config.get('sort_global_users')) {
								self.storage.listInsertSorted( 'global/users', { username: new_user.username }, ['username', 1], function(err) {
									if (err) self.logError( 1, "Failed to add user to master list: " + err );
									
									// fire after hook in background
									self.fireHook('after_create', args);
								} );
							}
							else {
								self.storage.listUnshift( 'global/users', { username: new_user.username }, function(err) {
									if (err) self.logError( 1, "Failed to add user to master list: " + err );
									
									// fire after hook in background
									self.fireHook('after_create', args);
								} );
							}
							
							// send e-mail in background (no callback)
							if (send_welcome_email) {
								args.user = new_user;
								args.self_url = self.server.WebServer.getSelfURL(args.request, '/');
								self.sendEmail( 'welcome_new_user', args );
							}
							
						} // success
					} ); // save user
				} ); // hook before
			} ); // check exists
		} ); // load session
	},
	
	api_admin_update: function(args, callback) {
		// admin only: update any user
		var self = this;
		var updates = args.params;
		var path = 'users/' + this.normalizeUsername(updates.username);
		
		if (!this.requireParams(args.params, {
			username: this.usernameMatch
		}, callback)) return;
		
		this.loadSession(args, function(err, session, admin_user) {
			if (!session) {
				return self.doError('session', "Session has expired or is invalid.", callback);
			}
			if (!admin_user) {
				return self.doError('user', "User not found: " + session.username, callback);
			}
			if (!admin_user.active) {
				return self.doError('user', "User account is disabled: " + session.username, callback);
			}
			if (!admin_user.privileges.admin) {
				return self.doError('user', "User is not an administrator: " + session.username, callback);
			}
			
			self.storage.get(path, function(err, user) {
				if (err) {
					return self.doError('user', "User not found: " + updates.username, callback);
				}
				
				args.admin_user = admin_user;
				args.session = session;
				args.user = user;
				
				self.fireHook('before_update', args, function(err) {
					if (err) {
						return self.doError('user', "Failed to update user: " + err, callback);
					}
					
					// check for password change
					if (updates.new_password) {
						updates.salt = Tools.generateUniqueID( 64, user.username );
						updates.password = Tools.digestHex( '' + updates.new_password + updates.salt );
					} // change password
					else delete updates.password;
					
					delete updates.new_password;
					
					// apply updates
					for (var key in updates) {
						user[key] = updates[key];
					}
					
					// update user record
					user.modified = Tools.timeNow(true);
					
					self.logDebug(6, "Admin updating user", user);
					
					self.storage.put( path, user, function(err, data) {
						if (err) {
							return self.doError('user', "Failed to update user: " + err, callback);
						}
					
						self.logDebug(6, "Successfully updated user");
						self.logTransaction('user_update', user.username, 
							self.getClientInfo(args, { user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } ) }));
						
						callback({ 
							code: 0, 
							user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } )
						});
						
						self.fireHook('after_update', args);
					} ); // updated user
				} ); // hook before
			} ); // loaded user
		} ); // loaded session
	},
	
	api_admin_delete: function(args, callback) {
		// admin only: delete any user account
		var self = this;
		var params = args.params;
		var path = 'users/' + this.normalizeUsername(params.username);
		
		if (!this.requireParams(params, {
			username: this.usernameMatch
		}, callback)) return;
		
		this.loadSession(args, function(err, session, admin_user) {
			if (!session) {
				return self.doError('session', "Session has expired or is invalid.", callback);
			}
			if (!admin_user) {
				return self.doError('user', "User not found: " + session.username, callback);
			}
			if (!admin_user.active) {
				return self.doError('user', "User account is disabled: " + session.username, callback);
			}
			if (!admin_user.privileges.admin) {
				return self.doError('user', "User is not an administrator: " + session.username, callback);
			}
			
			self.storage.get(path, function(err, user) {
				if (err) {
					return self.doError('user', "User not found: " + params.username, callback);
				}
				
				args.admin_user = admin_user;
				args.session = session;
				args.user = user;
				
				self.fireHook('before_delete', args, function(err) {
					if (err) {
						return self.doError('login', "Failed to delete user: " + err, callback);
					}
					
					self.logDebug(6, "Deleting user", user);
					self.storage.delete( "users/" + self.normalizeUsername(user.username), function(err, data) {
						if (err) {
							return self.doError('user', "Failed to delete user: " + err, callback);
						}
						else {
							self.logDebug(6, "Successfully deleted user");
							self.logTransaction('user_delete', user.username, self.getClientInfo(args));
							
							callback({ 
								code: 0
							});
							
							// remove from master user list in the background
							self.storage.listFindCut( 'global/users', { username: user.username }, function(err) {
								if (err) self.logError( 1, "Failed to remove user from master list: " + err );
								
								self.fireHook('after_delete', args);
							} );
							
						} // success
					} ); // delete user
				} ); // hook before
			} ); // loaded user
		} ); // loaded session
	},
	
	api_admin_get_user: function(args, callback) {
		// admin only: get single user record, for editing
		var self = this;
		var params = Tools.mergeHashes( args.params, args.query );
		
		if (!this.requireParams(params, {
			username: this.usernameMatch
		}, callback)) return;
		
		this.loadSession(args, function(err, session, admin_user) {
			if (!session) {
				return self.doError('session', "Session has expired or is invalid.", callback);
			}
			if (!admin_user) {
				return self.doError('user', "User not found: " + session.username, callback);
			}
			if (!admin_user.active) {
				return self.doError('user', "User account is disabled: " + session.username, callback);
			}
			if (!admin_user.privileges.admin) {
				return self.doError('user', "User is not an administrator: " + session.username, callback);
			}
				
			// load user
			var path = 'users/' + self.normalizeUsername(params.username);
			self.storage.get( path, function(err, user) {
				if (err) {
					return self.doError('user', "Failed to load user: " + err, callback);
				}
				
				// success, return user record
				callback({
					code: 0,
					user: Tools.copyHashRemoveKeys( user, { password: 1, salt: 1 } )
				});
			} ); // loaded user
				
		} ); // loaded session
	},
	
	api_admin_get_users: function(args, callback) {
		// admin only: get chunk of users from global list, with pagination
		var self = this;
		var params = Tools.mergeHashes( args.params, args.query );
		
		this.loadSession(args, function(err, session, admin_user) {
			if (!session) {
				return self.doError('session', "Session has expired or is invalid.", callback);
			}
			if (!admin_user) {
				return self.doError('user', "User not found: " + session.username, callback);
			}
			if (!admin_user.active) {
				return self.doError('user', "User account is disabled: " + session.username, callback);
			}
			if (!admin_user.privileges.admin) {
				return self.doError('user', "User is not an administrator: " + session.username, callback);
			}
			
			if (!params.offset) params.offset = 0;
			if (!params.limit) params.limit = 50;
			
			self.storage.listGet( 'global/users', params.offset, params.limit, function(err, stubs, list) {
				if (err) {
					// no users found, not an error for this API
					return callback({
						code: 0,
						rows: [],
						list: { length: 0 }
					});
				}
				
				// create array of paths to user records
				var paths = [];
				for (var idx = 0, len = stubs.length; idx < len; idx++) {
					paths.push( 'users/' + self.normalizeUsername(stubs[idx].username) );
				}
				
				// load all users
				self.storage.getMulti( paths, function(err, users) {
					if (err) {
						return self.doError('user', "Failed to load users: " + err, callback);
					}
					
					// remove passwords and salts
					for (var idx = 0, len = users.length; idx < len; idx++) {
						users[idx] = Tools.copyHashRemoveKeys( users[idx], { password: 1, salt: 1 } );
					}
					
					// success, return users and list header
					callback({
						code: 0,
						rows: users,
						list: list
					});
				} ); // loaded users
			} ); // got username list
		} ); // loaded session
	},
	
	sendEmail: function(name, args, callback) {
		// send e-mail using template system and arg placeholders, if enabled
		var self = this;
		var emails = this.config.get('email_templates') || {};
		
		if (emails[name]) {
			// email is enabled
			args.config = this.server.config.get();
			
			this.mail.send( emails[name], args, function(err) {
				if (err) self.logError('email', "Failed to send e-mail: " + err);
				if (callback) callback(err);
			} );
		}
	},
	
	registerHook: function(name, callback) {
		// register a function as a hook handler
		name = name.toLowerCase();
		this.hooks[name] = callback;
	},
	
	fireHook: function(name, data, callback) {
		// fire custom hook, allowing webapp to intercept and alter data or throw an error
		name = name.toLowerCase();
		if (!callback) callback = function() {};
		
		if (this.hooks[name]) {
			this.hooks[name](data, callback);
		}
		else callback(null);
	},
	
	getClientInfo: function(args, params) {
		// return client info object suitable for logging in the data column
		if (!params) params = {};
		params.ip = args.ip;
		params.headers = args.request.headers;
		return params;
	},
	
	loadSession: function(args, callback) {
		// make sure session is valid
		var self = this;
		var session_id = args.cookies['session_id'] || args.request.headers['x-session-id'] || args.params.session_id || args.query.session_id;
		if (!session_id) return callback( new Error("No Session ID could be found") );
		
		this.storage.get('sessions/' + session_id, function(err, session) {
			if (err) return callback(err, null);
			
			// also load user
			self.storage.get('users/' + self.normalizeUsername(session.username), function(err, user) {
				if (err) return callback(err, null);
				
				// pass both session and user to callback
				callback(null, session, user);
			} );
		} );
	},
	
	requireParams: function(params, rules, callback) {
		// require params to exist and have length
		assert( arguments.length == 3, "Wrong number of arguments to requireParams" );
		for (var key in rules) {
			var regexp = rules[key];
			if (typeof(params[key]) == 'undefined') {
				this.doError('api', "Missing parameter: " + key, callback);
				return false;
			}
			if (!params[key].toString().match(regexp)) {
				this.doError('api', "Malformed parameter: " + key, callback);
				return false;
			}
		}
		return true;
	},
	
	doError: function(code, msg, callback) {
		// log error and send api response
		assert( arguments.length == 3, "Wrong number of arguments to doError" );
		this.logError( code, msg );
		callback({ code: code, description: msg });
		return false;
	},
	
	shutdown: function(callback) {
		// shutdown user service
		callback();
	}
	
});
