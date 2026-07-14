// LLDPq Authentication Module
// Include this in all protected pages

// Ensure the shared dark-themed dialogs (lldpqToast / lldpqConfirm / lldpqPrompt) are available
// on every page that loads auth.js. Loaded from the same directory as this script so it works
// from sub-directory pages too. This also routes any native alert() through our dark UI.
(function () {
    if (window.__lldpqDialogsLoaded || window.__lldpqDialogsRequested) return;
    window.__lldpqDialogsRequested = true;
    try {
        var base = 'css/';
        var cur = document.currentScript;
        if (cur && cur.src) base = cur.src.replace(/[^\/]*$/, '');
        var s = document.createElement('script');
        s.src = base + 'ui-dialogs.js';
        (document.head || document.documentElement).appendChild(s);
    } catch (e) {}
})();

const LLDPqAuth = {
    user: null,
    role: null,
    hostname: 'lldpq',
    
    // Check if user is authenticated
    async check() {
        let data = null;
        try {
            const response = await fetch('/auth-api?action=check');
            data = await response.json();
        } catch (e) {
            // Network error or server busy (e.g. fcgiwrap busy with a long-running
            // request). Do NOT redirect to login — the session may still be valid.
            // The caller handles the false return by aborting its own action.
            console.error('Auth check failed:', e);
            return false;
        }

        if (data && data.authenticated) {
            this.user = data.username;
            this.role = data.role;
            this.hostname = (
                typeof data.lldpq_hostname === 'string' &&
                /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(data.lldpq_hostname)
            ) ? data.lldpq_hostname : 'lldpq';
            try { localStorage.setItem('lldpq_role', data.role || ''); } catch (e) {}
            return true;
        } else {
            // Server explicitly returned authenticated:false — redirect to login.
            this.redirectToLogin();
            return false;
        }
    },
    
    // Redirect to login page (break out of iframe to avoid nested app shell)
    redirectToLogin() {
        const topWin = this.getTopWindow();
        if (!topWin.location.pathname.includes('login.html')) {
            topWin.location.href = '/login.html';
        }
    },

    // Get the top window safely, falling back to current window if same-origin access fails
    getTopWindow() {
        try {
            if (window.top && window.top !== window) {
                void window.top.location.pathname;
                return window.top;
            }
        } catch (e) {
        }
        return window;
    },
    
    // Logout
    async logout() {
        let logoutSucceeded = false;
        try {
            const response = await fetch('/auth-api?action=logout', { method: 'POST' });
            if (!response || !response.ok) {
                throw new Error(`Logout request failed${response && response.status ? ` (${response.status})` : ''}`);
            }
            // The current endpoint returns JSON. Also accept a successful no-content or
            // legacy response that does not expose json(), but never ignore success:false.
            if (response.status !== 204 && typeof response.json === 'function') {
                const data = await response.json();
                if (!data || data.success !== true) throw new Error('Logout was not confirmed by the server');
            }
            logoutSucceeded = true;
        } catch (e) {
            console.error('Logout error:', e);
        }
        // Preserve reconnectable Console SIDs when logout did not actually happen. The
        // normal redirect remains unchanged, and a later successful logout will clear them.
        if (logoutSucceeded) this.clearConsoleSessionState();
        try { localStorage.removeItem('lldpq_role'); } catch (e) {}
        this.getTopWindow().location.href = '/login.html';
    },

    // Console PTY ids must never survive an authentication boundary. Keep visual
    // preferences (for example font size), but remove all per-tab Console state.
    clearConsoleSessionState() {
        const stores = [];
        try { stores.push(window.sessionStorage); } catch (e) {}
        try {
            const topWin = this.getTopWindow();
            if (topWin !== window && topWin.sessionStorage) stores.push(topWin.sessionStorage);
        } catch (e) {}
        stores.forEach(store => {
            try {
                // Explicit removal also supports small storage mocks without key()/length.
                store.removeItem('lldpq_console_tabs');
                const keys = [];
                for (let i = 0; i < store.length; i += 1) {
                    const key = store.key(i);
                    if (key && key.indexOf('lldpq_console_') === 0) keys.push(key);
                }
                keys.forEach(key => store.removeItem(key));
            } catch (e) {}
        });
    },
    
    // Check if user is admin
    isAdmin() {
        return this.role === 'admin';
    },
    
    // Check if user is operator
    isOperator() {
        return this.role === 'operator';
    },
    
    // Hide elements for operators
    hideForOperator(selector) {
        if (this.isOperator()) {
            const elements = document.querySelectorAll(selector);
            elements.forEach(el => el.style.display = 'none');
        }
    },
    
    // Show elements only for admin
    showForAdmin(selector) {
        if (!this.isAdmin()) {
            const elements = document.querySelectorAll(selector);
            elements.forEach(el => el.style.display = 'none');
        }
    },
    
    // Create user menu HTML
    createUserMenu() {
        const menuHtml = `
            <div class="user-menu" id="user-menu">
                <div class="user-menu-trigger" onclick="LLDPqAuth.toggleMenu()">
                    <span class="user-icon">&#9679;</span>
                    <span class="user-name">${this.user}</span>
                </div>
                <div class="user-dropdown" id="user-dropdown">
                    ${this.isAdmin() ? '<a href="#" onclick="LLDPqAuth.showUserManagementModal(); return false;">User Management</a>' : ''}
                    ${this.isAdmin() ? '<a href="#" onclick="LLDPqAuth.showPasswordModal(); return false;">Change Passwords</a>' : ''}
                    <a href="#" onclick="LLDPqAuth.logout(); return false;">Logout</a>
                </div>
            </div>
        `;
        return menuHtml;
    },
    
    // Toggle dropdown menu
    toggleMenu() {
        const dropdown = document.getElementById('user-dropdown');
        if (dropdown) {
            dropdown.classList.toggle('show');
        }
    },
    
    // Show password change modal
    showPasswordModal() {
        const modal = document.getElementById('password-modal');
        if (modal) {
            modal.style.display = 'flex';
        }
        this.toggleMenu(); // Close dropdown
    },
    
    // Hide password modal
    hidePasswordModal() {
        const modal = document.getElementById('password-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    },
    
    // Change password
    async changePassword(targetUser, newPassword) {
        try {
            const response = await fetch('/auth-api?action=change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `target_user=${encodeURIComponent(targetUser)}&new_password=${encodeURIComponent(newPassword)}`
            });
            
            const data = await response.json();
            return data;
        } catch (e) {
            return { success: false, error: 'Connection error' };
        }
    },
    
    // Create password modal HTML
    createPasswordModal() {
        const modalHtml = `
            <div id="password-modal" class="modal" style="display: none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>Change Password</h3>
                        <span class="modal-close" onclick="LLDPqAuth.hidePasswordModal()">&times;</span>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label>Select User</label>
                            <select id="pw-target-user">
                                <option value="admin">admin</option>
                                <option value="operator">operator</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>New Password</label>
                            <input type="password" id="pw-new-password" placeholder="Enter new password (min 6 chars)">
                        </div>
                        <div class="form-group">
                            <label>Confirm Password</label>
                            <input type="password" id="pw-confirm-password" placeholder="Confirm new password">
                        </div>
                        <div id="pw-error" class="error-text" style="display: none;"></div>
                        <div id="pw-success" class="success-text" style="display: none;"></div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn-cancel" onclick="LLDPqAuth.hidePasswordModal()">Cancel</button>
                        <button class="btn-save" onclick="LLDPqAuth.handlePasswordChange()">Change Password</button>
                    </div>
                </div>
            </div>
        `;
        return modalHtml;
    },
    
    // Handle password change form submission
    async handlePasswordChange() {
        const targetUser = document.getElementById('pw-target-user').value;
        const newPassword = document.getElementById('pw-new-password').value;
        const confirmPassword = document.getElementById('pw-confirm-password').value;
        const errorDiv = document.getElementById('pw-error');
        const successDiv = document.getElementById('pw-success');
        
        errorDiv.style.display = 'none';
        successDiv.style.display = 'none';
        
        if (newPassword.length < 6) {
            errorDiv.textContent = 'Password must be at least 6 characters';
            errorDiv.style.display = 'block';
            return;
        }
        
        if (newPassword !== confirmPassword) {
            errorDiv.textContent = 'Passwords do not match';
            errorDiv.style.display = 'block';
            return;
        }
        
        const result = await this.changePassword(targetUser, newPassword);
        
        if (result.success) {
            successDiv.textContent = 'Password changed successfully';
            successDiv.style.display = 'block';
            document.getElementById('pw-new-password').value = '';
            document.getElementById('pw-confirm-password').value = '';
            
            setTimeout(() => {
                this.hidePasswordModal();
                successDiv.style.display = 'none';
            }, 2000);
        } else {
            errorDiv.textContent = result.error || 'Failed to change password';
            errorDiv.style.display = 'block';
        }
    },
    
    // Show user management modal
    async showUserManagementModal() {
        const modal = document.getElementById('user-management-modal');
        if (modal) {
            modal.style.display = 'flex';
            await this.loadUserList();
        }
        this.toggleMenu(); // Close dropdown
    },
    
    // Hide user management modal
    hideUserManagementModal() {
        const modal = document.getElementById('user-management-modal');
        if (modal) {
            modal.style.display = 'none';
        }
        // Clear form
        document.getElementById('um-new-username').value = '';
        document.getElementById('um-new-password').value = '';
        document.getElementById('um-error').style.display = 'none';
        document.getElementById('um-success').style.display = 'none';
    },
    
    // Load user list
    async loadUserList() {
        try {
            const response = await fetch('/auth-api?action=list-users');
            const data = await response.json();
            
            if (data.success && data.users) {
                const listDiv = document.getElementById('um-user-list');
                listDiv.innerHTML = data.users.map(user => `
                    <div class="user-list-item">
                        <div class="user-list-info">
                            <span class="user-list-name">${user.username}</span>
                            <span class="user-list-role ${user.role}">${user.role}</span>
                        </div>
                        ${user.username !== 'admin' ? `<button class="btn-delete-user" onclick="LLDPqAuth.deleteUser('${user.username}')">Delete</button>` : '<span class="protected-badge">Protected</span>'}
                    </div>
                `).join('');
                
                // Update password modal select options
                this.updatePasswordUserSelect(data.users);
            }
        } catch (e) {
            console.error('Failed to load users:', e);
        }
    },
    
    // Update password modal user select
    updatePasswordUserSelect(users) {
        const select = document.getElementById('pw-target-user');
        if (select && users) {
            select.innerHTML = users.map(user => 
                `<option value="${user.username}">${user.username} (${user.role})</option>`
            ).join('');
        }
    },
    
    // Create new user
    async createUser() {
        const username = document.getElementById('um-new-username').value.trim();
        const password = document.getElementById('um-new-password').value;
        const errorDiv = document.getElementById('um-error');
        const successDiv = document.getElementById('um-success');
        
        errorDiv.style.display = 'none';
        successDiv.style.display = 'none';
        
        if (!username) {
            errorDiv.textContent = 'Username is required';
            errorDiv.style.display = 'block';
            return;
        }
        
        if (password.length < 6) {
            errorDiv.textContent = 'Password must be at least 6 characters';
            errorDiv.style.display = 'block';
            return;
        }
        
        try {
            const response = await fetch('/auth-api?action=create-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
            });
            
            const data = await response.json();
            
            if (data.success) {
                successDiv.textContent = data.message;
                successDiv.style.display = 'block';
                document.getElementById('um-new-username').value = '';
                document.getElementById('um-new-password').value = '';
                await this.loadUserList();
                
                setTimeout(() => { successDiv.style.display = 'none'; }, 3000);
            } else {
                errorDiv.textContent = data.error;
                errorDiv.style.display = 'block';
            }
        } catch (e) {
            errorDiv.textContent = 'Connection error';
            errorDiv.style.display = 'block';
        }
    },
    
    // Delete user (dark confirm modal, then perform)
    deleteUser(username) {
        const run = () => this._performDeleteUser(username);
        if (window.lldpqConfirm) {
            const safe = String(username).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
            lldpqConfirm('Delete User', `Delete user <strong>${safe}</strong>? This cannot be undone.`, run);
        } else {
            run();
        }
    },

    async _performDeleteUser(username) {
        const errorDiv = document.getElementById('um-error');
        const successDiv = document.getElementById('um-success');
        
        try {
            const response = await fetch('/auth-api?action=delete-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `username=${encodeURIComponent(username)}`
            });
            
            const data = await response.json();
            
            if (data.success) {
                successDiv.textContent = data.message;
                successDiv.style.display = 'block';
                await this.loadUserList();
                
                setTimeout(() => { successDiv.style.display = 'none'; }, 3000);
            } else {
                errorDiv.textContent = data.error;
                errorDiv.style.display = 'block';
            }
        } catch (e) {
            errorDiv.textContent = 'Connection error';
            errorDiv.style.display = 'block';
        }
    },
    
    // Create user management modal HTML
    createUserManagementModal() {
        const modalHtml = `
            <div id="user-management-modal" class="modal" style="display: none;">
                <div class="modal-content" style="max-width: 500px;">
                    <div class="modal-header">
                        <h3>User Management</h3>
                        <span class="modal-close" onclick="LLDPqAuth.hideUserManagementModal()">&times;</span>
                    </div>
                    <div class="modal-body">
                        <div class="um-section">
                            <h4>Existing Users</h4>
                            <div id="um-user-list" class="user-list">
                                <div class="loading">Loading...</div>
                            </div>
                        </div>
                        <div class="um-section">
                            <h4>Create New User <span class="role-note">(Operator role)</span></h4>
                            <div class="form-group">
                                <label>Username</label>
                                <input type="text" id="um-new-username" placeholder="Enter username (3-20 chars)">
                            </div>
                            <div class="form-group">
                                <label>Password</label>
                                <input type="password" id="um-new-password" placeholder="Enter password (min 6 chars)">
                            </div>
                            <button class="btn-create-user" onclick="LLDPqAuth.createUser()">Create User</button>
                        </div>
                        <div id="um-error" class="error-text" style="display: none;"></div>
                        <div id="um-success" class="success-text" style="display: none;"></div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn-cancel" onclick="LLDPqAuth.hideUserManagementModal()">Close</button>
                    </div>
                </div>
            </div>
        `;
        return modalHtml;
    },
    
    // Get CSS styles for auth components
    getStyles() {
        return `
            .user-menu {
                position: relative;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid #444;
            }
            
            .user-menu-trigger {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 12px 16px;
                background: linear-gradient(135deg, rgba(118, 185, 0, 0.15) 0%, rgba(100, 160, 0, 0.10) 100%);
                border: 1px solid rgba(118, 185, 0, 0.3);
                border-radius: 8px;
                cursor: pointer;
                color: #76b900;
                font-size: 14px;
                font-weight: 500;
                transition: all 0.3s ease;
            }
            
            .user-menu-trigger:hover {
                background: linear-gradient(135deg, rgba(118, 185, 0, 0.25) 0%, rgba(100, 160, 0, 0.18) 100%);
                border-color: rgba(118, 185, 0, 0.45);
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            }
            
            .user-icon {
                font-size: 10px;
                color: #76b900;
            }
            
            .user-name {
                color: #fff;
            }
            
            .user-role {
                color: #888;
                font-size: 12px;
            }
            
            .user-dropdown {
                position: absolute;
                top: 100%;
                right: 0;
                margin-top: 5px;
                background: #2d2d2d;
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                min-width: 160px;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
                display: none;
                z-index: 1000;
            }
            
            .user-dropdown.show {
                display: block;
            }
            
            .user-dropdown a {
                display: block;
                padding: 12px 16px;
                color: #ccc;
                text-decoration: none;
                transition: background 0.2s;
            }
            
            .user-dropdown a:hover {
                background: rgba(255, 255, 255, 0.1);
                color: #fff;
            }
            
            .user-dropdown a:first-child {
                border-radius: 8px 8px 0 0;
            }
            
            .user-dropdown a:last-child {
                border-radius: 0 0 8px 8px;
            }
            
            .modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 2000;
            }
            
            .modal-content {
                background: #2d2d2d;
                border-radius: 12px;
                width: 100%;
                max-width: 400px;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
            }
            
            .modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 20px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .modal-header h3 {
                margin: 0;
                color: #fff;
                font-size: 18px;
            }
            
            .modal-close {
                font-size: 24px;
                color: #888;
                cursor: pointer;
                transition: color 0.2s;
            }
            
            .modal-close:hover {
                color: #fff;
            }
            
            .modal-body {
                padding: 20px;
            }
            
            .modal-body .form-group {
                margin-bottom: 15px;
            }
            
            .modal-body label {
                display: block;
                color: #ccc;
                font-size: 14px;
                margin-bottom: 6px;
            }
            
            .modal-body input,
            .modal-body select {
                width: 100%;
                padding: 10px 12px;
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 6px;
                color: #fff;
                font-size: 14px;
                box-sizing: border-box;
            }
            
            .modal-body input:focus,
            .modal-body select:focus {
                outline: none;
                border-color: #76b900;
            }
            
            .modal-footer {
                padding: 15px 20px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                display: flex;
                justify-content: flex-end;
                gap: 10px;
            }
            
            .btn-cancel {
                padding: 10px 20px;
                background: transparent;
                border: 1px solid rgba(255, 255, 255, 0.2);
                color: #ccc;
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.2s;
            }
            
            .btn-cancel:hover {
                background: rgba(255, 255, 255, 0.1);
                color: #fff;
            }
            
            .btn-save {
                padding: 10px 20px;
                background: #76b900;
                border: none;
                color: #fff;
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.2s;
            }
            
            .btn-save:hover {
                background: #8ad400;
            }
            
            .error-text {
                color: #ff6b6b;
                font-size: 13px;
                margin-top: 10px;
            }
            
            .success-text {
                color: #76b900;
                font-size: 13px;
                margin-top: 10px;
            }
            
            /* User Management Modal Styles */
            .um-section {
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .um-section:last-of-type {
                border-bottom: none;
                margin-bottom: 10px;
            }
            
            .um-section h4 {
                color: #76b900;
                font-size: 14px;
                margin-bottom: 12px;
                font-weight: 600;
            }
            
            .um-section .role-note {
                color: #888;
                font-weight: normal;
                font-size: 12px;
            }
            
            .user-list {
                max-height: 200px;
                overflow-y: auto;
                background: rgba(0, 0, 0, 0.2);
                border-radius: 6px;
                padding: 8px;
            }
            
            .user-list-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 10px 12px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 4px;
                margin-bottom: 6px;
            }
            
            .user-list-item:last-child {
                margin-bottom: 0;
            }
            
            .user-list-info {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .user-list-name {
                color: #fff;
                font-weight: 500;
            }
            
            .user-list-role {
                padding: 2px 8px;
                border-radius: 10px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
            }
            
            .user-list-role.admin {
                background: rgba(118, 185, 0, 0.2);
                color: #76b900;
            }
            
            .user-list-role.operator {
                background: rgba(79, 195, 247, 0.2);
                color: #4fc3f7;
            }
            
            .btn-delete-user {
                padding: 5px 12px;
                background: rgba(244, 67, 54, 0.2);
                border: 1px solid rgba(244, 67, 54, 0.5);
                color: #f44336;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
                transition: all 0.2s;
            }
            
            .btn-delete-user:hover {
                background: rgba(244, 67, 54, 0.4);
            }
            
            .protected-badge {
                padding: 5px 12px;
                background: rgba(255, 255, 255, 0.1);
                color: #888;
                border-radius: 4px;
                font-size: 11px;
            }
            
            .btn-create-user {
                width: 100%;
                padding: 10px;
                background: #76b900;
                border: none;
                color: #fff;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 500;
                transition: all 0.2s;
                margin-top: 10px;
            }
            
            .btn-create-user:hover {
                background: #8ad400;
            }
            
            .loading {
                text-align: center;
                color: #888;
                padding: 20px;
            }
        `;
    }
};

// Close dropdown when clicking outside
document.addEventListener('click', function(e) {
    if (!e.target.closest('.user-menu')) {
        const dropdown = document.getElementById('user-dropdown');
        if (dropdown) {
            dropdown.classList.remove('show');
        }
    }
});
