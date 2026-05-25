document.addEventListener('DOMContentLoaded', () => {
    const signupForm = document.getElementById('signupForm');
    const submitBtn  = document.getElementById('submitBtn');
 
    // Crypto helpers
 
    function strToBuffer(str) {
        return new TextEncoder().encode(str);
    }
 
    function bufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }
 
    // Hash password: try PBKDF2 first, fall back to plain SHA-256 if unavailable
    async function hashPassword(password) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const saltB64 = bufferToBase64(salt);
 
        // Check if SubtleCrypto is available (requires HTTPS or localhost)
        if (window.crypto && window.crypto.subtle) {
            try {
                const keyMaterial = await crypto.subtle.importKey(
                    'raw',
                    strToBuffer(password),
                    { name: 'PBKDF2' },
                    false,
                    ['deriveBits']
                );
 
                const hashBuffer = await crypto.subtle.deriveBits(
                    {
                        name:       'PBKDF2',
                        salt:       salt,
                        iterations: 10_000,   // lowered for broader browser support
                        hash:       'SHA-256',
                    },
                    keyMaterial,
                    256
                );
 
                return {
                    hash:   bufferToBase64(hashBuffer),
                    salt:   saltB64,
                    method: 'pbkdf2',
                };
            } catch (err) {
                console.warn('PBKDF2 failed, falling back to SHA-256:', err);
            }
        }
 
        // Fallback: SHA-256(salt + password)
        const combined   = saltB64 + password;
        const msgBuffer  = strToBuffer(combined);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        return {
            hash:   bufferToBase64(hashBuffer),
            salt:   saltB64,
            method: 'sha256',
        };
    }
 
    // Form submission 
    signupForm.addEventListener('submit', async function (e) {
        e.preventDefault();
 
        const email    = document.getElementById('username').value.trim().toLowerCase();
        const password = document.getElementById('password').value;
 
        if (!email || !password) {
            alert('Please fill in all fields.');
            return;
        }
 
        if (password.length < 6) {
            alert('Password must be at least 6 characters.');
            return;
        }
 
        // Check if email already registered
        const users = JSON.parse(localStorage.getItem('users') || '[]');
        if (users.find(u => u.email === email)) {
            alert('An account with that email already exists.');
            return;
        }
 
        submitBtn.innerText = 'Creating...';
        submitBtn.disabled  = true;
 
        try {
            const { hash, salt, method } = await hashPassword(password);
 
            users.push({
                email,
                passwordHash:   hash,
                passwordSalt:   salt,
                hashMethod:     method,
                createdAt:      new Date().toISOString(),
            });
 
            localStorage.setItem('users', JSON.stringify(users));
 
            // Auto-login the new user and redirect to onboarding
            sessionStorage.setItem('loggedIn', 'true');
            sessionStorage.setItem('currentUser', JSON.stringify({ email }));
 
            // Redirect to onboarding tour
            window.location.href = 'onboarding.html';
 
        } catch (err) {
            console.error('Signup error:', err);
            alert('Signup failed: ' + err.message);
            submitBtn.innerText = 'Create account';
            submitBtn.disabled  = false;
        }
    });
});