document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const submitBtn = document.getElementById('submitBtn');
 
    // ── Crypto helpers ────────────────────────────────────────────────────────
 
    function strToBuffer(str) {
        return new TextEncoder().encode(str);
    }
 
    function bufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }
 
    function base64ToBuffer(b64) {
        const binary = atob(b64);
        const bytes  = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }
 
    // Re-hash using whichever method was used at signup time
    async function verifyPassword(password, storedHash, storedSalt, method) {
        if (method === 'pbkdf2' && window.crypto && window.crypto.subtle) {
            try {
                const saltBuffer = base64ToBuffer(storedSalt);
 
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
                        salt:       saltBuffer,
                        iterations: 10_000,
                        hash:       'SHA-256',
                    },
                    keyMaterial,
                    256
                );
 
                return bufferToBase64(hashBuffer) === storedHash;
            } catch (err) {
                console.warn('PBKDF2 verify failed:', err);
                return false;
            }
        }
 
        // Fallback: SHA-256(salt + password)
        const combined   = storedSalt + password;
        const msgBuffer  = strToBuffer(combined);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        return bufferToBase64(hashBuffer) === storedHash;
    }
 
    // ── Form submission ───────────────────────────────────────────────────────
 
    loginForm.addEventListener('submit', async function (e) {
        e.preventDefault();
 
        submitBtn.innerText = 'Verifying...';
        submitBtn.disabled  = true;
 
        const email    = document.getElementById('username').value.trim().toLowerCase();
        const password = document.getElementById('password').value;
 
        if (!email || !password) {
            alert('Please fill in all fields.');
            submitBtn.innerText = 'Sign In';
            submitBtn.disabled  = false;
            return;
        }
 
        try {
            const users = JSON.parse(localStorage.getItem('users') || '[]');
            const user  = users.find(u => u.email === email);
 
            if (!user) {
                alert('No account found with that email.');
                submitBtn.innerText = 'Sign In';
                submitBtn.disabled  = false;
                loginForm.reset();
                return;
            }
 
            const isValid = await verifyPassword(
                password,
                user.passwordHash,
                user.passwordSalt,
                user.hashMethod || 'pbkdf2'
            );
 
            if (isValid) {
                sessionStorage.setItem('loggedIn', 'true');
                sessionStorage.setItem('currentUser', JSON.stringify({ email: user.email }));
 
                window.location.href = 'dashboard.html';
                return;
            } else {
                alert('Incorrect password. Please try again.');
            }
 
        } catch (err) {
            console.error('Login error:', err);
            alert('Login failed: ' + err.message);
        }
 
        submitBtn.innerText = 'Sign In';
        submitBtn.disabled  = false;
        loginForm.reset();
    });
});

    const toggle = document.getElementById('togglePassword');
  const passInput = document.getElementById('password');

  toggle.addEventListener('click', () => {
    const isPassword = passInput.type === 'password';
    passInput.type = isPassword ? 'text' : 'password';
    toggle.classList.toggle('fa-eye');
    toggle.classList.toggle('fa-eye-slash');
  });