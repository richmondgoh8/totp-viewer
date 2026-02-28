const i18n = {
            en: {
                title: "TOTP Viewer",
                subtitle: "Secure Time-Based Passwords",
                remaining: "remaining",
                secret: "Shared Secret",
                missing: "Secret Missing:",
                prompt: "Please use a URL with a secret parameter, e.g.:",
                update: "Update",
                validate: "Validate Code",
                verify_now: "Verify Now",
                label_verify: "Enter Code to Verify",
                label_steps: "Tolerance Window",
                verified: "VERIFIED",
                invalid: "INVALID CODE",
                about_title: "About this Project",
                about_desc: "This is a ultra-secure, client-side TOTP viewer. Your secrets are processed only in your browser and never sent to any server. It supports bookmarkable URLs for quick access while maintaining a premium glassmorphic aesthetic.",
                copied: "COPIED",
                share: "Share",
                link_copied: "LINK COPIED",
                bmc: "Buy me a coffee",
                delete_all: "Delete All",
                confirm_delete_all: "Are you sure you want to delete ALL accounts? This cannot be undone.",
                accounts_title: "My Accounts",
                add_new: "+ Add New",
                export: "Export JSON",
                import: "Import JSON",
                modal_title_add: "Add New Account",
                modal_account_name: "Account Name",
                modal_secret: "Shared Secret",
                cancel: "Cancel",
                save_account: "Save Account",
                add_to_dashboard: "Add to Dashboard",
                theme_light: "Light",
                theme_dark: "Dark"
            },
            cn: {
                title: "TOTP 令牌生成器",
                subtitle: "安全的时间同步密码",
                remaining: "秒后更新",
                secret: "共享密钥",
                missing: "缺少密钥:",
                prompt: "请使用带有 secret 参数的 URL，例如：",
                update: "更新",
                validate: "验证代码",
                verify_now: "立即验证",
                label_verify: "输入要验证的代码",
                label_steps: "容差窗口",
                verified: "验证通过",
                invalid: "验证码错误",
                about_title: "关于本项目",
                about_desc: "这是一个超安全的客户端 TOTP 查看器。您的密钥仅在浏览器中处理，永远不会发送到任何服务器。它支持书签链接以实现快速访问，同时保持高端的磨砂玻璃审美。",
                copied: "已复制",
                share: "分享",
                link_copied: "链接已复制",
                bmc: "请我喝杯咖啡",
                delete_all: "删除全部",
                confirm_delete_all: "您确定要删除所有帐号吗？此操作无法撤销。",
                accounts_title: "我的帐号",
                add_new: "+ 新增",
                export: "导出 JSON",
                import: "导入 JSON",
                modal_title_add: "新增帐号",
                modal_account_name: "帐号名称",
                modal_secret: "共享密钥",
                cancel: "取消",
                save_account: "保存帐号",
                add_to_dashboard: "添加到仪表板",
                theme_light: "浅色",
                theme_dark: "深色"
            }
        };

        // --- TOTP Implementation in JS ---

        function base32ToBuf(s) {
            s = s.toUpperCase().replace(/ /g, '');
            const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let bits = "";
            for (let i = 0; i < s.length; i++) {
                const val = alphabet.indexOf(s[i]);
                if (val === -1) continue;
                bits += val.toString(2).padStart(5, '0');
            }
            const buf = new Uint8Array(Math.floor(bits.length / 8));
            for (let i = 0; i < buf.length; i++) {
                buf[i] = parseInt(bits.substr(i * 8, 8), 2);
            }
            return buf;
        }

        async function generateTOTP(secret, time = Date.now()) {
            try {
                const keyBuf = base32ToBuf(secret);
                const epoch = Math.floor(time / 1000);
                const counter = Math.floor(epoch / 30);

                // Prepare counter as 8-byte big-endian
                const msg = new Uint8Array(8);
                let tempCounter = counter;
                for (let i = 7; i >= 0; i--) {
                    msg[i] = tempCounter & 0xff;
                    tempCounter = tempCounter >> 8;
                }

                const cryptoKey = await crypto.subtle.importKey(
                    "raw", keyBuf,
                    { name: "HMAC", hash: "SHA-1" },
                    false, ["sign"]
                );

                const signature = await crypto.subtle.sign("HMAC", cryptoKey, msg);
                const hmac = new Uint8Array(signature);
                const offset = hmac[hmac.length - 1] & 0x0f;
                const otp = (
                    ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff)
                ) % 1000000;

                return otp.toString().padStart(6, '0');
            } catch (e) {
                console.error("TOTP Generation Error:", e);
                return null;
            }
        }

        const elements = {
            title: document.getElementById('titleTxt'),
            subtitle: document.getElementById('subtitleTxt'),
            remaining: document.getElementById('remainingTxt'),
            labelSecret: document.getElementById('labelSecret'),
            validate: document.getElementById('toggleValidatorBtn'),
            verify_now: document.getElementById('verifyBtn'),
            label_verify: document.getElementById('labelVerify'),
            label_steps: document.getElementById('labelSteps'),
            about_title: document.getElementById('aboutTitleText'),
            about_desc: document.getElementById('aboutDescText'),
            copy_feedback: document.getElementById('copyFeedback'),
            bmc: document.getElementById('bmcTxt'),
            // New elements
            accountsTitle: document.getElementById('accountsTitle'),
            accountsDashboard: document.getElementById('accountsDashboard'),
            mainDashboard: document.getElementById('mainDashboard'),
            accountsList: document.getElementById('accountsList'),
            addNewAccountBtn: document.getElementById('addNewAccountBtn'),
            accountModal: document.getElementById('accountModal'),
            modalTitle: document.getElementById('modalTitle'),
            labelModalAccountName: document.getElementById('labelModalAccountName'),
            labelModalSecret: document.getElementById('labelModalSecret'),
            modalAccountName: document.getElementById('modalAccountName'),
            modalSecret: document.getElementById('modalSecret'),
            saveModalBtn: document.getElementById('saveModalBtn'),
            closeModalBtn: document.getElementById('closeModalBtn'),
            exportBtn: document.getElementById('exportBtn'),
            importBtn: document.getElementById('importBtn'),
            deleteAllBtn: document.getElementById('deleteAllBtn'),
            importInput: document.getElementById('importInput'),
            aboutSection: document.getElementById('aboutSection'),
            accountsScroll: document.getElementById('accountsScroll'),
            shareBtn: document.getElementById('shareBtn'),
            shareBtnTxt: document.getElementById('shareBtnTxt'),
            shareFeedback: document.getElementById('shareFeedback'),
            addToDashboardBtn: document.getElementById('addToDashboardBtn')
        };

        const secretInput = document.getElementById('secret');
        const totpCode = document.getElementById('totpCode');
        const progressBar = document.getElementById('progressBar');
        const timerText = document.getElementById('timerText');
        const validatorSection = document.getElementById('validatorSection');
        const validateCodeInput = document.getElementById('validateCode');
        const windowStepsInput = document.getElementById('windowSteps');
        const statusBadge = document.getElementById('statusBadge');
        const langSelect = document.getElementById('langSelect');
        const themeToggle = document.getElementById('themeToggle');
        const copyBtn = document.getElementById('copyBtn');

        let currentLang = localStorage.getItem('totp-lang') || 'en';
        let currentTheme = localStorage.getItem('totp-theme') || 'dark';
        let accounts = JSON.parse(localStorage.getItem('totp-accounts') || '[]');
        let activeAccountId = null;

        function applyLanguage(lang) {
            currentLang = lang;
            localStorage.setItem('totp-lang', lang);
            const t = i18n[lang];
            elements.title.textContent = t.title;
            elements.subtitle.textContent = t.subtitle;
            elements.remaining.textContent = t.remaining;
            elements.labelSecret.textContent = t.secret;
            elements.validate.textContent = t.validate;
            elements.verify_now.textContent = t.verify_now;
            elements.label_verify.textContent = t.label_verify;
            elements.label_steps.textContent = t.label_steps;
            elements.about_title.textContent = t.about_title;
            elements.about_desc.textContent = t.about_desc;
            elements.copy_feedback.textContent = t.copied;
            elements.shareBtnTxt.textContent = t.share;
            elements.shareFeedback.textContent = t.link_copied;
            elements.bmc.textContent = t.bmc;
            elements.deleteAllBtn.textContent = t.delete_all;
            
            elements.accountsTitle.textContent = t.accounts_title;
            elements.addNewAccountBtn.textContent = t.add_new;
            elements.exportBtn.textContent = t.export;
            elements.importBtn.textContent = t.import;
            elements.modalTitle.textContent = t.modal_title_add;
            elements.labelModalAccountName.textContent = t.modal_account_name;
            elements.labelModalSecret.textContent = t.modal_secret;
            elements.closeModalBtn.textContent = t.cancel;
            elements.saveModalBtn.textContent = t.save_account;
            
            if (elements.addToDashboardBtn) {
                elements.addToDashboardBtn.textContent = t.add_to_dashboard;
            }
            
            langSelect.value = lang;
            
            if (currentTheme) {
                document.getElementById('themeText').textContent = currentTheme === 'dark' ? t.theme_dark : t.theme_light;
            }
        }

        function toggleTheme() {
            currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
            localStorage.setItem('totp-theme', currentTheme);
            document.body.classList.toggle('light-mode', currentTheme === 'light');
            document.getElementById('themeIcon').textContent = currentTheme === 'dark' ? '🌙' : '☀️';
            const t = i18n[currentLang];
            document.getElementById('themeText').textContent = currentTheme === 'dark' ? t.theme_dark : t.theme_light;
        }

        async function copyToClipboard() {
            const text = totpCode.textContent;
            if (text === '------') return;
            try {
                await navigator.clipboard.writeText(text);
                elements.copy_feedback.classList.add('show');
                setTimeout(() => elements.copy_feedback.classList.remove('show'), 2000);
            } catch (err) {
                console.error('Copy failed', err);
            }
        }

        let refreshTimer = null;
        function updateProgress() {
            const now = new Date();
            const seconds = now.getSeconds() % 30;
            const remaining = 30 - seconds;
            const progress = (remaining / 30) * 100;
            progressBar.style.width = progress + '%';
            timerText.textContent = remaining;
            if (seconds === 0) fetchTotp();
        }

        async function fetchTotp() {
            const secret = secretInput.value.trim();
            if (!secret) return;
            const totp = await generateTOTP(secret);
            if (totp) totpCode.textContent = totp;
        }

        async function verifyCode() {
            const secret = secretInput.value.trim();
            const code = validateCodeInput.value.trim();
            const windowSteps = parseInt(windowStepsInput.value.trim() || '1');
            if (!secret || !code) return;

            statusBadge.classList.remove('hidden', 'status-valid', 'status-invalid');
            let isValid = false;

            const now = Date.now();
            for (let i = -windowSteps; i <= windowSteps; i++) {
                const checkTime = now + (i * 30000);
                const checkOtp = await generateTOTP(secret, checkTime);
                if (checkOtp === code) {
                    isValid = true;
                    break;
                }
            }

            if (isValid) {
                statusBadge.textContent = i18n[currentLang].verified;
                statusBadge.style.color = 'var(--success)';
                statusBadge.classList.remove('hidden');
            } else {
                statusBadge.textContent = i18n[currentLang].invalid;
                statusBadge.style.color = 'var(--error)';
                statusBadge.classList.remove('hidden');
            }
        }

        // --- Account Management Logic ---

        function updateAccountsState(newAccounts) {
            accounts = newAccounts;
            localStorage.setItem('totp-accounts', JSON.stringify(accounts));
            renderAccounts();
        }

        function renderAccounts() {
            elements.accountsList.innerHTML = '';
            accounts.forEach(acc => {
                const card = document.createElement('div');
                card.className = `account-card ${acc.id === activeAccountId ? 'active' : ''}`;
                card.innerHTML = `
                    <div class="account-info">
                        <span class="account-name">${acc.name}</span>
                        <span class="account-secret-preview">${acc.secret.substr(0, 4)}...${acc.secret.substr(-4)}</span>
                    </div>
                    <div class="account-actions">
                        <button class="action-btn delete-btn" data-id="${acc.id}">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2M10 11v6M14 11v6"/>
                            </svg>
                        </button>
                    </div>
                `;
                card.onclick = (e) => {
                    if (e.target.closest('.delete-btn')) return;
                    showAccountTotp(acc);
                };
                card.querySelector('.delete-btn').onclick = (e) => {
                    e.stopPropagation();
                    deleteAccount(acc.id);
                };
                elements.accountsList.appendChild(card);
            });
        }

        function showAccountTotp(acc) {
            activeAccountId = acc.id;
            secretInput.value = acc.secret;
            elements.shareBtn.classList.remove('hidden');
            renderAccounts(); // Re-render to update active class
            fetchTotp();
            if (!refreshTimer) refreshTimer = setInterval(updateProgress, 1000);
            updateProgress();
        }

        function deleteAccount(id) {
            if (activeAccountId === id) {
                activeAccountId = null;
                secretInput.value = '';
                totpCode.textContent = '------';
                progressBar.style.width = '100%';
                timerText.textContent = '30';
                elements.shareBtn.classList.add('hidden');
                if (refreshTimer) {
                    clearInterval(refreshTimer);
                    refreshTimer = null;
                }
            }
            updateAccountsState(accounts.filter(a => a.id !== id));
        }

        function deleteAllAccounts() {
            if (confirm(i18n[currentLang].confirm_delete_all)) {
                activeAccountId = null;
                secretInput.value = '';
                totpCode.textContent = '------';
                progressBar.style.width = '100%';
                timerText.textContent = '30';
                elements.shareBtn.classList.add('hidden');
                if (refreshTimer) {
                    clearInterval(refreshTimer);
                    refreshTimer = null;
                }
                updateAccountsState([]);
            }
        }

        function saveAccount(name, secret) {
            const id = Date.now().toString();
            updateAccountsState([...accounts, { id, name, secret }]);
            elements.accountModal.classList.remove('show');
        }

        function exportAccounts() {
            const data = JSON.stringify(accounts, null, 2);
            const blob = new Blob([data], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `totp-backup-${new Date().toISOString().split('T')[0]}.json`;
            a.click();
        }

        function importAccounts(e) {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (event) => {
                try {
                    const imported = JSON.parse(event.target.result);
                    if (Array.isArray(imported)) {
                        updateAccountsState(imported);
                        activeAccountId = null;
                        if (accounts.length > 0) {
                            showAccountTotp(accounts[0]);
                        } else {
                            secretInput.value = '';
                            totpCode.textContent = '------';
                            elements.shareBtn.classList.add('hidden');
                        }
                    }
                } catch (err) {
                    console.error("JSON Import Error:", err);
                    alert("Invalid JSON file");
                }
            };
            reader.readAsText(file);
        }

        elements.addNewAccountBtn.onclick = () => {
            elements.modalTitle.textContent = i18n[currentLang].modal_title_add;
            elements.modalAccountName.value = '';
            elements.modalSecret.value = '';
            elements.accountModal.classList.add('show');
        };

        elements.closeModalBtn.onclick = () => elements.accountModal.classList.remove('show');

        elements.saveModalBtn.onclick = () => {
            const name = elements.modalAccountName.value.trim();
            const secret = elements.modalSecret.value.trim();
            if (name && secret) saveAccount(name, secret);
        };

        elements.exportBtn.onclick = exportAccounts;
        elements.importBtn.onclick = () => elements.importInput.click();
        elements.deleteAllBtn.onclick = deleteAllAccounts;
        elements.importInput.onchange = importAccounts;

        langSelect.onchange = (e) => applyLanguage(e.target.value);
        themeToggle.onclick = toggleTheme;
        copyBtn.onclick = copyToClipboard;
        document.getElementById('toggleValidatorBtn').onclick = () => validatorSection.classList.toggle('hidden');
        document.getElementById('verifyBtn').onclick = verifyCode;

        async function shareAccount() {
            const secret = secretInput.value.trim();
            if (!secret) return;
            const baseUrl = window.location.href.split('?')[0];
            const url = `${baseUrl}?secret=${secret}`;

            try {
                // Open new tab
                window.open(url, '_blank');
            } catch (error) {
                console.error('Share failed', error);
            }
        }
        elements.shareBtn.onclick = shareAccount;

        // Initialization
        const urlParams = new URLSearchParams(window.location.search);
        const urlSecret = urlParams.get('secret');

        if (urlSecret) {
            // SHARE MODE: Minimal UI, no account features
            document.getElementById('mainContainer').classList.add('share-mode');
            secretInput.value = urlSecret;
            elements.mainDashboard.classList.remove('hidden');
            elements.accountsDashboard.classList.add('hidden');
            elements.shareBtn.classList.add('hidden');
            if (elements.addToDashboardBtn) {
                elements.addToDashboardBtn.classList.remove('hidden');
            }
            elements.aboutSection.classList.remove('hidden'); // Show About section
            fetchTotp();
            refreshTimer = setInterval(updateProgress, 1000);
            updateProgress();
            
            if (elements.addToDashboardBtn) {
                elements.addToDashboardBtn.onclick = () => {
                    // Pre-fill the modal with the secret so the user can just type a name and save.
                    // This creates a much better UX than immediately saving a blank name.
                    const existingAccount = accounts.find(a => a.secret === urlSecret);
                    
                    if (!existingAccount) {
                        elements.modalTitle.textContent = i18n[currentLang].add_to_dashboard;
                        elements.modalAccountName.value = 'Shared Account';
                        elements.modalSecret.value = urlSecret;
                        
                        // We hijack the saveModalBtn behavior specifically for this import flow
                        
                        elements.saveModalBtn.onclick = () => {
                            const name = elements.modalAccountName.value.trim();
                            const secret = elements.modalSecret.value.trim();
                            if (name && secret) {
                                // Save it to local storage directly without calling saveAccount (which does UI updates)
                                // We want to force a reload immediately so the URL params are cleared.
                                const id = Date.now().toString();
                                accounts.push({ id, name, secret });
                                localStorage.setItem('totp-accounts', JSON.stringify(accounts));
                                window.location.href = window.location.pathname; 
                            }
                        };
                        
                        elements.accountModal.classList.add('show');

                    } else {
                        // Secret already exists, just return to dashboard to see it
                        window.location.href = window.location.pathname;
                    }
                };
            }

        } else {
            // ACCOUNT MODE: Unified dashboard
            elements.mainDashboard.classList.remove('hidden'); // Always show display
            elements.accountsDashboard.classList.remove('hidden');
            elements.shareBtn.classList.add('hidden'); // Hide until selected
            if (elements.addToDashboardBtn) {
                 elements.addToDashboardBtn.classList.add('hidden');
            }
            elements.aboutSection.classList.remove('hidden');
            renderAccounts();
            if (accounts.length > 0) showAccountTotp(accounts[0]);
        }

        // Mouse-drag scroll for account list
        let isDown = false;
        let startX;
        let scrollLeft;

        elements.accountsScroll.addEventListener('mousedown', (e) => {
            isDown = true;
            elements.accountsScroll.classList.add('active');
            startX = e.pageX - elements.accountsScroll.offsetLeft;
            scrollLeft = elements.accountsScroll.scrollLeft;
        });
        elements.accountsScroll.addEventListener('mouseleave', () => {
            isDown = false;
        });
        elements.accountsScroll.addEventListener('mouseup', () => {
            isDown = false;
        });
        elements.accountsScroll.addEventListener('mousemove', (e) => {
            if (!isDown) return;
            e.preventDefault();
            const x = e.pageX - elements.accountsScroll.offsetLeft;
            const walk = (x - startX) * 2; // Scroll speed
            elements.accountsScroll.scrollLeft = scrollLeft - walk;
        });

        applyLanguage(currentLang);
        if (currentTheme === 'light') {
            document.body.classList.add('light-mode');
            document.getElementById('themeIcon').textContent = '☀️';
            document.getElementById('themeText').textContent = i18n[currentLang].theme_light;
        } else {
            document.getElementById('themeText').textContent = i18n[currentLang].theme_dark;
        }