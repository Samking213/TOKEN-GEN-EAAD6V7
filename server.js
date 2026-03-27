const express = require("express");
const axios = require("axios");
const qs = require("qs");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Facebook/Meta App Credentials
const APP_CONFIG = {
    messenger_ios: {
        client_id: '447188370370048',
        client_secret: 'af41071a4bafe5fb8c87b3f7c7b7f3b4',
        access_token: '447188370370048|af41071a4bafe5fb8c87b3f7c7b7f3b4',
        user_agent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/MessengerForiOS;FBAV/450.0;FBBV/450.0;FBDV/iPhone15,3;FBMD/iPhone;FBSN/iOS;FBSV/17.0;FBSS/3;FBID/phone;FBLC/en_US;FBOP/5;FBRV/0]'
    },
    fb_android: {
        client_id: '350685531728',
        client_secret: 'c1e620fa708a1d5696fb991c1bde5662',
        access_token: '350685531728|c1e620fa708a1d5696fb991c1bde5662',
        user_agent: 'Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36'
    }
};

class TokenGenerator {
    constructor() {
        this.session = axios.create({
            headers: {
                'User-Agent': APP_CONFIG.messenger_ios.user_agent,
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            },
            timeout: 30000
        });
    }

    async getEAAD6V7Token(email, password, method = 'login', recoveryCode = null) {
        try {
            console.log(`Starting token generation via ${method}...`);
            
            let universalToken;
            
            if (method === 'login') {
                universalToken = await this.loginWithCredentials(email, password);
            } else if (method === 'recovery') {
                universalToken = await this.loginWithRecoveryCode(email, recoveryCode);
            } else {
                throw new Error('Invalid method');
            }
            
            if (!universalToken) {
                throw new Error('Failed to get universal token');
            }
            
            console.log('Universal token obtained, converting to EAAD6V7...');
            
            const eaaToken = await this.convertToEAAD6V7(universalToken);
            
            const tokenInfo = await this.validateToken(eaaToken);
            
            return {
                success: true,
                universal_token: universalToken,
                eaadv7_token: eaaToken,
                token_type: 'EAAD6V7',
                user_id: tokenInfo.user_id,
                app_id: tokenInfo.app_id,
                expires_at: tokenInfo.expires_at,
                scopes: tokenInfo.scopes || [],
                is_valid: tokenInfo.is_valid,
                generated_at: new Date().toISOString()
            };
            
        } catch (error) {
            console.error('Error:', error.message);
            return {
                success: false,
                error: error.message,
                error_code: error.code || 'TOKEN_GEN_FAILED'
            };
        }
    }

    async loginWithCredentials(email, password) {
        try {
            const params = await this.getLoginParams();
            
            const loginData = {
                lsd: params.lsd,
                jazoest: params.jazoest,
                m_ts: params.m_ts,
                li: params.li,
                try_number: '0',
                unrecognized_tries: '0',
                email: email,
                pass: password,
                login: 'Log In',
                bi_xrwh: '0',
                fb_dtsg: params.fb_dtsg
            };
            
            const response = await this.session.post(
                'https://www.facebook.com/login/device-based/regular/login/',
                qs.stringify(loginData),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Origin': 'https://www.facebook.com',
                        'Referer': 'https://www.facebook.com/',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    },
                    maxRedirects: 5
                }
            );
            
            const token = this.extractTokenFromResponse(response.data);
            
            if (!token) {
                throw new Error('Login successful but token not found');
            }
            
            return token;
            
        } catch (error) {
            throw new Error(`Login failed: ${error.message}`);
        }
    }

    async loginWithRecoveryCode(email, recoveryCode) {
        try {
            await this.requestPasswordReset(email);
            const resetToken = await this.submitRecoveryCode(email, recoveryCode);
            const newPassword = this.generateRandomPassword();
            await this.setNewPassword(resetToken, newPassword);
            return await this.loginWithCredentials(email, newPassword);
        } catch (error) {
            throw new Error(`Recovery login failed: ${error.message}`);
        }
    }

    async getLoginParams() {
        const response = await this.session.get('https://www.facebook.com');
        const html = response.data;
        
        const extractValue = (regex) => {
            const match = html.match(regex);
            return match ? match[1] : '';
        };
        
        return {
            lsd: extractValue(/name="lsd" value="([^"]+)"/),
            jazoest: extractValue(/name="jazoest" value="([^"]+)"/),
            m_ts: extractValue(/name="m_ts" value="([^"]+)"/),
            li: extractValue(/name="li" value="([^"]+)"/),
            fb_dtsg: extractValue(/name="fb_dtsg" value="([^"]+)"/) || 
                     extractValue(/"DTSGInitData",\[\],{"token":"([^"]+)"}/)
        };
    }

    extractTokenFromResponse(html) {
        const tokenPatterns = [
            /access_token=([^&]+)/,
            /"accessToken":"([^"]+)"/,
            /"token":"([^"]+)"/,
            /EAAD[UV6][A-Za-z0-9._-]{150,300}/,
            /"EAAD[^"]+"/,
            /accessToken=([^&\s]+)/
        ];
        
        for (const pattern of tokenPatterns) {
            const match = html.match(pattern);
            if (match) {
                const token = match[1] ? match[1].replace(/"/g, '') : match[0].replace(/"/g, '');
                if (token.length > 100) {
                    return token;
                }
            }
        }
        
        return null;
    }

    async convertToEAAD6V7(universalToken) {
        try {
            const response = await axios.get(
                'https://graph.facebook.com/v6.0/oauth/access_token',
                {
                    params: {
                        grant_type: 'fb_exchange_token',
                        client_id: APP_CONFIG.messenger_ios.client_id,
                        client_secret: APP_CONFIG.messenger_ios.client_secret,
                        fb_exchange_token: universalToken
                    }
                }
            );
            
            const exchangedToken = response.data.access_token;
            
            if (exchangedToken.startsWith('EAAD6')) {
                return exchangedToken;
            }
            
            const pageToken = await this.getPageAccessToken(exchangedToken);
            if (pageToken && pageToken.startsWith('EAAD6')) {
                return pageToken;
            }
            
            const v6Response = await axios.get(
                'https://graph.facebook.com/v6.0/me',
                {
                    params: {
                        access_token: exchangedToken,
                        fields: 'id'
                    }
                }
            );
            
            if (v6Response.data.id) {
                return exchangedToken;
            }
            
            return universalToken;
            
        } catch (error) {
            console.warn('EAAD6V7 conversion failed:', error.message);
            return universalToken;
        }
    }

    async getPageAccessToken(userToken) {
        try {
            const response = await axios.get(
                'https://graph.facebook.com/v6.0/me/accounts',
                {
                    params: {
                        access_token: userToken,
                        fields: 'access_token'
                    }
                }
            );
            
            if (response.data.data && response.data.data.length > 0) {
                return response.data.data[0].access_token;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    async validateToken(token) {
        try {
            const response = await axios.get(
                'https://graph.facebook.com/debug_token',
                {
                    params: {
                        input_token: token,
                        access_token: `${APP_CONFIG.messenger_ios.client_id}|${APP_CONFIG.messenger_ios.client_secret}`
                    }
                }
            );
            
            return {
                is_valid: response.data.data.is_valid,
                app_id: response.data.data.app_id,
                user_id: response.data.data.user_id,
                expires_at: response.data.data.expires_at,
                scopes: response.data.data.scopes || []
            };
        } catch (error) {
            return {
                is_valid: false,
                error: error.message
            };
        }
    }

    async requestPasswordReset(email) {
        const params = await this.getLoginParams();
        
        const resetData = {
            lsd: params.lsd,
            email: email,
            did_submit: 'Search',
            fb_dtsg: params.fb_dtsg
        };
        
        await this.session.post(
            'https://www.facebook.com/login/identify/',
            qs.stringify(resetData),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': 'https://www.facebook.com'
                }
            }
        );
    }

    async submitRecoveryCode(email, code) {
        const params = await this.getLoginParams();
        
        const codeData = {
            lsd: params.lsd,
            n: code,
            save_new_password: '1',
            fb_dtsg: params.fb_dtsg
        };
        
        const response = await this.session.post(
            'https://www.facebook.com/recover/code/',
            qs.stringify(codeData),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );
        
        const tokenMatch = response.data.match(/name="reset_token" value="([^"]+)"/);
        return tokenMatch ? tokenMatch[1] : null;
    }

    async setNewPassword(resetToken, newPassword) {
        const params = await this.getLoginParams();
        
        const passwordData = {
            lsd: params.lsd,
            reset_token: resetToken,
            new_password: newPassword,
            new_password_confirm: newPassword,
            fb_dtsg: params.fb_dtsg
        };
        
        await this.session.post(
            'https://www.facebook.com/recover/complete/',
            qs.stringify(passwordData),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );
    }

    generateRandomPassword() {
        return crypto.randomBytes(12).toString('hex') + 'Aa1!';
    }

    async testMessage(token, userId, message = 'Test from EAAD6V7 token') {
        try {
            const response = await axios.post(
                'https://graph.facebook.com/v6.0/me/messages',
                {
                    recipient: { id: userId },
                    message: { text: message }
                },
                {
                    params: { access_token: token }
                }
            );
            
            return {
                success: true,
                message_id: response.data.message_id
            };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.error?.message || error.message
            };
        }
    }
}

// Initialize token generator
const tokenGen = new TokenGenerator();

// API Routes
app.post('/api/generate-token', async (req, res) => {
    const { email, password, method, recoveryCode } = req.body;
    
    if (!email) {
        return res.status(400).json({ success: false, error: 'Email is required' });
    }
    
    if (method === 'login' && !password) {
        return res.status(400).json({ success: false, error: 'Password is required' });
    }
    
    if (method === 'recovery' && !recoveryCode) {
        return res.status(400).json({ success: false, error: 'Recovery code is required' });
    }
    
    const result = await tokenGen.getEAAD6V7Token(email, password, method, recoveryCode);
    res.json(result);
});

app.post('/api/test-token', async (req, res) => {
    const { token, userId, message } = req.body;
    
    if (!token || !userId) {
        return res.status(400).json({ success: false, error: 'Token and User ID are required' });
    }
    
    const result = await tokenGen.testMessage(token, userId, message);
    res.json(result);
});

app.get('/api/validate-token', async (req, res) => {
    const { token } = req.query;
    
    if (!token) {
        return res.status(400).json({ success: false, error: 'Token is required' });
    }
    
    const result = await tokenGen.validateToken(token);
    res.json(result);
});

// Serve index.html for all other routes (SPA support)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Visit: http://localhost:${PORT}`);
});
