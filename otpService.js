const axios = require('axios');

const OTP_API_BASE_URL = 'https://mail-steel.vercel.app';

class OtpService {
    constructor() {
        this.axios = axios.create({
            baseURL: OTP_API_BASE_URL,
            timeout: 10000
        });
    }

    // Send OTP to user email
    async sendUserOtp(email) {
        try {
            const response = await this.axios.post('/send-otp', { email });
            return response.data;
        } catch (error) {
            console.error('Error sending user OTP:', error.response?.data || error.message);
            throw new Error(error.response?.data?.error || 'Failed to send OTP');
        }
    }

    // Verify user OTP
    async verifyUserOtp(email, otp) {
        try {
            const response = await this.axios.post('/verify-otp', { email, otp });
            return response.data;
        } catch (error) {
            console.error('Error verifying user OTP:', error.response?.data || error.message);
            throw new Error(error.response?.data?.error || 'Failed to verify OTP');
        }
    }

    // Send OTP to admin email
    async sendAdminOtp() {
        try {
            const response = await this.axios.post('/admin/send-otp');
            return response.data;
        } catch (error) {
            console.error('Error sending admin OTP:', error.response?.data || error.message);
            throw new Error(error.response?.data?.error || 'Failed to send admin OTP');
        }
    }

    // Verify admin OTP
    async verifyAdminOtp(otp) {
        try {
            const response = await this.axios.post('/admin/verify-otp', { otp });
            return response.data;
        } catch (error) {
            console.error('Error verifying admin OTP:', error.response?.data || error.message);
            throw new Error(error.response?.data?.error || 'Failed to verify admin OTP');
        }
    }

    // Check OTP status
    async checkOtpStatus() {
        try {
            const response = await this.axios.get('/otp-status');
            return response.data;
        } catch (error) {
            console.error('Error checking OTP status:', error.response?.data || error.message);
            throw new Error(error.response?.data?.error || 'Failed to check OTP status');
        }
    }

    // Check API health
    async checkHealth() {
        try {
            const response = await this.axios.get('/health');
            return response.data;
        } catch (error) {
            console.error('Error checking API health:', error.response?.data || error.message);
            throw new Error(error.response?.data?.error || 'Failed to check API health');
        }
    }
}

module.exports = new OtpService(); 