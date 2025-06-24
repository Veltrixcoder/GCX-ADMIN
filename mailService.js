const nodemailer = require('nodemailer');

// Create reusable transporter object using Gmail SMTP
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'veltrix620@gmail.com',
    pass: 'tdkdumjozzfszxkj' // Gmail app password
  }
});

/**
 * Generates a 6-digit numeric OTP
 * @returns {string} 6-digit OTP
 */
const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Sends OTP email to the specified email address
 * @param {string} email - Recipient email address
 * @param {string} otp - 6-digit OTP
 * @returns {Promise} - Nodemailer send promise
 */
const sendOtpEmail = async (email, otp) => {
  const mailOptions = {
    from: 'veltrix620@gmail.com',
    to: email,
    subject: 'Your OTP for Seller Panel',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Your OTP for Seller Panel</h2>
        <p style="color: #666; font-size: 16px;">Your One-Time Password (OTP) is:</p>
        <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; margin: 20px 0; border-radius: 5px;">
          <strong>${otp}</strong>
        </div>
        <p style="color: #666; font-size: 14px;">This OTP is valid for 1 hour. Please do not share this OTP with anyone.</p>
        <p style="color: #666; font-size: 14px;">If you didn't request this OTP, please ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">This is an automated message, please do not reply.</p>
      </div>
    `
  };

  return transporter.sendMail(mailOptions);
};

module.exports = {
  generateOtp,
  sendOtpEmail
}; 