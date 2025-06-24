# SLD GC Portal

A modern, secure, and user-friendly gift card management system that allows users to convert their gift cards to cash through a streamlined process.

## 🌟 Features

- **Secure Authentication**
  - Email-based login/registration
  - OTP verification system
  - Session management

- **Gift Card Management**
  - Support for multiple gift card types:
    - Roblox (100, 400, 1000)
    - Overwatch (200, 500, 1000)
    - Amazon (50, 100, 500)
  - Video proof upload system
  - Real-time status tracking

- **Payment Options**
  - UPI transfers
  - Paytm integration
  - Crypto transfer support

- **Admin Dashboard**
  - Real-time submission monitoring
  - Status management
  - User communication system
  - Video proof verification

- **Modern UI/UX**
  - Responsive design
  - Dark theme with glass morphism
  - Animated transitions
  - Interactive elements

## 🚀 Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Modern web browser

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sld-gc-portal.git
cd sld-gc-portal
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp .env.example .env
```
Edit `.env` with your configuration.

4. Start the development server:
```bash
npm run dev
```

## 📁 Project Structure

```
sld-gc-portal/
├── public/
│   ├── index.html      # Main application page
│   ├── status.html     # Status tracking page
│   └── admin.html      # Admin dashboard
├── src/
│   ├── api/           # API endpoints
│   ├── config/        # Configuration files
│   ├── models/        # Database models
│   └── utils/         # Utility functions
├── .env               # Environment variables
└── package.json       # Project dependencies
```

## 🔒 Security Features

- OTP-based authentication
- Secure session management
- File upload validation
- Input sanitization
- XSS protection
- CSRF protection

## 💻 Technology Stack

- **Frontend**
  - HTML5
  - Tailwind CSS
  - JavaScript (ES6+)
  - Font Awesome icons

- **Backend**
  - Node.js
  - Express.js
  - MongoDB

- **Services**
  - File2Link for video uploads
  - Email service for OTP
  - Payment gateway integration

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Team

- **Shirt Less Digital** - *Initial work* - [YouTube Channel](https://www.youtube.com/@shirtlessdigital)

## 🙏 Acknowledgments

- Thanks to all contributors
- Inspired by the need for a secure gift card management system
- Built with modern web technologies

## 📞 Support

For support, email contact@shirtlessdigital.com or visit our [YouTube Channel](https://www.youtube.com/@shirtlessdigital) 