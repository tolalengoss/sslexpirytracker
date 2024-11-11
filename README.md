# An Open Source WebBase SSL Certs Expiry Tracker

The SSL Certificate Expiry Tracker is an open source web application built with Flask that helps users monitor the expiration dates of SSL certificates for various domains. The application provides notifications via Telegram when certificates are nearing expiration, allowing users to take timely action to renew them.

### ✨ Core Functionality
- **Features**
  - User Authentication: Secure login for administrators to manage monitored sites.
  - Domain Monitoring: Add, edit, and delete domains to monitor their SSL certificate expiration dates.
  - Notifications: Receive alerts via Telegram when certificates are about to expire, with customizable thresholds for alerts and warnings.
  - Database Storage: Uses SQLite to store site information and settings.
  - CSV Export: Export the list of monitored sites and their SSL certificate details to a CSV file.
  - Error Handling: Graceful handling of errors with informative messages.

![sslexpirytracker](https://tolaleng.com/storage/images/ssltracker/ssltracker-light.png)
![sslexpirytracker](https://tolaleng.com/storage/images/ssltracker/ssltracker-dark.png)

## Demo
🌐 [![Live Demo](sslexpirytracker.oss.tolaleng.com) - Check out the working demo

### 📖 Usage
- Login: Use the admin credentials specified in the .env file to log in.
- Add Sites: Use the interface to add domains you want to monitor.
- Receive Notifications: Ensure your Telegram bot is set up to receive notifications about expiring certificates.
- Export Data: You can export the monitored sites and their details to a CSV file

## Installation

### 🚀 Automatic Installation (Recommended)
Clone the repository:
```bash
   git clone https://github.com/tolalengoss/sslexpirytracker.git && cd sslexpirytracker && chmod +x installation-all-os.sh && sudo ./installation-all-os.sh
```

### 🚀 Short-Term Roadmap
- HTTP (S) Monitoring and Alerts
- Add more notification channel (Signal, Slack, Discord)
- Detail Monitoring Domain Static (Up & Down)
- UI Improvement
