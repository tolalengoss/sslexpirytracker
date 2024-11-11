#!/bin/bash

# Define constants
INSTALL_DIR="/opt/managecerts"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="certs.service"

# Function to install Python and dependencies
install_python() {
    echo "Checking for Python 3..."
    if command -v python3 &> /dev/null; then
        echo -e "\033[32mPython 3 is already installed.\033[0m"
    else
        echo -e "\033[31mPython 3 not found. Installing Python 3...\033[0m"
        if [ -f /etc/debian_version ]; then
            # For Debian/Ubuntu
            sudo apt update
            sudo apt install -y python3 python3-venv python3-pip
        elif [ -f /etc/redhat-release ]; then
            # For Rocky Linux/CentOS
            sudo dnf install -y python3 python3-venv python3-pip || sudo yum install -y python3 python3-venv python3-pip
        else
            echo -e "\033[31mUnsupported OS. Please install Python 3 manually.\033[0m"
            exit 1
        fi
    fi
}

# Create the installation directory if it doesn't exist
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "\033[34mCreating installation directory: $INSTALL_DIR\033[0m"
    sudo mkdir -p "$INSTALL_DIR"
fi

# Move application files to the installation directory
echo -e "\033[34mMoving application files to $INSTALL_DIR\033[0m"
sudo cp -r ./* "$INSTALL_DIR"  # Copy all non-hidden files
sudo cp -r ./.env "$INSTALL_DIR"  # Copy the .env file explicitly

# Install Python and dependencies
install_python

# Create a virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo -e "\033[34mCreating virtual environment in $VENV_DIR\033[0m"
    python3 -m venv "$VENV_DIR"
fi

# Activate the virtual environment and install requirements
echo -e "\033[34mInstalling dependencies from requirements.txt\033[0m"
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$INSTALL_DIR/requirements.txt"
deactivate

# Create systemd service file
echo -e "\033[34mCreating systemd service file at /etc/systemd/system/$SERVICE_NAME\033[0m"
cat <<EOL | sudo tee /etc/systemd/system/$SERVICE_NAME > /dev/null
[Unit]
Description=SSL Certificate Monitoring Service
After=network.target networking.service

[Service]
Type=simple
User =root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$VENV_DIR/bin"
Environment="PYTHONPATH=$INSTALL_DIR"
Environment="FLASK_ENV=production"
ExecStart=$VENV_DIR/bin/python3 -u $INSTALL_DIR/app.py
Restart=on-failure
RestartSec=10
StartLimitIntervalSec=500
StartLimitBurst=5
LimitNOFILE=65535
LimitNPROC=4096
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd to recognize the new service
echo -e "\033[34mReloading systemd to recognize the new service\033[0m"
sudo systemctl daemon-reload

# Enable and start the service
echo -e "\033[34mEnabling and starting the $SERVICE_NAME service\033[0m"
sudo systemctl enable $SERVICE_NAME
sudo systemctl start $SERVICE_NAME

# Detect the host's IP address
HOST_IP=$(hostname -I | awk '{print $1}')
if [ -z "$HOST_IP" ]; then
    HOST_IP="0.0.0.0" # Fallback to 0.0.0.0 if no IP is detected
fi

# Output access URL and default credentials with a beautiful frame
echo -e "\n\033[32mInstallation completed successfully!\033[0m"
echo "╔═════════════════════════════════════════════════════╗"
echo "║                     ACCESS DETAILS                  ║"
echo "╠═════════════════════════════════════════════════════╣"
echo "║ Access URL: http://$HOST_IP:8080                    ║"
echo "║ Default Credentials: admin/admin                    ║"
echo "╚═════════════════════════════════════════════════════╝"