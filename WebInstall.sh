#!/bin/bash

mkdir STATICFILES_DIRS

# Update packages
sudo apt update -y

# Install PostgreSQL
sudo apt-get install postgresql -y

# Create PostgreSQL user and database
sudo -u postgres psql -c "CREATE USER postgres;"
# Prompt the user to enter a new password for the PostgreSQL user
echo "Please enter a new password for the PostgreSQL user:"
read postgres_password

# Change the PostgreSQL user's password
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '$postgres_password';"

sudo -u postgres psql -c "CREATE DATABASE test;"



# Install Python3 and pip
sudo apt install python3 python3-dev -y
sudo apt install python3-pip -y

# Install Python requirements
pip3 install -r ./ego/requirements.txt
pip3 install "censys==2.0.7; python_version > '3.8'" "censys==0.0.8; python_version <= '3.8'"
python3 manage.py makemigrations
python3 manage.py migrate

# Update packages again
sudo apt-get update -y

# Download and install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -xvf go1.21.0.linux-amd64.tar.gz
sudo mv go /usr/local

# Set Go environment variables
echo 'export GOROOT=/usr/local/go' >> ~/.profile
echo 'export GOPATH=$HOME/go' >> ~/.profile
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.profile
source ~/.profile

# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Prompt the user to enter a new value for expected_secret_code
echo "Please enter a new value for expected_secret_code:"
read new_secret_code

# Replace the value of expected_secret_code in /ego/views.py
sed -i "s/expected_secret_code = .*/expected_secret_code = '$new_secret_code'/" /ego/views.py

python3 manage.py collectstatic

#sudo apt-get install mailutils -y
#sudo apt-get install postfix dovecot-imapd dovecot-pop3d -y

#!/bin/bash

# Generate a random secret code
GENERATED_SECRET_CODE=$(openssl rand -base64 32)

# Path to the settings.py file
SETTINGS_FILE="ego/settings.py"

# Use sed to replace the line containing SECRET_CODE
sed -i "s/^SECRET_CODE = '.*'/SECRET_CODE = '${GENERATED_SECRET_CODE}'/" "$SETTINGS_FILE"

echo "SECRET_CODE updated successfully in $SETTINGS_FILE"
