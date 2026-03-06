#!/bin/bash
# Download Wazuh single-node configuration files and certificates

BASE_URL="https://raw.githubusercontent.com/wazuh/wazuh-docker/master/single-node"
CONFIG_DIR="/workspace/playground/config"

echo "Creating config directory structure..."
mkdir -p "$CONFIG_DIR/wazuh_cluster"
mkdir -p "$CONFIG_DIR/wazuh_indexer"
mkdir -p "$CONFIG_DIR/wazuh_indexer_ssl_certs"
mkdir -p "$CONFIG_DIR/wazuh_dashboard"

echo "Downloading Wazuh configuration files..."

# Wazuh Manager config
curl -sL "$BASE_URL/config/wazuh_cluster/wazuh_manager.conf" -o "$CONFIG_DIR/wazuh_cluster/wazuh_manager.conf"

# Wazuh Indexer configs
curl -sL "$BASE_URL/config/wazuh_indexer/wazuh.indexer.yml" -o "$CONFIG_DIR/wazuh_indexer/wazuh.indexer.yml"
curl -sL "$BASE_URL/config/wazuh_indexer/internal_users.yml" -o "$CONFIG_DIR/wazuh_indexer/internal_users.yml"

# Wazuh Dashboard configs
curl -sL "$BASE_URL/config/wazuh_dashboard/opensearch_dashboards.yml" -o "$CONFIG_DIR/wazuh_dashboard/opensearch_dashboards.yml"
curl -sL "$BASE_URL/config/wazuh_dashboard/wazuh.yml" -o "$CONFIG_DIR/wazuh_dashboard/wazuh.yml"

# SSL Certificates
echo "Downloading SSL certificates..."
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/root-ca.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/root-ca.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/root-ca-manager.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/root-ca-manager.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/admin.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/admin.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/admin-key.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/admin-key.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/wazuh.indexer.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/wazuh.indexer.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/wazuh.manager.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/wazuh.manager.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/wazuh.manager-key.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/wazuh.manager-key.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/wazuh.dashboard.pem"
curl -sL "$BASE_URL/config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem" -o "$CONFIG_DIR/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem"

echo "Setting proper permissions..."
chmod -R 644 "$CONFIG_DIR"
chmod 600 "$CONFIG_DIR/wazuh_indexer_ssl_certs/"*.pem

echo "Download complete! Files in: $CONFIG_DIR"
ls -lR "$CONFIG_DIR"
