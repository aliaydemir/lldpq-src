#!/usr/bin/env python3
"""
LLDPq Alert System - Test script for Slack webhook configuration
Copyright (c) 2024 LLDPq Project - Licensed under MIT License

This script sends test alerts to verify Slack webhook configuration.
Usage: python3 verify_alerts.py
"""

import yaml
import requests
import json
import datetime
import sys
import os

def load_config():
    """Load notification configuration"""
    config_file = "notifications.yaml"
    
    if not os.path.exists(config_file):
        print(f"❌ Configuration file not found: {config_file}")
        print("   Please create notifications.yaml first")
        return None
    
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        return None



def test_slack_webhook(webhook_url, channel, username, icon_emoji):
    """Test Slack webhook"""
    print("🔹 Testing Slack webhook...")
    
    payload = {
        "channel": channel,
        "username": username,
        "icon_emoji": icon_emoji,
        "attachments": [{
            "color": "#0066CC",
            "title": "🧪 LLDPq Test Alert",
            "text": "This is a test message to verify Slack integration is working correctly.",
            "fields": [
                {"title": "Status", "value": "TEST MESSAGE", "short": True},
                {"title": "Time", "value": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "short": True}
            ]
        }]
    }
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 200:
            print("   ✅ Slack webhook working correctly!")
            return True
        else:
            print(f"   ❌ Slack webhook failed with status code: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"   ❌ Slack webhook error: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 LLDPq Alert System - Webhook Test")
    print("=" * 40)
    
    # Load configuration
    config = load_config()
    if not config:
        sys.exit(1)
    
    notifications = config.get('notifications', {})
    
    if not notifications.get('enabled', False):
        print("❌ Notifications are disabled in configuration")
        print("   Set 'notifications.enabled: true' in notifications.yaml")
        sys.exit(1)
    
    print("✅ Notifications are enabled")
    print()
    
    # Test results
    tests_passed = 0
    total_tests = 0
    

    
    # Test Slack
    slack_config = notifications.get('slack', {})
    if slack_config.get('enabled', False):
        total_tests += 1
        webhook_url = slack_config.get('webhook', '')
        channel = slack_config.get('channel', '#network-alerts')
        username = slack_config.get('username', 'LLDPq Bot')
        icon_emoji = slack_config.get('icon_emoji', ':warning:')
        
        if not webhook_url:
            print("❌ Slack webhook URL is empty")
        elif not webhook_url.startswith('https://hooks.slack.com/services/'):
            print("❌ Slack webhook URL format appears incorrect")
            print(f"   Expected: https://hooks.slack.com/services/...")
            print(f"   Got: {webhook_url[:50]}...")
        else:
            if test_slack_webhook(webhook_url, channel, username, icon_emoji):
                tests_passed += 1
    else:
        print("ℹ️  Slack integration is disabled")
    
    print()
    print("=" * 40)
    
    if total_tests == 0:
        print("⚠️  No webhook integrations are enabled")
        print("   Enable Slack in notifications.yaml to test")
    elif tests_passed == total_tests:
        print(f"🎉 All tests passed! ({tests_passed}/{total_tests})")
        print("   Your webhook configuration is working correctly")
        print("   Alerts will be sent every 10 minutes via lldpq cron job")
    else:
        print(f"❌ Some tests failed ({tests_passed}/{total_tests} passed)")
        print("   Please check your webhook URLs and configuration")
    
    print()
    print("📖 Next steps:")
    print("   1. Adjust thresholds in notifications.yaml if needed")
    print("   2. Wait for monitoring data to be collected (monitor.sh)")
    print("   3. Alerts will be automatically sent when thresholds are exceeded")
    print("   4. Check alert states in: monitor/alert-states/")

if __name__ == "__main__":
    main()