#!/bin/bash
echo "Starting reAIghidra Analysis Node..."
/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
