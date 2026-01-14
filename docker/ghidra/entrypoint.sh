#!/bin/bash
echo "Starting reAIghidra Analysis Node..."
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
