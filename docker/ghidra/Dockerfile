FROM blacktop/ghidra:latest

USER root

# Install X11 / VNC dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb \
    x11-utils \
    x11vnc \
    xterm \
    fluxbox \
    menu \
    python3-numpy \
    supervisor \
    autocutsel \
    net-tools \
    novnc \
    websockify \
    xdotool \
    gdb \
    gdbserver \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Fix websockify import error commonly found in ubuntu packages
# Link novnc to webroot
RUN mkdir -p /usr/share/novnc && ln -sf /usr/share/novnc/vnc_lite.html /usr/share/novnc/index.html

# Setup Supervisor to run Xvfb + VNC + Ghidra
RUN echo '[supervisord]' > /etc/super.conf && \
    echo 'nodaemon=true' >> /etc/super.conf && \
    echo '' >> /etc/super.conf && \
    echo '[program:xvfb]' >> /etc/super.conf && \
    echo 'command=/usr/bin/Xvfb :0 -screen 0 1920x1080x24' >> /etc/super.conf && \
    echo 'autorestart=true' >> /etc/super.conf && \
    echo '' >> /etc/super.conf && \
    echo '[program:fluxbox]' >> /etc/super.conf && \
    echo 'command=/usr/bin/fluxbox' >> /etc/super.conf && \
    echo 'environment=DISPLAY=":0"' >> /etc/super.conf && \
    echo 'autorestart=true' >> /etc/super.conf && \
    echo '' >> /etc/super.conf && \
    echo '[program:x11vnc]' >> /etc/super.conf && \
    echo 'command=/usr/bin/x11vnc -display :0 -forever -shared -passwd ghidra -listen 0.0.0.0 -xkb' >> /etc/super.conf && \
    echo 'autorestart=true' >> /etc/super.conf && \
    echo '' >> /etc/super.conf && \
    echo '[program:autocutsel]' >> /etc/super.conf && \
    echo 'command=/usr/bin/autocutsel -fork' >> /etc/super.conf && \
    echo 'autorestart=true' >> /etc/super.conf && \
    echo '' >> /etc/super.conf && \
    echo '[program:websockify]' >> /etc/super.conf && \
    echo 'command=/usr/bin/websockify --web=/usr/share/novnc 0.0.0.0:6080 127.0.0.1:5900' >> /etc/super.conf && \
    echo 'autorestart=true' >> /etc/super.conf && \
    echo '' >> /etc/super.conf && \
    echo '[program:ghidra]' >> /etc/super.conf && \
    echo 'command=/start_ghidra.sh' >> /etc/super.conf && \
    echo 'environment=DISPLAY=":0"' >> /etc/super.conf && \
    echo 'autorestart=true' >> /etc/super.conf && \
    echo '' >> /etc/super.conf && \
    echo '[program:job_watcher]' >> /etc/super.conf && \
    echo 'command=python3 -u /ghidra/scripts/job_watcher.py' >> /etc/super.conf && \
    echo 'autorestart=true' >> /etc/super.conf

COPY start_ghidra.sh /start_ghidra.sh
RUN tr -d '\r' < /start_ghidra.sh > /start_ghidra.sh.tmp && mv /start_ghidra.sh.tmp /start_ghidra.sh && chmod +x /start_ghidra.sh

RUN echo '#!/bin/bash' > /entrypoint.sh && \
    echo 'echo "Starting reAIghidra Analysis Node..."' >> /entrypoint.sh && \
    echo 'rm -f /tmp/.X0-lock /tmp/.X11-unix/X0' >> /entrypoint.sh && \
    echo 'exec /usr/bin/supervisord -c /etc/super.conf' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENV DISPLAY=:0
EXPOSE 5900 6080
ENTRYPOINT ["/entrypoint.sh"]
