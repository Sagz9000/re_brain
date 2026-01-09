FROM blacktop/ghidra:latest

USER root

# Install X11 / VNC dependencies
RUN apt-get update && apt-get install -y \
    xvfb \
    x11vnc \
    xterm \
    openbox \
    menu \
    python3-numpy \
    supervisor \
    net-tools \
    novnc \
    websockify \
    && rm -rf /var/lib/apt/lists/*

# Fix websockify import error commonly found in ubuntu packages
# Link novnc to webroot
RUN ln -s /usr/share/novnc /usr/share/novnc/vnc_lite.html /usr/share/novnc/index.html

# Setup Supervisor to run Xvfb + VNC + Ghidra
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create a startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV DISPLAY=:0
ENV GHIDRA_ARGS=""

EXPOSE 5900 6080

ENTRYPOINT ["/entrypoint.sh"]
