#!/bin/bash
# start_ghidra.sh
# Handles waiting for project initialization and starting the GUI

PROJECT_FILE="/ghidra/projects/reBrain.gpr"
LAUNCH_SCRIPT="/ghidra/support/launch.sh"
GHIDRA_CONFIG_DIR="/root/.config/ghidra/ghidra_12.0_PUBLIC"

echo "Ghidra Launcher: Initializing environment..."
mkdir -p "$GHIDRA_CONFIG_DIR"

# Bypass user agreement and tips
# Note: Using escaped spaces if needed, but typically standard key=value or quoted values work.
cat <<EOF > "$GHIDRA_CONFIG_DIR/preferences"
ACCEPTED_USER_AGREEMENT=true
USER_AGREEMENT=ACCEPT
Show\ Tip\ of\ the\ Day=false
GhidraSetupWizard=false
EOF

echo "Ghidra Launcher: Ensuring default project exists..."
mkdir -p /ghidra/projects
if [ ! -f "$PROJECT_FILE" ]; then
    echo "Ghidra Launcher: Creating default reBrain project by importing dummy file..."
    touch /tmp/init
    /ghidra/support/analyzeHeadless /ghidra/projects reBrain -import /tmp/init -deleteProject || true
    # Wait, -deleteProject? No, we want to KEEP the project.
    # But if we import /tmp/init, it stays there. That's fine.
    # Actually, simpler: just import and keep it.
    /ghidra/support/analyzeHeadless /ghidra/projects reBrain -import /tmp/init || true
fi

echo "Ghidra Launcher: Cleaning up stale project locks..."
rm -f /ghidra/projects/*.lock /ghidra/projects/*.lock~

echo "Ghidra Launcher: Installing LiveBridge.java to user scripts (Symlink)..."
mkdir -p /root/ghidra_scripts
ln -sf /ghidra/scripts/LiveBridge.java /root/ghidra_scripts/LiveBridge.java

echo "Ghidra Launcher: Waiting for DISPLAY :0..."
while ! xdpyinfo -display :0 >/dev/null 2>&1; do
    sleep 1
done

echo "Ghidra Launcher: Starting Ghidra with project $PROJECT_FILE..."

# Reverting to direct launch.sh to prevent restart loops.
# Manually invoking GhidraRun with proper classpath to ensure Extensions (Jython) load.
# The standard /ghidra/ghidraRun script sets up CP and calls launch.sh.
# If we run it directly, we need to make sure it doesn't background.
# 'exec /ghidra/ghidraRun' *should* work if it stays foreground.

# Debugging: Why does ghidraRun exit?
# It ends with: "${GHIDRA_HOME}/support/launch.sh" ... "${debugArgs[@]}" "$@"
# Be default launch.sh runs java in foreground.

# Maybe the issue is 'exec' with the wrapper? 
# Let's try running it without exec, just to be safe? No, that would exit script.

# Alternative: Go back to launch.sh but explicitly add the extension JARs?
# Too complex.

# Let's try a modified invocation that forces foreground.
# Actually, the previous 'launch.sh' invocation worked for VNC but failed Python.
# It failed Python because the classpath wasn't set up for extensions.

# Solution: Source the support/launch.properties or rely on Ghidra's auto-discovery?
# Ghidra discovers extensions via GHIDRA_EXTENSIONS_DIR? No.

# Let's try invoking the wrapper properly.
# Maybe the loop is because I kept the 'exec' but the previous script had a background loop?
# No, I removed the background loop.

# Wait! "ghidra (exit status 0; expected)"
# This means the process exited cleanly.
# If Ghidra GUI opens, blocks, and then closes... why?
# Unless it's crashing? Log says "Ghidra startup complete".

# If I use `ghidraRun`, maybe it detects something and exits?
# Let's force using the direct launch command BUT point to the `ghidraRun` logic?
# No.

# Let's just go back to the command that WORKED for VNC (launch.sh)
# AND add the Jython JAR to the classpath explicitly?
# Or just ensure the extension is enabled?
# The user said "Options are there".
# If I run launch.sh manually, maybe I missed a flag?

# Let's look at ghidraRun content? I can't easily.

# Let's try this:
# Use `launch.sh` but pass the `ghidra.Ghidra` class directly like before,
# BUT verify environment variables.

# Actually, I'll try to run ghidraRun WITHOUT exec, in a wait loop.
# This prevents the container from dying if it exits, giving me time to debug?
# No, supervisor restarts it anyway.

# Let's go back to the explicit `launch.sh` command line that was stable:
# "$LAUNCH_SCRIPT" fg jdk Ghidra 2G "" ghidra.GhidraRun "$PROJECT_FILE"
# And rely on the user manually enabling extensions? 
# But the user said "Ghidra was not started with PyGhidra".

# PyGhidra is a specific thing. 
# Wait. `ghidra.GhidraRun` IS the main class.
# Standard Ghidra just needs Jython extension enabled.

# Maybe `start_ghidra.sh` needs to export the classpath?
# Let's try adding the CLASSPATH env var before launch?

# Better:
# Use `exec /ghidra/support/launch.sh fg jdk Ghidra 2G "" ghidra.GhidraRun "$PROJECT_FILE"`
# AND ensure we don't have stray locks (I added cleanup).

# Why did `ghidraRun` loop?
# Maybe it forks?
# Let's try WITHOUT `exec` and just call it?
# /ghidra/ghidraRun "$PROJECT_FILE"
# Loop at end?

# Let's revert to the STABLE command (launch.sh) and address Python separately if needed.
# The user wants VNC back first.
# Background trigger for LiveBridge via xdotool hotkey
(
    exec > /tmp/bridge_trigger.log 2>&1
    echo "Ghidra Launcher: Monitoring for CodeBrowser to auto-start LiveBridge..."
    for i in {1..120}; do # Poll for 10 minutes
        # Search for Code Browser window
        WID=$(xdotool search --name "Code Browser" | head -n 1)
        if [ ! -z "$WID" ]; then
            echo "Ghidra Launcher: CodeBrowser detected ($WID). Sending Ctrl+Shift+L..."
            xdotool windowactivate --sync $WID
            sleep 2
            xdotool key "ctrl+shift+l"
            sleep 2
            
            # Check if port 9999 is now active
            if netstat -tuln | grep -q ":9999 "; then
                echo "Ghidra Launcher: LiveBridge is ACTIVE on 9999. Success."
                break
            fi
            echo "Ghidra Launcher: Hotkey sent but port 9999 not open yet. Retrying..."
        fi
        sleep 5
    done
    echo "Ghidra Launcher: Monitor finished."
) &

exec "$LAUNCH_SCRIPT" fg jdk Ghidra 2G "" ghidra.GhidraRun "$PROJECT_FILE"
