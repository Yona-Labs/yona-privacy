

lsof -i:3001
lsof -i:8784
lsof -i:8899

# Kill all processes on these ports
./kill-ports.sh
