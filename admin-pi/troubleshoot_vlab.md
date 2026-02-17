# VLAB Service Troubleshooting

## Problem Summary
- Service name: vlabiisc.service
- Current status: Failed (Result: exit-code)
- Expected behavior: Server should be running on 10.114.62.214:5000
- Current network IP: 10.114.62.214

## Troubleshooting Steps

1. Check the service configuration file
2. Check the main application file app.py
3. Check the Python environment and dependencies
4. Run the application manually to get error details
5. Check if port 5000 is available
6. Check system logs for more details
7. Fix any identified issues
8. Restart the service and verify

## Files to Check
- /etc/systemd/system/vlabiisc.service (service config)
- /home/abhi/virtual_lab/app.py (main application)
- /home/abhi/virtual_lab/requirements.txt (dependencies)