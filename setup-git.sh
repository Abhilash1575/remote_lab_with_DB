#!/bin/bash

# GitHub Repository Setup Script
# Run this after install.sh to push code to GitHub

set -e

echo "========================================"
echo "GitHub Repository Setup"
echo "========================================"

# Get git remote URL
read -p "Enter your GitHub repository URL (e.g., https://github.com/username/virtual_lab.git): " REPO_URL

if [ -z "$REPO_URL" ]; then
    echo "Error: Repository URL is required"
    exit 1
fi

# Add remote if not exists
if ! git remote get-url origin &>/dev/null; then
    git remote add origin "$REPO_URL"
    echo "Added remote origin: $REPO_URL"
else
    echo "Remote origin already exists"
fi

# Check if repository exists on GitHub
echo ""
echo "IMPORTANT: Before pushing, you need to create the repository on GitHub:"
echo ""
echo "1. Go to https://github.com/new"
echo "2. Repository name: virtual_lab"
echo "3. Description: Virtual Lab - Remote Embedded Systems Laboratory"
echo "4. Set as Public or Private as needed"
echo "5. DO NOT initialize with README, .gitignore, or license"
echo "6. Click 'Create repository'"
echo ""
echo "Then run these commands on your Pi:"
echo ""
echo "  git branch -M main"
echo "  git push -u origin main"
echo ""
echo "Enter your GitHub credentials when prompted."

read -p "Have you created the GitHub repository? (y/n): " CONFIRM

if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
    echo ""
    echo "Pushing to GitHub..."
    git push -u origin main
    echo ""
    echo -e "${GREEN}Successfully pushed to GitHub!${NC}"
else
    echo ""
    echo "Please create the repository on GitHub first, then run:"
    echo "  git branch -M main"
    echo "  git push -u origin main"
fi
