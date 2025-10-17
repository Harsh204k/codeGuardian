#!/bin/bash

# Step 1: Move to your home working directory
cd ~/  # or any directory you prefer on HPC

# Step 2: Pull latest code if repo exists, otherwise clone fresh
if [ -d "codeGuardian" ]; then
    echo "Updating existing codeGuardian repo..."
    cd codeGuardian
    git pull
else
    echo "Cloning fresh codeGuardian repo..."
    git clone https://github.com/Harsh204k/codeGuardian.git
    cd codeGuardian
fi

# Step 3: Ready to run scripts inside repo
echo "Current directory:"
pwd
ls -l
