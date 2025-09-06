#!/bin/bash

# check if commit message is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <commit-message>"
  exit 1
fi

msg=$1
echo "=== Committing changes to main branch ==="
# commit changes to main branch
git add .
git commit -m "$msg"
git push origin main
echo "=== Committing to main branch -- Complete ==="

echo "=== Building site with Hugo ==="
# build site
hugo --cleanDestinationDir
echo "=== Building -- Complete ==="


echo "=== Deploying to gh-pages branch ==="
# push to gh-pages
cd public || exit
git add .
git commit -m "$msg"
git push origin gh-pages
cd ..

echo "=== Deployment -- Complete ==="
