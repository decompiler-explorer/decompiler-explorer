#!/bin/sh

ANGR_VERSION=$(python -c "import feedparser; print(feedparser.parse('https://pypi.org/rss/project/angr/releases.xml').entries[0].title)")
sed -i "s/^RUN pip install --user 'angr.*$/RUN pip install --user 'angr~=$ANGR_VERSION'/g" runners/decompiler/Dockerfile
if [ ! -z "$(git diff --name-only)" ]; then
    git checkout -b angr-$ANGR_VERSION
    git add runners/decompiler/Dockerfile
    git config --global user.name "Github Actions"
    git commit -m "Update angr to $ANGR_VERSION"
    git push origin angr-$ANGR_VERSION
    gh pr create --fill --assignee twizmwazin
fi
