# Releasing CommentInject v1.0.0

## 1. GitHub (Terminal)
    cd /Users/sc/Documents/RP/1_CURRENT_PAPERS/09_CommentInject_Dataset/CommentInject_release
    git init -b main
    git add .
    git commit -m "CommentInject v1.0.0: 30 samples, 12 strategies, 3,360 trials"
    gh repo create sunny-chokshi/commentinject --public --source=. --remote=origin --push

## 2. Zenodo switch (browser)
zenodo.org > your name (top right) > GitHub > Sync now > flip "commentinject" to ON.

## 3. Release (Terminal, same folder) - this is what mints the DOI
    gh release create v1.0.0 --title "CommentInject v1.0.0" --notes "30 vulnerable Python samples, 12 adversarial comment strategies, 3,360 trials across four studies."

Wait 2-5 minutes, then check zenodo.org > Uploads for the new record and its DOI.

## 4. Hugging Face (browser)
huggingface.co > New > Dataset > name: commentinject > License: cc-by-4.0 > Public > Create.
Files and versions > Add file > Upload files > drag in ALL 7 files from the huggingface/ folder > Commit.

## 5. After the DOI
Send the DOI to Claude: it goes into the README badge, the HF card, ORCID Works, DOI_Register.xlsx and the evidence folder.
