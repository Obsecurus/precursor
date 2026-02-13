# GitHub Pages Deployment

## 1) Enable GitHub Pages

1. Open repository settings.
2. Under Pages, set source to GitHub Actions.
3. Merge/push changes containing `.github/workflows/pages.yml` and `site/`.

## 2) Configure custom domain

This repository includes `site/CNAME` with:

```text
precursor.hashdb.io
```

GitHub Pages should detect this automatically after deployment.

## 3) Create/update DNS record at your DNS provider

Create this record:
- Type: `CNAME`
- Host: `precursor`
- Value: `obsecurus.github.io`
- TTL: `300` (or automatic)

## 4) Verify

After DNS propagation:

```bash
dig +short precursor.hashdb.io
```

Then visit:

```text
https://precursor.hashdb.io
```
