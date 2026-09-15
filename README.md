# nvd-rss

A small web service that turns the [National Vulnerability Database](https://nvd.nist.gov/vuln/data-feeds) JSON 2.0 feed into an RSS feed you can follow in any reader.
It downloads the gzipped feed on startup and again on a fixed interval, keeps every CVE whose highest CVSS base score across v3.1, v3.0 and v2 meets the threshold, and can narrow that down further to a single product.
Each item links to the CVE's page on nvd.nist.gov, and the feed answers with a 503 until the first download has finished.

## Configuration

Everything is set through environment variables.

| Variable                  | Default                                                             | Description                                                                                       |
| :------------------------ | :------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------ |
| `CVSS_THRESHOLD`          | `8.0`                                                               | Minimum CVSS base score for a CVE to appear in the feed.                                          |
| `PRODUCT_FILTER`          | unset                                                               | Keeps only CVEs whose CPE criteria contain this text, case-insensitively, like chrome or windows. |
| `UPDATE_INTERVAL_MINUTES` | `30`                                                                | How often the NVD feed is downloaded again.                                                       |
| `PORT`                    | `3000`                                                              | Port the server listens on.                                                                       |
| `RSS_PATH`                | `/rss`                                                              | Path the RSS feed is served at.                                                                   |
| `NVD_FEED_URL`            | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz` | Gzipped NVD JSON 2.0 feed to read from.                                                           |

## Running

The container image is published to GitHub Container Registry as ghcr.io/xsaveopt/nvd-rss, tagged latest and by version for releases, and dev for the main branch.

```sh
docker run -p 3000:3000 -e CVSS_THRESHOLD=9.0 ghcr.io/xsaveopt/nvd-rss:latest
```

Running from source needs Node 26 and pnpm, both pinned in mise.toml, since Node runs the TypeScript directly.

```sh
pnpm install
CVSS_THRESHOLD=9.0 PRODUCT_FILTER=windows pnpm start
```

The image can also be built from the Dockerfile in the repo.

```sh
docker build -t nvd-rss .
```

## License

GPL-2.0, see LICENSE.
