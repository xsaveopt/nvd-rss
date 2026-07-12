# NVD RSS Generator

A simple service that generates an RSS feed from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/vuln/data-feeds) JSON 2.0 feeds. It filters vulnerabilities based on CVSS score and product names.

## Configuration

The application is configured using environment variables.

| Variable                  | Default             | Description                                                                                              |
| :------------------------ | :------------------ | :------------------------------------------------------------------------------------------------------- |
| `CVSS_THRESHOLD`          | `8.0`               | Minimum CVSS base score to include in the feed.                                                          |
| `PRODUCT_FILTER`          | `null`              | A string to filter vulnerabilities by product (e.g., "chrome", "windows"). Matches against CPE criteria. |
| `UPDATE_INTERVAL_MINUTES` | `30`                | Frequency (in minutes) to check the NVD feed for updates.                                                |
| `PORT`                    | `3000`              | The port the server listens on.                                                                          |
| `RSS_PATH`                | `/rss`              | The URL path where the RSS feed is served.                                                               |
| `NVD_FEED_URL`            | _(NVD Recent Feed)_ | The URL of the NVD JSON 2.0 GZ feed to consume.                                                          |

## Running the Project

### Local Development

```bash
pnpm install
pnpm start
```

### With Configuration

```bash
CVSS_THRESHOLD=9.0 PRODUCT_FILTER="windows" pnpm start
```

### Docker

```bash
docker build -t nvd-rss .
docker run -p 3000:3000 -e CVSS_THRESHOLD=9.0 nvd-rss
```
