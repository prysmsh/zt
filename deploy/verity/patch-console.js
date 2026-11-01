//
// Hide the console's loading screen.
//
// While the console boots it shows the platform's logo above a spinner.
// That splash is replaced as soon as the console mounts, so hiding it
// removes the branding without changing anything the operator uses.
//
// The selector matches the loading screen's shape — a div holding an svg
// and a span — which nothing in the mounted console matches.
//
// The patch is idempotent, so it is safe to run on every start.
//

import { readFileSync, writeFileSync } from "node:fs";

const path = "/etc/logto/packages/console/dist/index.html";
const marker = "zt-console-hide-loading";

const style =
  `<style id="${marker}">#app>div:has(>svg+span){display:none!important}</style>`;

try {
  const html = readFileSync(path, "utf8");

  if (html.includes(marker)) {
    console.log("[zt] the console loading screen is already hidden");
  } else if (!html.includes("</head>")) {
    console.error("[zt] the console HTML has no </head>; nothing was patched");
  } else {
    writeFileSync(path, html.replace("</head>", `${style}</head>`));
    console.log("[zt] the console loading screen is hidden");
  }
} catch (error) {
  // A failure here must not stop the console from starting.
  console.error(`[zt] could not patch the console HTML: ${error.message}`);
}
