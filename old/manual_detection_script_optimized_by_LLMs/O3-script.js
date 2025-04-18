/**
 * Detects the Swagger‑UI major version (2.x → 5.x).
 * Returns a JSON‐string with `{ method, version, major }`.
 */
(function detectSwaggerUIVersion() {
  try {
    /*───────────────────────────
     | 1. window.versions object |
     ───────────────────────────*/
    if (
      window.versions &&
      window.versions.swaggerUi &&
      window.versions.swaggerUi.version
    ) {
      const v = window.versions.swaggerUi.version;
      const major = v.startsWith("5")
        ? "5.x"
        : v.startsWith("4")
          ? "4.x"
          : v.startsWith("3")
            ? "3.x"
            : "unknown";

      return JSON.stringify({ method: "versions-object", version: v, major });
    }

    /* Fallback for very early 3.x builds that have the object but no `.version` */
    if (window.versions && window.versions.swaggerUi) {
      return JSON.stringify({
        method: "versions-object-3x",
        version: window.versions.swaggerUi.version || "3.x",
        major: "3.x",
      });
    }

    /*──────────────────────────────────────
     | 2. SwaggerUIBundle.version (3–5)    |
     ──────────────────────────────────────*/
    if (window.SwaggerUIBundle && window.SwaggerUIBundle.version) {
      const v = window.SwaggerUIBundle.version;
      const major = v.startsWith("5")
        ? "5.x"
        : v.startsWith("4")
          ? "4.x"
          : v.startsWith("3")
            ? "3.x"
            : "unknown";

      return JSON.stringify({ method: "swagger-ui-bundle", version: v, major });
    }

    /*──────────────────────────
     | 3. ui.getConfigs() (3+)  |
     ──────────────────────────*/
    if (window.ui && typeof window.ui.getConfigs === "function") {
      try {
        const cfg = window.ui.getConfigs();
        if (cfg && cfg.version) {
          const v = cfg.version;
          const major = v.startsWith("5")
            ? "5.x"
            : v.startsWith("4")
              ? "4.x"
              : v.startsWith("3")
                ? "3.x"
                : "unknown";

          return JSON.stringify({ method: "ui-configs", version: v, major });
        }
      } catch (e) {
        /* Some builds throw if UI isn’t initialised yet */
        console.error("ui.getConfigs() failed:", e);
      }
    }

    /*─────────────────────────────────────
     | 4. Global SwaggerUI indicators     |
     ─────────────────────────────────────*/
    if (window.SwaggerUI) {
      /* 5.x exposes extra helpers such as ".plugins" / ".systems" */
      if (window.SwaggerUI.plugins || window.SwaggerUI.systems) {
        return JSON.stringify({
          method: "swagger-ui-5x-apis",
          version: "5.x",
          major: "5.x",
        });
      }

      /* Pre‑3 builds ship only the “SwaggerUI” constructor (no ‑Bundle) */
      if (!window.SwaggerUIBundle) {
        return JSON.stringify({
          method: "swagger-ui-global",
          version: "2.x",
          major: "2.x",
        });
      }
    }

    /*────────────────────────────
     | 5. New 5.x global symbol   |
     ────────────────────────────*/
    if (window.SwaggerUINext) {
      return JSON.stringify({
        method: "swagger-ui-next",
        version: window.SwaggerUINext.version || "5.x",
        major: "5.x",
      });
    }

    /*───────────────────────────────
     | 6. data‑swagger‑version attr |
     ───────────────────────────────*/
    for (const el of document.querySelectorAll("[data-swagger-version]")) {
      const v = el.getAttribute("data-swagger-version");
      if (v && v.startsWith("5")) {
        return JSON.stringify({
          method: "dom-data-attribute",
          version: v,
          major: "5.x",
        });
      }
    }

    /*─────────────────────────────────
     | 7. 5.x specific CSS selectors  |
     ─────────────────────────────────*/
    const v5Selectors = [
      ".swagger-ui-v5",
      ".swagger-ui-5",
      ".swagger-v5",
      "[class*=swagger-ui-v5]",
    ];
    for (const sel of v5Selectors) {
      if (document.querySelector(sel)) {
        return JSON.stringify({
          method: "dom-class-detection-5x",
          version: "5.x",
          major: "5.x",
        });
      }
    }

    /*────────────────────────────────────
     | 8. DOM structure / visual clues   |
     ────────────────────────────────────*/
    const swagger2Container = document.querySelector("#swagger-ui-container");
    const swaggerSection = document.querySelector(".swagger-section");
    const swagger3Element = document.querySelector(".swagger-ui");

    /* Heuristics for 5.x */
    const hasTryIt = document.querySelectorAll(".try-out__btn").length > 0;
    const hasOpblocks =
      document.querySelectorAll(".opblock-summary-path").length > 0;
    const hasServers = document.querySelectorAll(".servers-title").length > 0;

    if (hasTryIt && hasOpblocks && hasServers) {
      return JSON.stringify({
        method: "dom-component-structure",
        version: "5.x",
        major: "5.x",
      });
    }

    /* 3.x vs 4.x */
    if (swagger3Element && !swagger2Container) {
      const is4x =
        document.querySelectorAll(".model-box").length > 0 ||
        document.querySelectorAll(".model-title__text").length > 0;

      return JSON.stringify({
        method: "dom-detection",
        version: is4x ? "4.x" : "3.x",
        major: is4x ? "4.x" : "3.x",
      });
    }

    /* 2.x legacy layout */
    if (swagger2Container || swaggerSection) {
      return JSON.stringify({
        method: "dom-detection",
        version: "2.x",
        major: "2.x",
      });
    }

    /*───────────────────────────────
     | 9. File‑name pattern in <script>
     ───────────────────────────────*/
    for (const s of document.querySelectorAll("script[src]")) {
      const src = s.getAttribute("src");
      if (!src) continue;

      if (/swagger-ui[-@]5/.test(src)) {
        return JSON.stringify({
          method: "script-src-detection",
          version: "5.x",
          major: "5.x",
        });
      }
      if (/swagger-ui[-@]4/.test(src)) {
        return JSON.stringify({
          method: "script-src-detection",
          version: "4.x",
          major: "4.x",
        });
      }
      if (/swagger-ui[-@]3/.test(src)) {
        return JSON.stringify({
          method: "script-src-detection",
          version: "3.x",
          major: "3.x",
        });
      }
      if (/swagger-ui[-@]2/.test(src)) {
        return JSON.stringify({
          method: "script-src-detection",
          version: "2.x",
          major: "2.x",
        });
      }
    }

    /*─────────────────────────────────
     | Nothing matched → give up      |
     ─────────────────────────────────*/
    return JSON.stringify({
      method: "detection-failed",
      error: "No known Swagger‑UI patterns detected",
      major: "",
    });
  } catch (err) {
    return JSON.stringify({
      method: "detection-failed",
      error: err.toString(),
      major: "",
    });
  }
})();
