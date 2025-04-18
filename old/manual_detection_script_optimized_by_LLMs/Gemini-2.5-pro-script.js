(function () {
  // Helper function to determine major version from a version string
  function getMajorVersion(versionString) {
    if (typeof versionString !== "string") {
      return "unknown";
    }
    if (versionString.startsWith("5")) return "5.x";
    if (versionString.startsWith("4")) return "4.x";
    if (versionString.startsWith("3")) return "3.x";
    // Add check for 2.x if version string might explicitly contain it
    if (versionString.startsWith("2")) return "2.x";
    return "unknown";
  }

  try {
    // Method 1: Try window.versions object (preferred, often contains explicit version)
    // Check safely for nested properties and ensure version is a string
    if (
      window.versions &&
      window.versions.swaggerUi &&
      typeof window.versions.swaggerUi.version === "string"
    ) {
      const v = window.versions.swaggerUi.version;
      const mj = getMajorVersion(v);
      // Only return if major version is determined, otherwise fallback might be better
      if (mj !== "unknown") {
        return JSON.stringify({
          method: "versions-object",
          version: v,
          major: mj,
        });
      }
    }

    // Method 2: Try SwaggerUIBundle.version (Common in 3.x, 4.x, 5.x standard bundles)
    if (
      window.SwaggerUIBundle &&
      typeof window.SwaggerUIBundle.version === "string"
    ) {
      const v = window.SwaggerUIBundle.version;
      const mj = getMajorVersion(v);
      if (mj !== "unknown") {
        return JSON.stringify({
          method: "swagger-ui-bundle",
          version: v,
          major: mj,
        });
      }
    }

    // Method 3: Try ui.getConfigs() (Available in 3.x+, but might not be initialized)
    // `ui` is the common variable name for the Swagger UI instance
    if (window.ui && typeof window.ui.getConfigs === "function") {
      try {
        const config = window.ui.getConfigs();
        // Check if config and its version property exist and version is a string
        if (config && typeof config.version === "string") {
          const v = config.version;
          const mj = getMajorVersion(v);
          if (mj !== "unknown") {
            return JSON.stringify({
              method: "ui-configs",
              version: v,
              major: mj,
            });
          }
        }
      } catch (configError) {
        // Some versions throw errors if getConfigs is called too early or if `ui` isn't fully ready.
        console.warn(
          "Could not get version from ui.getConfigs():",
          configError.message,
        );
      }
    }

    // Method 4: Look for global SwaggerUI object and infer based on properties
    // The 'SwaggerUI' constructor function exists in v3, v4, v5. Its *properties* differ.
    // 'SwaggerUI' also existed in v2, but often without SwaggerUIBundle.
    if (window.SwaggerUI) {
      // Check for 5.x-specific static properties (plugins/systems were prominent additions)
      if (window.SwaggerUI.plugins || window.SwaggerUI.systems) {
        // High confidence this is 5.x or related structure
        return JSON.stringify({
          method: "swagger-ui-5x-apis",
          version: "5.x inferred", // Cannot get exact version here easily
          major: "5.x",
        });
      }
      // If SwaggerUI exists but SwaggerUIBundle does NOT, it's likely 2.x
      // (Bundle was introduced later)
      else if (!window.SwaggerUIBundle) {
        return JSON.stringify({
          method: "swagger-ui-global-no-bundle",
          version: "2.x inferred",
          major: "2.x",
        });
      }
      // If SwaggerUI exists and SwaggerUIBundle exists, Method 2 should have caught it.
      // If it falls through here, it might be an unusual setup (e.g., v3/v4 without bundle version property)
      // We can make an educated guess based on the presence of SwaggerUI + Bundle
      else if (window.SwaggerUIBundle) {
        // Cannot reliably distinguish 3.x/4.x here without version property
        // Let DOM methods try to refine this
        console.warn(
          "Found SwaggerUI and SwaggerUIBundle, but Bundle had no version property.",
        );
      }
    }

    // Method 5: Check for SwaggerUINext (Potentially a 5.x specific global or future version indicator)
    if (window.SwaggerUINext) {
      // Try to get a version if available, otherwise default to 5.x
      const v =
        typeof window.SwaggerUINext.version === "string"
          ? window.SwaggerUINext.version
          : "5.x inferred";
      return JSON.stringify({
        method: "swagger-ui-next",
        version: v,
        major: "5.x", // Assuming SwaggerUINext implies 5.x
      });
    }

    // --- DOM Based Checks (Less reliable, used as fallback) ---

    // Method 6: Look for 5.x specific data attributes in the DOM
    // This relies on developers explicitly adding this attribute.
    try {
      const dataAttrs = document.querySelectorAll("[data-swagger-version]");
      for (let i = 0; i < dataAttrs.length; i++) {
        const versionAttr = dataAttrs[i].getAttribute("data-swagger-version");
        // Check if attribute value looks like a v5 version
        if (
          versionAttr &&
          typeof versionAttr === "string" &&
          versionAttr.trim().startsWith("5")
        ) {
          return JSON.stringify({
            method: "dom-data-attribute",
            version: versionAttr,
            major: "5.x",
          });
        }
      }
    } catch (domError) {
      console.warn("DOM query error (data-attr):", domError.message);
    }

    // Method 7: Check for indicative CSS classes (potentially version-specific or custom)
    try {
      const swaggerVersionClasses = [
        ".swagger-ui-v5", // Example specific class
        ".swagger-ui--v5", // Another pattern
        '.swagger-ui .swagger-ui-wrap[data-v="5"]', // Example attribute selector
        '[class*="swagger-ui-v5"]', // Wildcard check
        '[class*="swagger-ui-5"]', // Simpler wildcard
      ];
      for (const selector of swaggerVersionClasses) {
        if (document.querySelector(selector)) {
          return JSON.stringify({
            method: "dom-class-detection",
            version: "5.x inferred", // Class presence doesn't give specific version
            major: "5.x",
          });
        }
      }
      // Wil add similar checks for v4/v3 in future if reliable classes are known
      // Example for v4:
      // if (document.querySelector('.swagger-ui--v4')) { return ... "4.x" ... }
      // Example for v3:
      // if (document.querySelector('.swagger-ui--v3')) { return ... "3.x" ... }
    } catch (domError) {
      console.warn("DOM query error (class):", domError.message);
    }

    // Method 8: Check DOM element structure typical for different major versions
    // This is heuristic and can be broken by customization.
    try {
      const swaggerUiBaseElement = document.querySelector(".swagger-ui"); // Common base for v3+
      const swaggerV2Container = document.querySelector(
        "#swagger-ui-container",
      ); // Common ID for v2
      const swaggerV2Section = document.querySelector(".swagger-section"); // Another v2 indicator

      // V5 Heuristics: Often includes specific components like server dropdowns, new opblock structures
      const hasServersDropdown = !!document.querySelector(
        ".servers > .servers-title, .servers > label > select",
      );
      const hasNewOpblockPath = !!document.querySelector(
        ".opblock .opblock-summary-path",
      );
      const hasAuthorizeBtn = !!document.querySelector(
        ".auth-wrapper .authorize",
      );

      if (
        swaggerUiBaseElement &&
        hasServersDropdown &&
        hasNewOpblockPath &&
        hasAuthorizeBtn
      ) {
        // High likelihood of v5 due to combination of modern components within .swagger-ui
        return JSON.stringify({
          method: "dom-structure-v5",
          version: "5.x inferred",
          major: "5.x",
        });
      }

      // V3/V4 Heuristics: Has .swagger-ui base, lacks v2 containers.
      // Distinguishing v3/v4 via DOM alone is tricky. V4 introduced subtle changes.
      else if (swaggerUiBaseElement && !swaggerV2Container) {
        // Look for elements more common in v4+ (e.g., updated model rendering)
        const hasV4ModelElements = !!document.querySelector(
          ".model-box, .model-title .model-title__text, .models .model-container",
        );
        if (hasV4ModelElements) {
          return JSON.stringify({
            method: "dom-structure-v4",
            version: "4.x inferred",
            major: "4.x",
          });
        } else {
          // If it has .swagger-ui but lacks clear v4/v5 indicators, assume v3
          return JSON.stringify({
            method: "dom-structure-v3",
            version: "3.x inferred",
            major: "3.x",
          });
        }
      }
      // V2 Heuristics: Uses older container IDs/classes
      else if (swaggerV2Container || swaggerV2Section) {
        return JSON.stringify({
          method: "dom-structure-v2",
          version: "2.x inferred",
          major: "2.x",
        });
      }
    } catch (domError) {
      console.warn("DOM query error (structure):", domError.message);
    }

    // Method 9: Check script source URLs for version patterns (Last resort)
    // Relies on common CDN or file naming patterns.
    try {
      const scripts = document.querySelectorAll("script[src]");
      for (let i = 0; i < scripts.length; i++) {
        const src = scripts[i].getAttribute("src");
        if (src && typeof src === "string") {
          // Check from newest to oldest
          if (
            src.includes("swagger-ui@5") ||
            src.includes("swagger-ui/5.") ||
            src.includes("swagger-ui-bundle/5.")
          ) {
            return JSON.stringify({
              method: "script-src-detection",
              version: "5.x inferred",
              major: "5.x",
            });
          }
          if (
            src.includes("swagger-ui@4") ||
            src.includes("swagger-ui/4.") ||
            src.includes("swagger-ui-bundle/4.")
          ) {
            return JSON.stringify({
              method: "script-src-detection",
              version: "4.x inferred",
              major: "4.x",
            });
          }
          if (
            src.includes("swagger-ui@3") ||
            src.includes("swagger-ui/3.") ||
            src.includes("swagger-ui-bundle/3.")
          ) {
            return JSON.stringify({
              method: "script-src-detection",
              version: "3.x inferred",
              major: "3.x",
            });
          }
          // V2 often didn't use 'bundle' and might just be 'swagger-ui.js' or similar, less specific pattern.
          // Checking for '@2' or '/2.' might catch some cases.
          if (src.includes("swagger-ui@2") || src.includes("swagger-ui/2.")) {
            return JSON.stringify({
              method: "script-src-detection",
              version: "2.x inferred",
              major: "2.x",
            });
          }
        }
      }
    } catch (domError) {
      console.warn("DOM query error (script src):", domError.message);
    }

    // If none of the methods above worked, return detection failure
    return JSON.stringify({
      method: "detection-failed",
      error:
        "No definitive Swagger UI markers found via objects or DOM inspection.",
      major: "unknown", // Explicitly state unknown
    });
  } catch (e) {
    // Catch any unexpected errors during the detection process
    console.error("Swagger UI detection script failed:", e);
    return JSON.stringify({
      method: "detection-error",
      error: e.toString(),
      major: "error", // Indicate an error occurred
    });
  }
})(); // Immediately invoke the function
