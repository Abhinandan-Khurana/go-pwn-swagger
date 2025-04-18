(function () {
  try {
    // Method 1: Try versions object (if present, use its version to derive major)
    if (window.versions) {
      if (versions.swaggerUi && versions.swaggerUi.version) {
        var v = versions.swaggerUi.version;
        var mj = v.startsWith("5")
          ? "5.x"
          : v.startsWith("4")
            ? "4.x"
            : v.startsWith("3")
              ? "3.x"
              : "unknown";

        return JSON.stringify({
          method: "versions-object",
          version: v,
          major: mj,
        });
      }
      // Check for 3.x structure
      else if (versions.swaggerUi) {
        return JSON.stringify({
          method: "versions-object-3x",
          version: versions.swaggerUi.version,
          major: "3.x",
        });
      }
    }

    // Method 2: Try SwaggerUIBundle.version (3.x and 4.x)
    if (window.SwaggerUIBundle && SwaggerUIBundle.version) {
      let major = SwaggerUIBundle.version.startsWith("3")
        ? "3.x"
        : SwaggerUIBundle.version.startsWith("4")
          ? "4.x"
          : SwaggerUIBundle.version.startsWith("5")
            ? "5.x"
            : "unknown";
      return JSON.stringify({
        method: "swagger-ui-bundle",
        version: SwaggerUIBundle.version,
        major: major,
      });
    }

    // Method 3: Try ui.getConfigs() for (3.x+)
    if (window.ui && typeof ui.getConfigs === "function") {
      try {
        const config = ui.getConfigs();
        if (config && config.version) {
          let major = config.version.startsWith("3")
            ? "3.x"
            : config.version.startsWith("4")
              ? "4.x"
              : config.version.startsWith("5")
                ? "5.x"
                : "unknown";
          return JSON.stringify({
            method: "ui-configs",
            version: config.version,
            major: major,
          });
        }
      } catch (configError) {
        // Some versions throw errors when calling getConfigs without proper initialization
        console.error("Config error:", configError);
      }
    }

    // Method 4: Look for 5.x-specific global APIs and objects
    if (window.SwaggerUI) {
      // Check for 5.x-specific presets or properties
      if (window.SwaggerUI.plugins || window.SwaggerUI.systems) {
        return JSON.stringify({
          method: "swagger-ui-5x-apis",
          version: "5.x",
          major: "5.x",
        });
      }
      // Likely 2.x if no SwaggerUIBundle
      else if (!window.SwaggerUIBundle) {
        return JSON.stringify({
          method: "swagger-ui-global",
          version: "2.x",
          major: "2.x",
        });
      }
    }

    // Method 5: Check for SwaggerUINext (5.x indicator)
    if (window.SwaggerUINext) {
      return JSON.stringify({
        method: "swagger-ui-next",
        version: window.SwaggerUINext.version || "5.x",
        major: "5.x",
      });
    }

    // Method 6: Look for 5.x specific attributes in the DOM
    const dataAttrs = document.querySelectorAll("[data-swagger-version]");
    for (let i = 0; i < dataAttrs.length; i++) {
      const version = dataAttrs[i].getAttribute("data-swagger-version");
      if (version && version.startsWith("5")) {
        return JSON.stringify({
          method: "dom-data-attribute",
          version: version,
          major: "5.x",
        });
      }
    }

    // Method 7: Check CSS classes and layout structure
    const swagger5Classes = [
      ".swagger-ui-v5",
      ".swagger-ui-5",
      ".swagger-v5",
      '[class*="swagger-ui-v5"]',
    ];

    for (let selector of swagger5Classes) {
      if (document.querySelector(selector)) {
        return JSON.stringify({
          method: "dom-class-detection-5x",
          version: "5.x",
          major: "5.x",
        });
      }
    }

    // Method 8: Check DOM elements typical for each version but with more precise checks
    const swaggerSection = document.querySelector(".swagger-section");
    const swagger2Container = document.querySelector("#swagger-ui-container");
    const swagger3Element = document.querySelector(".swagger-ui");

    // Check for 5.x specific UI components (even without specific classes)
    const hasTryItButtons =
      document.querySelectorAll(".try-out__btn").length > 0;
    const hasNewUIStructure =
      document.querySelectorAll(".opblock-summary-path").length > 0;
    const hasServersDropdown =
      document.querySelectorAll(".servers-title").length > 0;

    // 5.x often has certain modern components visible
    if (
      hasServersDropdown &&
      hasNewUIStructure &&
      document.querySelectorAll(".auth-wrapper .authorize").length > 0
    ) {
      // More likely to be 5.x with modern component structure
      return JSON.stringify({
        method: "dom-component-structure",
        version: "5.x",
        major: "5.x",
      });
    }
    // 3.x or 4.x detection
    else if (swagger3Element && !swagger2Container) {
      // Try to distinguish between 3.x and 4.x
      // 4.x typically has more modern component names
      if (
        document.querySelectorAll(".model-box").length > 0 ||
        document.querySelectorAll(".model-title__text").length > 0
      ) {
        return JSON.stringify({
          method: "dom-detection",
          version: "4.x",
          major: "4.x",
        });
      }
      return JSON.stringify({
        method: "dom-detection",
        version: "3.x",
        major: "3.x",
      });
    }
    // 2.x detection
    else if (swagger2Container || swaggerSection) {
      return JSON.stringify({
        method: "dom-detection",
        version: "2.x",
        major: "2.x",
      });
    }

    // Final attempt: Check for bundled file naming patterns in script sources
    const scripts = document.querySelectorAll("script[src]");
    for (let i = 0; i < scripts.length; i++) {
      const src = scripts[i].getAttribute("src");
      if (src) {
        if (src.includes("swagger-ui-5") || src.includes("swagger-ui@5")) {
          return JSON.stringify({
            method: "script-src-detection",
            version: "5.x",
            major: "5.x",
          });
        } else if (
          src.includes("swagger-ui-4") ||
          src.includes("swagger-ui@4")
        ) {
          return JSON.stringify({
            method: "script-src-detection",
            version: "4.x",
            major: "4.x",
          });
        } else if (
          src.includes("swagger-ui-3") ||
          src.includes("swagger-ui@3")
        ) {
          return JSON.stringify({
            method: "script-src-detection",
            version: "3.x",
            major: "3.x",
          });
        } else if (
          src.includes("swagger-ui-2") ||
          src.includes("swagger-ui@2")
        ) {
          return JSON.stringify({
            method: "script-src-detection",
            version: "2.x",
            major: "2.x",
          });
        }
      }
    }

    // No detectable version
    return JSON.stringify({
      method: "detection-failed",
      error: "No known Swagger UI patterns detected",
      major: "",
    });
  } catch (e) {
    return JSON.stringify({
      method: "detection-failed",
      error: e.toString(),
      major: "",
    });
  }
})();
