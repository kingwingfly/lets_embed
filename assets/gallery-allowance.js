// Embedded media and search fetches cannot navigate the containing gallery themselves.
(() => {
  const upgrade = "/user/upgrade";
  let leaving = false;
  function openPayment() {
    if (!leaving) {
      leaving = true;
      location.assign(upgrade);
    }
  }

  if (window.PerformanceObserver) {
    const observer = new PerformanceObserver((list) => {
      const onDetails = (location.pathname || "").startsWith("/details/");
      if (
        list
          .getEntries()
          .some((entry) => {
            if (
              !entry.name.startsWith(location.origin + "/") ||
              !entry.serverTiming?.some(
                (metric) => metric.name === "gallery-allowance",
              )
            ) {
              return false;
            }
            // Background "Similar" widget on /details/:id handles 402 inline so
            // visitors and crawlers are not bounced off an accessible details page.
            if (onDetails) {
              try {
                if (new URL(entry.name).pathname === "/api/search_similar") {
                  return false;
                }
              } catch {}
            }
            return true;
          })
      )
        openPayment();
    });
    observer.observe({ type: "resource", buffered: true });
  }
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) leaving = false;
  });

  // Native video players can withhold Resource Timing entries. Only probe a
  // failed gallery resource. HEAD evaluates access without spending points.
  const pending = new Set();
  const imageTiming =
    window.PerformanceObserver &&
    window.PerformanceResourceTiming &&
    "serverTiming" in window.PerformanceResourceTiming.prototype;
  document.addEventListener(
    "error",
    async (event) => {
      const media = event.target;
      if (
        leaving ||
        (media.tagName !== "VIDEO" && (media.tagName !== "IMG" || imageTiming))
      )
        return;
      const src = media.currentSrc || media.src;
      if (!src) return;
      const url = new URL(src, location.href);
      if (
        url.origin !== location.origin ||
        !/^\/(images|videos)\//.test(url.pathname) ||
        pending.has(url.href)
      )
        return;
      pending.add(url.href);
      try {
        const response = await fetch(url, {
          method: "HEAD",
          cache: "no-store",
          redirect: "manual",
        });
        if (
          response.status === 402 &&
          response.headers.get("location") === upgrade
        )
          openPayment();
      } catch {
        // A network error carries no billing decision.
      } finally {
        pending.delete(url.href);
      }
    },
    true,
  );
})();
