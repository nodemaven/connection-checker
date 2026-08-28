/*
 * Connection Checker — frontend configuration.
 * Point these at YOUR backend, then serve this folder from any static host.
 */
window.NM_TOOLS_API = {
  // The credentials service (also serves /ip and /ip/<ip>). No trailing slash.
  base: "https://api.example.com",
};

// The HTTP/3 probe service (forced-IPv4 /ip + /h3probe). No trailing slash.
window.NM_CONNCHECK_H3_BASE = "https://probe.example.com";

// Wire the H3 base onto the widget root before the checker initializes.
document.addEventListener("DOMContentLoaded", function () {
  var el = document.querySelector(".nm-tool--conncheck");
  if (el && window.NM_CONNCHECK_H3_BASE) {
    el.setAttribute("data-h3-base", window.NM_CONNCHECK_H3_BASE);
  }
});
