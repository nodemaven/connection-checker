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

// Wire the H3 base onto the widget root. This MUST run synchronously, NOT on
// DOMContentLoaded: app.js loads right after this file and constructs the
// checker immediately, reading data-h3-base in its constructor. A
// DOMContentLoaded handler would fire too late (after the checker is built) and
// the HTTP/3 check would silently never run. config.js is placed after the tool
// markup, so the element already exists here.
(function () {
  var el = document.querySelector(".nm-tool--conncheck");
  if (el && window.NM_CONNCHECK_H3_BASE) {
    el.setAttribute("data-h3-base", window.NM_CONNCHECK_H3_BASE);
  }
})();
