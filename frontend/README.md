# Frontend

Static, dependency-free. The checks run in the browser and talk to your backend.

## Configure

Edit `config.js`:

```js
window.NM_TOOLS_API = { base: "https://api.example.com" };   // credentials service
window.NM_CONNCHECK_H3_BASE = "https://probe.example.com";   // http3-probe service
```

## Serve

Any static host works:

```bash
python -m http.server 8080     # then open http://localhost:8080
```

## Files

| File | Purpose |
|---|---|
| `index.html` | markup the checks drive |
| `app.js` | all detection logic (vanilla JS) |
| `style.css` | widget styles |
| `tokens.css` | design tokens (edit to match your brand) |
| `config.js` | **the only file you normally edit** |
