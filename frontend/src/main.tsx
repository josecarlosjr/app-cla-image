import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { getStoredTheme, applyTheme } from "./utils/theme";
import "./index.css";

// Belt-and-suspenders with the inline script in index.html: re-assert
// the stored theme once the bundle is up, so the <html> class and
// localStorage stay in sync even if the inline script was skipped.
applyTheme(getStoredTheme());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
