import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import DocsPage from "./DocsPage.jsx";
import "./styles.css";

// routing simple por query (?page=docs) — GH Pages sirve docs.html que la carga con esa query
const params = new URLSearchParams(window.location.search);
const page = params.get("page");
createRoot(document.getElementById("root")).render(page === "docs" ? <DocsPage /> : <App />);
