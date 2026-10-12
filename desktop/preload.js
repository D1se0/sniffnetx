const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("sniffnexDesktop", {
  isDesktop: true,
  version: process.versions.electron,
});
