import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Download, Search } from "lucide-react";

const IMG_PREFIX = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"];

function fmtSize(n) {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1e6) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1e6).toFixed(2)} MB`;
}

export default function FilesView({ data, setLightbox }) {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("all");

  const rows = useMemo(() => {
    let list = data?.files || [];
    if (kind === "img") list = list.filter((f) => (f.mime || f.content_type || "").startsWith("image/"));
    if (kind === "bin") list = list.filter((f) => !(f.mime || f.content_type || "").startsWith("image/"));
    if (q.trim()) {
      const lq = q.toLowerCase();
      list = list.filter((f) => [f.filename, f.src, f.dst, f.mime, f.content_type, f.sha256].join(" ").toLowerCase().includes(lq));
    }
    return list;
  }, [data?.files, q, kind]);

  const kindBadge = (f) => {
    const mime = f.mime || f.content_type || "";
    if (mime.startsWith("image/")) return ["c-green", "IMAGEN"];
    if (mime.includes("pdf")) return ["c-red", "PDF"];
    if (mime.includes("zip") || mime.includes("octet")) return ["c-amber", "BIN"];
    return ["c-cyan", "HTTP"];
  };

  return (
    <div>
      <div className="section-title">Archivos reconstruidos de la red</div>
      <div className="section-sub">
        Objetos extraídos del tráfico: cuerpos HTTP con filename/Content-Type, imágenes y documentos. Haz clic en la miniatura para ampliar.
      </div>

      <div className="filters">
        <div style={{ position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: 10, top: 10, color: "var(--dim)" }} />
          <input
            className="f-input" placeholder="filtrar por nombre, host, mime, hash …"
            value={q} onChange={(e) => setQ(e.target.value)} style={{ paddingLeft: 30, width: 320 }}
            spellCheck={false}
          />
        </div>
        <select className="f-select" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="all">Todos los tipos</option>
          <option value="img">Solo imágenes</option>
          <option value="bin">Solo binarios</option>
        </select>
        <span className="f-count">{rows.length} archivos</span>
      </div>

      <div className="card">
        {!rows.length ? (
          <div className="empty">
            <div className="big">▣</div>
            Sin archivos reconstruidos aún. Aparecerán cuando el tráfico HTTP incluya imágenes o contenidos con filename.
          </div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: "calc(100vh - 300px)" }}>
            <table className="data">
              <thead>
                <tr><th>Preview</th><th>Nombre</th><th>Tipo</th><th>Tamaño</th><th>Origen → Destino</th><th>SHA-256</th><th></th></tr>
              </thead>
              <tbody>
                {rows.map((f, i) => {
                  const id = f.id;
                  const [bcls, blbl] = kindBadge(f);
                  const mime = f.mime || f.content_type || "";
                  return (
                    <motion.tr key={`${f.filename}-${i}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.02, 0.3) }}>
                      <td style={{ width: 90 }}>
                        {id != null && IMG_PREFIX.some((p) => mime.startsWith(p.split("/")[0]) && mime.startsWith(p)) ? (
                          <img
                            className="imgcell"
                            src={`/api/files/${id}}/raw`.replace("}", "")}
                            onError={(e) => { e.target.style.visibility = "hidden"; }}
                            onClick={() => setLightbox(`/api/files/${id}/raw`)}
                          />
                        ) : (
                          <div className="imgcell" style={{ display: "flex", alignItems: "center", justifyContent: "center", color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 9 }}>
                            {mime.startsWith("image/") ? "##" : "≡"}
                          </div>
                        )}
                      </td>
                      <td className="mono">{f.filename}</td>
                      <td><span className={`badge ${bcls}`}>{blbl}</span> <span className="dim mono" style={{ fontSize: 10.5 }}>{mime}</span></td>
                      <td className="mono">{fmtSize(f.size)}</td>
                      <td className="mono" style={{ fontSize: 11 }}>
                        {f.src || "?"} <span style={{ color: "var(--dim)" }}>→</span> {f.dst || "?"}
                      </td>
                      <td className="mono dim" style={{ fontSize: 10 }}>{f.sha256 ? f.sha256.slice(0, 12) + "…" : "—"}</td>
                      <td>
                        {id != null && (
                          <button className="btn ghost" style={{ padding: "5px 10px" }} onClick={() => window.open(`/api/files/${id}/raw`, "_blank")}>
                            <Download size={13} />
                          </button>
                        )}
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
