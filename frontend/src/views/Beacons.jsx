import { Clock, ShieldAlert } from "lucide-react";

export default function Beacons({ data }) {
  const beacons = data?.beacons || [];
  return (
    <div>
      <div className="section-title">Beacons — conexiones periódicas sospechosas</div>
      <div className="section-sub">
        Los malware/ratos C2 «llaman a casa» con intervalos casi idénticos. Aquí van las conexiones
        cuya regularidad (menos jitter) supera el umbral — el número es % de mecanicidad.
      </div>

      {!beacons.length ? (
        <div className="empty-note">
          <ShieldAlert style={{ verticalAlign: "-3px" }} /> Sin beacons todavía. Aparecen cuando un
          host repite conexiones hacia el mismo destino con intervalos metrónomos (≥ 6 conexiones,
          regularidad ≥ 82 %).
        </div>
      ) : (
        <div className="card">
          <div className="tablewrap" style={{ maxHeight: "calc(100vh - 250px)" }}>
            <table className="data">
              <thead>
                <tr><th>Origen</th><th>Destino</th><th>Servicio</th><th>Conex.</th><th>Intervalo</th><th style={{minWidth: 260}}>Regularidad</th><th>Score</th></tr>
              </thead>
              <tbody>
                {beacons.map((b, i) => (
                  <tr key={i} className="rowlink" title="Se abre en Sesiones filtrando el par">
                    <td className="mono" style={{ color: "var(--accent)" }}>{b.src}</td>
                    <td className="mono" style={{ color: "var(--accent2)" }}>{b.dst}:{b.dport}</td>
                    <td>{b.service}</td>
                    <td className="mono">{b.count}</td>
                    <td className="mono">{b.mean_s} s</td>
                    <td>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <div className="reg-bar"><span style={{ width: `${b.regularity}%` }} /></div>
                        <span className="mono" style={{ fontSize: 11 }}>{b.regularity}%</span>
                      </div>
                    </td>
                    <td className="mono">{b.score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <div className="spark-note">
        <Clock size={11} style={{ verticalAlign: "-2px" }} /> Cada fila = un par origen→destino.
        Score = regularidad × nº de conexiones: grandes y regulares arriba.
      </div>
    </div>
  );
}
