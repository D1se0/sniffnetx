import { useLayoutEffect, useRef } from "react";

/**
 * Animación FLIP de filas al reordenar/filtrar: mide la posición de cada fila
 * (por clave) antes y después del render y anima el transform de la diferencia.
 * Fluida, sin librerías de animación y sin capas de composición GPU (segura en
 * VMs sin aceleración).
 *
 * Uso:  const flip = useFlipSort([rows]);
 *       <tr ref={(el) => { el ? flip.current.set(key, el) : flip.current.delete(key); }}>
 */
export function useFlipSort(deps) {
  const reg = useRef(new Map());   // clave -> elemento fila
  const prev = useRef(new Map());  // clave -> rect anterior

  useLayoutEffect(() => {
    const now = new Map();
    reg.current.forEach((el, k) => {
      if (!el || !el.isConnected) { prev.current.delete(k); return; }
      const r = el.getBoundingClientRect();
      now.set(k, r);
      const pr = prev.current.get(k);
      if (pr) {
        const dx = pr.left - r.left, dy = pr.top - r.top;
        if (Math.abs(dx) > 1 || Math.abs(dy) > 1) {
          el.style.transition = "none";
          el.style.transform = `translate(${dx}px, ${dy}px)`;
          void el.getBoundingClientRect(); // reflow: fija el estado inicial
          el.style.transition = "transform 430ms cubic-bezier(0.22, 0.9, 0.24, 1)";
          el.style.transform = "";
        }
      }
    });
    prev.current = now;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return reg;
}
