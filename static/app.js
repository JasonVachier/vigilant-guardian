/**
 * app.js — Interactions côté client (Personne 3)
 * Vigilant Guardian — Veille CVE défensive
 *
 * - Tri des colonnes du tableau
 * - Lignes cliquables
 * - Raccourci "/" pour focus sur la recherche
 */

document.addEventListener("DOMContentLoaded", () => {

    // ── Tri des colonnes ────────────────────────────────────
    const table = document.getElementById("vulnTable");
    if (table) {
        const headers = table.querySelectorAll("th.sortable");
        let currentSort = { column: null, ascending: true };

        headers.forEach((header) => {
            header.addEventListener("click", () => {
                const sortKey = header.dataset.sort;
                if (currentSort.column === sortKey) {
                    currentSort.ascending = !currentSort.ascending;
                } else {
                    currentSort.column = sortKey;
                    currentSort.ascending = true;
                }
                headers.forEach(h => h.classList.remove("sort-asc", "sort-desc"));
                header.classList.add(currentSort.ascending ? "sort-asc" : "sort-desc");
                sortTable(sortKey, currentSort.ascending);
            });
        });

        function sortTable(key, ascending) {
            const tbody = table.querySelector("tbody");
            const rows = Array.from(tbody.querySelectorAll("tr.vg-row"));

            rows.sort((a, b) => {
                let valA, valB;
                switch (key) {
                    case "cve":
                        valA = a.dataset.cve || "";
                        valB = b.dataset.cve || "";
                        return ascending ? valA.localeCompare(valB) : valB.localeCompare(valA);
                    case "severity":
                        const sev = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, UNKNOWN: 5 };
                        valA = sev[cell(a, 1).toUpperCase()] || 5;
                        valB = sev[cell(b, 1).toUpperCase()] || 5;
                        return ascending ? valA - valB : valB - valA;
                    case "score":
                        valA = parseFloat(cell(a, 2)) || 0;
                        valB = parseFloat(cell(b, 2)) || 0;
                        return ascending ? valA - valB : valB - valA;
                    case "date":
                        valA = cell(a, 4) || "0000-00-00";
                        valB = cell(b, 4) || "0000-00-00";
                        return ascending ? valA.localeCompare(valB) : valB.localeCompare(valA);
                    default: return 0;
                }
            });
            rows.forEach((row) => tbody.appendChild(row));
        }

        function cell(row, i) {
            return row.cells[i] ? row.cells[i].textContent.trim() : "";
        }
    }

    // ── Lignes cliquables ───────────────────────────────────
    document.querySelectorAll("tr.vg-row").forEach((row) => {
        row.style.cursor = "pointer";
        row.addEventListener("click", (e) => {
            if (e.target.closest("a") || e.target.closest("button")) return;
            const cveId = row.dataset.cve;
            if (cveId) window.location.href = `/detail/${cveId}`;
        });
    });

    // ── Raccourci "/" pour la recherche ──────────────────────
    document.addEventListener("keydown", (e) => {
        if (e.key === "/" && document.activeElement.tagName !== "INPUT") {
            e.preventDefault();
            const input = document.getElementById("searchInput");
            if (input) input.focus();
        }
        if (e.key === "Escape") {
            const input = document.getElementById("searchInput");
            if (input && document.activeElement === input) input.blur();
        }
    });

});
