/**
 * Airlock dashboard interactions, live execution connector, and Chart.js visualizations
 */

document.addEventListener("DOMContentLoaded", () => {
  initRouter();
  initHeroChart();
  initDonutChart();
  initBenchmarkChart();
  initFilterTabs();
  initTableSearch();
  initRedTeamButton();
  initMobileMenu();
  initToastActions();
  initModals();
  checkBackendStatus();
});

function initRouter() {
  const links = document.querySelectorAll(".sidebar__nav a[href^='#']");
  const pages = document.querySelectorAll(".page-view");

  function navigate(hash) {
    if (!hash || hash === "#") hash = "#dashboard";

    links.forEach((link) => {
      if (link.getAttribute("href") === hash) {
        link.classList.add("active");
        link.setAttribute("aria-current", "page");
      } else {
        link.classList.remove("active");
        link.removeAttribute("aria-current");
      }
    });

    const targetPageId = "page-" + hash.substring(1);
    pages.forEach((page) => {
      if (page.id === targetPageId) {
        page.classList.add("active");
      } else {
        page.classList.remove("active");
      }
    });

    const sidebar = document.getElementById("sidebar");
    if (window.innerWidth < 700 && sidebar) {
      sidebar.classList.remove("is-open");
    }

    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  links.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const hash = link.getAttribute("href");
      window.history.pushState(null, null, hash);
      navigate(hash);
    });
  });

  window.addEventListener("popstate", () => {
    navigate(window.location.hash);
  });

  navigate(window.location.hash);
}

function initHeroChart() {
  const canvas = document.getElementById("heroChart");
  if (!canvas || typeof Chart === "undefined") return;

  const ctx = canvas.getContext("2d");
  const parent = canvas.parentElement;

  const getGradient = (startRgba, endRgba) => {
    const height = parent ? parent.clientHeight : 140;
    const gradient = ctx.createLinearGradient(0, 0, 0, height || 140);
    gradient.addColorStop(0, startRgba);
    gradient.addColorStop(1, endRgba);
    return gradient;
  };

  const labels = ["Oct 1", "Oct 2", "Oct 3", "Oct 4", "Oct 5", "Oct 6", "Oct 7"];

  new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Threats flagged",
          data: [12, 19, 14, 25, 22, 38, 14],
          borderColor: "#ee478b",
          borderWidth: 2.4,
          tension: 0.42,
          fill: true,
          backgroundColor: getGradient("rgba(238, 71, 139, 0.32)", "rgba(238, 71, 139, 0.01)"),
          pointRadius: 3,
          pointHoverRadius: 6,
          pointBackgroundColor: "#ffffff",
          pointBorderColor: "#ee478b",
          pointBorderWidth: 2,
        },
        {
          label: "Actions enforced",
          data: [8, 14, 9, 16, 17, 26, 10],
          borderColor: "#7c5cd9",
          borderWidth: 2.2,
          tension: 0.42,
          fill: true,
          backgroundColor: getGradient("rgba(124, 92, 217, 0.28)", "rgba(124, 92, 217, 0.01)"),
          pointRadius: 3,
          pointHoverRadius: 6,
          pointBackgroundColor: "#ffffff",
          pointBorderColor: "#7c5cd9",
          pointBorderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: "index",
        intersect: false,
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#222a40",
          titleColor: "#ffffff",
          bodyColor: "#cfd6e6",
          borderColor: "rgba(255, 255, 255, 0.08)",
          borderWidth: 1,
          padding: { top: 7, right: 10, bottom: 7, left: 10 },
          cornerRadius: 8,
          displayColors: true,
          boxWidth: 8,
          boxHeight: 8,
          usePointStyle: true,
          callbacks: {
            label(context) {
              return ` ${context.dataset.label}: ${context.parsed.y} events`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { display: false, drawBorder: false },
          ticks: {
            color: "#abb1c0",
            font: { family: "'DM Sans', sans-serif", size: 10, weight: 500 },
          },
          border: { display: false },
        },
        y: {
          beginAtZero: true,
          suggestedMax: 44,
          grid: { color: "rgba(235, 238, 245, 0.85)", drawBorder: false },
          ticks: {
            color: "#b0b7c5",
            stepSize: 10,
            font: { family: "'DM Sans', sans-serif", size: 9 },
          },
          border: { dash: [4, 4], display: false },
        },
      },
    },
  });
}

function initDonutChart() {
  const canvas = document.getElementById("donutChart");
  if (!canvas || typeof Chart === "undefined") return;

  const ctx = canvas.getContext("2d");

  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: [
        "Prompt injection",
        "Data exfiltration",
        "Privilege escalation",
        "Tool hijacking",
      ],
      datasets: [
        {
          data: [33, 28, 27, 12],
          backgroundColor: ["#ed4b8f", "#7656d7", "#34bae8", "#f7b842"],
          borderWidth: 3,
          borderColor: "#ffffff",
          hoverOffset: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "72%",
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#222a40",
          titleColor: "#ffffff",
          bodyColor: "#cfd6e6",
          padding: 8,
          cornerRadius: 8,
          callbacks: {
            label(context) {
              return ` ${context.label}: ${context.raw}% of signals`;
            },
          },
        },
      },
    },
  });
}

function initBenchmarkChart() {
  const canvas = document.getElementById("benchmarkChart");
  if (!canvas || typeof Chart === "undefined") return;

  const ctx = canvas.getContext("2d");
  const categories = [
    "T1-direct",
    "T1-paraphrase",
    "T2-indirect-file",
    "T6-multistep",
  ]; // measured 2026-10-07, gemini-2.5-flash; T3/T5 hit provider rate limits — see BENCHMARK.md

  new Chart(ctx, {
    type: "bar",
    data: {
      labels: categories,
      datasets: [
        {
          label: "Without firewall (Baseline)",
          data: [100, 0, 0, 0],
          backgroundColor: "#f25696",
          borderRadius: 6,
          barPercentage: 0.6,
          categoryPercentage: 0.7,
        },
        {
          label: "With Airlock (Protected)",
          data: [0, 0, 0, 0],
          backgroundColor: "#7656d7",
          borderRadius: 6,
          barPercentage: 0.6,
          categoryPercentage: 0.7,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#222a40",
          titleColor: "#ffffff",
          bodyColor: "#cfd6e6",
          padding: 8,
          cornerRadius: 8,
          callbacks: {
            label(ctx) {
              return ` ${ctx.dataset.label}: ${ctx.raw}% ASR`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: "#9aa1b3", font: { size: 9, family: "'DM Sans', sans-serif" } },
        },
        y: {
          beginAtZero: true,
          suggestedMax: 100,
          ticks: {
            color: "#abb2c2",
            callback: (v) => v + "%",
            font: { size: 9, family: "'DM Sans', sans-serif" },
          },
          grid: { color: "rgba(235, 238, 245, 0.85)" },
        },
      },
    },
  });
}

function initFilterTabs() {
  const buttons = document.querySelectorAll(".filter-tabs button");
  const rows = document.querySelectorAll("#logRows tr");
  const counter = document.getElementById("logCount");

  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      const filter = btn.getAttribute("data-filter");
      let visible = 0;

      rows.forEach((row) => {
        const rowStatus = row.getAttribute("data-status");
        if (filter === "all" || rowStatus === filter) {
          row.style.display = "";
          visible++;
        } else {
          row.style.display = "none";
        }
      });

      if (counter) {
        counter.textContent = `Showing 1–${visible} of ${filter === "all" ? rows.length : visible} events`;
      }
    });
  });
}

function initTableSearch() {
  const searchInput = document.getElementById("logSearch");
  const rows = document.querySelectorAll("#logRows tr");

  if (!searchInput) return;

  searchInput.addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase().trim();
    rows.forEach((row) => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(term) ? "" : "none";
    });
  });
}

function initRedTeamButton() {
  const btn = document.getElementById("redTeamBtn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const originalContent = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `
      <svg class="btn-icon spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M21 12a9 9 0 1 1-6.22-8.56"/>
      </svg>
      <span>Running Attack Injection Demo…</span>
    `;

    try {
      const res = await fetch("/api/run_attack", { method: "POST" });
      const data = await res.json();

      if (data.leaked) {
        btn.innerHTML = `<span>⚠️ LEAK DETECTED (S1 Guard OFF)</span>`;
        btn.style.background = "linear-gradient(135deg, #ed4b8f 0%, #de357a 100%)";
        showToast(`Canary secret leaked: ${data.canary}`);
        renderLiveFeed(data.tool_calls);
      } else {
        btn.innerHTML = `<span>✓ Execution Finished (Safe)</span>`;
        btn.style.background = "linear-gradient(135deg, #10b981 0%, #059669 100%)";
        showToast("Attack finished. No leak detected.");
      }
    } catch (err) {
      showToast("Backend connection error: " + err.message);
    } finally {
      setTimeout(() => {
        btn.innerHTML = originalContent;
        btn.disabled = false;
        btn.style.background = "";
      }, 5000);
    }
  });
}

function renderLiveFeed(toolCalls) {
  const tbody = document.getElementById("logRows");
  if (!tbody || !toolCalls) return;

  tbody.innerHTML = "";
  toolCalls.forEach((tc) => {
    const time = (tc.timestamp || "").split("T")[1]?.slice(0, 8) || "Now";
    const isExfil = JSON.stringify(tc.args).includes("sk-CANARY");
    const risk = isExfil ? "Critical" : tc.name === "send_email" || tc.name === "read_file" ? "High" : "Low";
    const riskClass = isExfil ? "risk--critical" : risk === "High" ? "risk--medium" : "risk--low";

    const tr = document.createElement("tr");
    tr.setAttribute("data-status", "allowed");
    tr.innerHTML = `
      <td>${time}</td>
      <td><strong>airlock-agent</strong></td>
      <td><code>${tc.name}(${JSON.stringify(tc.args)})</code></td>
      <td><span class="risk ${riskClass}">${risk}</span></td>
      <td><span class="badge badge--allowed"><i></i>Allowed (S1)</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function initToastActions() {
  window.showToast = function (msg) {
    let toast = document.querySelector(".toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.className = "toast";
      document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add("is-visible");
    clearTimeout(window.toastTimer);
    window.toastTimer = setTimeout(() => {
      toast.classList.remove("is-visible");
    }, 3600);
  };
}

function initModals() {
  const createPolicyBtn = document.getElementById("createPolicyBtn");
  if (createPolicyBtn) {
    createPolicyBtn.addEventListener("click", () => {
      showToast("Policy engine in S1 is in observation mode (Guard OFF).");
    });
  }
}

function initMobileMenu() {
  const menuToggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");

  if (!menuToggle || !sidebar) return;

  menuToggle.addEventListener("click", () => {
    const isOpen = sidebar.classList.toggle("is-open");
    menuToggle.setAttribute("aria-expanded", String(isOpen));
  });

  document.querySelectorAll(".sidebar__nav a").forEach((link) => {
    link.addEventListener("click", () => {
      if (window.innerWidth < 700) {
        sidebar.classList.remove("is-open");
        menuToggle.setAttribute("aria-expanded", "false");
      }
    });
  });
}

async function checkBackendStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();
    const sidebarStatus = document.querySelector(".sidebar__status");
    if (sidebarStatus) {
      sidebarStatus.innerHTML = `
        <span class="status-orb" aria-hidden="true"></span>
        <span><strong>Airlock S1 Active</strong><small>Model: ${data.model.split("/").pop()}</small></span>
      `;
    }
  } catch {
    // Static mode fallback
  }
}
