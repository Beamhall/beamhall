// Beamhall terminal nav — switches "screens" in the main terminal area.
// Plain JS, served from the site origin so the CSP can stay script-src 'self'.
const buttons = Array.from(document.querySelectorAll(".nav button"));
const screens = Array.from(document.querySelectorAll(".screen"));
const pathEl = document.getElementById("path");
const ids = buttons.map((b) => b.dataset.screen);
// Menu entries that are real routes (e.g. /alternatives/...) rather than
// in-page screens. They keep the same 1..N numbering, continuing after the
// screens; on a standalone route every entry is a link, so `ids` is empty.
const links = Array.from(document.querySelectorAll(".nav a[data-nav-link]"));

function show(id, push = true) {
  if (!ids.includes(id)) return;
  buttons.forEach((b) => b.classList.toggle("active", b.dataset.screen === id));
  screens.forEach((s) => s.classList.toggle("active", s.id === `screen-${id}`));
  if (pathEl) pathEl.textContent = `~/${id === "install" ? "get-started" : id}`;
  const body = document.querySelector(".term-body");
  if (body) body.scrollTop = 0;
  if (push && location.hash !== `#${id}`) {
    history.replaceState(null, "", `#${id}`);
  }
}

buttons.forEach((b) => b.addEventListener("click", () => show(b.dataset.screen)));

document.addEventListener("keydown", (e) => {
  const tag = e.target && e.target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA") return;
  const cur = ids.findIndex((id) =>
    document.getElementById(`screen-${id}`)?.classList.contains("active")
  );
  if (e.key >= "1" && e.key <= "9") {
    const i = Number(e.key) - 1;
    if (i < ids.length) {
      show(ids[i]);
    } else if (links[i - ids.length]) {
      location.href = links[i - ids.length].href;
    }
  } else if (e.key === "ArrowDown" || e.key === "j") {
    show(ids[Math.min(ids.length - 1, cur + 1)]);
  } else if (e.key === "ArrowUp" || e.key === "k") {
    show(ids[Math.max(0, cur - 1)]);
  }
});

const initial = location.hash.replace("#", "");
if (initial) show(initial, false);
