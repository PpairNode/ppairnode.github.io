// ── SCROLL REVEAL ──────────────────────────────────────────
const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry, i) => {
    if (entry.isIntersecting) {
      setTimeout(() => entry.target.classList.add('visible'), i * 70);
    }
  });
}, { threshold: 0.1 });

document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

// ── NAV BORDER ON SCROLL ───────────────────────────────────
window.addEventListener('scroll', () => {
  document.getElementById('nav').style.borderBottomColor =
    window.scrollY > 40
      ? 'rgba(255,255,255,0.12)'
      : 'rgba(255,255,255,0.07)';
});