// Iroh Tea‑Cup Loading Overlay
// This script expects the overlay HTML (loader.html) to be included in the page.
// It manages showing/hiding the overlay, animating the tea‑cup fill, and rotating quotes.

document.addEventListener('DOMContentLoaded', function () {
  const overlay = document.getElementById('iroh-loading');
  const fill = overlay?.querySelector('.teacup-fill');
  const quoteEl = overlay?.querySelector('#iroh-quote');

  // Quotes from user request
  const quotes = [
    "A slow scan is not a problem. It is an opportunity to brew another cup of tea.",
    "Rushing a port scan is like gulping hot tea. You burn your tongue and learn nothing.",
    "The network has its own rhythm. Listen to it. Do not demand that it dance to yours.",
    "Some findings take time to reveal themselves. Like a good tea leaf, they unfold when you are patient.",
    "An open port is not a mistake. It is a door that once served a purpose.",
    "A recurring vulnerability is like a weed in the garden. Pull the leaf, but remove the root.",
    "Fear of finding a weakness is the only real weakness. Scan anyway.",
    "When a finding is marked 'resolved', do not celebrate too quickly. The most stubborn weeds grow back.",
    "Suppressing a finding is not fixing it. It is simply looking away.",
    "Every resolved vulnerability is a small victory. Do not let the mountain hide the stones you moved.",
    "You cannot fix what you do not see. That is why the dashboard exists.",
    "A good analyst learns from every recurring finding, not from a spotless record.",
    "Numbers tell you what happened. Wisdom tells you why.",
  ];

  let quoteIndex = 0;
  function rotateQuote() {
    if (quoteEl) {
      quoteEl.textContent = quotes[quoteIndex];
      quoteIndex = (quoteIndex + 1) % quotes.length;
    }
  }

  // Animate fill from 0% to 100% over ~30 seconds (adjust as needed)
  let progress = 0;
  function animateFill() {
    if (!fill) return;
    progress = Math.min(100, progress + 0.33); // ~30s to reach 100%
    fill.style.height = progress + "%";
    if (progress < 100) {
      requestAnimationFrame(animateFill);
    }
  }

  // Show overlay, start animations
  if (overlay) {
    overlay.classList.remove('hidden');
    rotateQuote();
    setInterval(rotateQuote, 8000); // change quote every 8 s
    animateFill();
    // Hide after fill complete + a short delay
    setTimeout(() => {
      overlay.classList.add('hidden');
    }, 35000);
  }
});
