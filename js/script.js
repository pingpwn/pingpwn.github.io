/* =========================================================
   CRT Site — Click-Only Navigation  (no keyboard)
   ========================================================= */

const rands = [ /* still here if you decide to reuse */ ];

const main   = document.querySelector('main');
const canvas = document.getElementById('canvas');
const ctx    = canvas.getContext('2d');
const text   = document.querySelector('.text');
const menu   = document.querySelector('.menu');
let   ul     = menu.querySelector('ul');
let   frame;

// size canvas at 1/3 width, 16:9 ratio
canvas.width  = window.innerWidth / 3;
canvas.height = (window.innerWidth * 0.5625) / 3;

/* ---------- CRT SNOW ------------------------------------ */
function snow(ctx) {
  const w = ctx.canvas.width,
        h = ctx.canvas.height,
        d = ctx.createImageData(w, h),
        b = new Uint32Array(d.data.buffer),
        len = b.length;
  for (let i = 0; i < len; i++) b[i] = ((255 * Math.random()) | 0) << 24;
  ctx.putImageData(d, 0, 0);
}
function animate() {
  snow(ctx);
  frame = requestAnimationFrame(animate);
}

/* ---------- ABOUT & MENU SWAP --------------------------- */
function showAboutInfo() {
  /* set background + pause noise */
  main.classList.add('about-mode');
  if (frame) { cancelAnimationFrame(frame); frame = null; }

  /* header text → ABOUT */
  menu.querySelector('header').textContent = 'About';

  /* keep original <ul> so we can restore */
  if (!window._originalMenu) window._originalMenu = ul;

  /* replace list with intro content */
  const aboutText = document.createElement('div');
  aboutText.className = 'about-text';
  aboutText.innerHTML = `
    <img src="assets/lecat.png" width="200" alt="cat" />
    <p>
      Hello! I'm PingPwn, a CTF player from Greece. Lately I've been focusing on reverse engineering and binary exploitation.
      Feel free to reach out on discord @pingpwn &lt;3
    </p>
    <p><a href="#" data-action="back">Back</a></p>
  `;
  ul.parentElement.replaceChild(aboutText, ul);
  window._aboutText = aboutText;
}

function restoreMenu() {
  /* remove background + resume noise */
  main.classList.remove('about-mode');
  if (!frame) animate();

  /* swap back to original list */
  if (window._aboutText && window._originalMenu) {
    window._aboutText.parentElement.replaceChild(window._originalMenu, window._aboutText);
    ul = window._originalMenu;
    window._aboutText = null;
    window._originalMenu = null;
  }

  /* header text → MAIN MENU */
  menu.querySelector('header').textContent = 'Main Menu';
}

/* ---------- DUPLICATE AV-1 SPANS FOR RGB OFFSET --------- */
for (let i = 0; i < 4; i++) {
  text.appendChild(text.firstElementChild.cloneNode(true));
}

/* ---------- INITIAL BOOT ANIMATION ---------------------- */
window.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    main.classList.add('on');
    main.classList.remove('off');
    animate();
  }, 1000);
});

/* ---------- CLICK-ONLY EVENT DELEGATION ----------------- */
menu.addEventListener('click', (e) => {
  const a = e.target.closest('a');
  if (!a) return;

  const action = a.dataset.action;

  if (action === 'about') {            /* open About */
    e.preventDefault();
    showAboutInfo();
    return;
  }
  if (action === 'back') {             /* back to menu */
    e.preventDefault();
    restoreMenu();
    return;
  }
  /* normal navigation for all other anchors */
}, false);
