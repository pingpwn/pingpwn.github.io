/* =========================================================
   CRT Site — Click-Only Navigation: Main / About / Blog
   ========================================================= */

const main   = document.querySelector('main');         // <main class="scanlines">
const screen = document.querySelector('.screen');      // CRT frame
const canvas = document.getElementById('canvas');      // noise canvas
const ctx    = canvas.getContext('2d');
const text   = document.querySelector('.text');        // “AV-1” label
const menu   = document.querySelector('.menu');        // blue box
let   ul     = menu.querySelector('ul');               // <ul> with options
let   frame;                                           // requestAnimationFrame id

/* --------------- SIZE THE CANVAS ----------------------- */
canvas.width  = window.innerWidth / 3;
canvas.height = (window.innerWidth * 0.5625) / 3;

/* --------------- CRT SNOW ------------------------------- */
function snow(c) {
  const w = c.canvas.width, h = c.canvas.height,
        d = c.createImageData(w, h),
        b = new Uint32Array(d.data.buffer);
  for (let i = 0; i < b.length; i++) b[i] = ((255 * Math.random()) | 0) << 24;
  c.putImageData(d, 0, 0);
}
function animate() { snow(ctx); frame = requestAnimationFrame(animate); }

/* ========================================================
   SECTION SWITCHERS
   ======================================================== */

/* ---------- ABOUT -------------------------------------- */
function showAbout() {
  main.classList.add('about-mode');           // new bg & colors
  if (frame) { cancelAnimationFrame(frame); frame = null; }

  menu.querySelector('header').textContent = 'About';

  if (!window._originalMenu) window._originalMenu = ul;

  const aboutText = document.createElement('div');
  aboutText.className = 'about-text';
  aboutText.innerHTML = `
    <img src="assets/lecat.png" width="200" alt="cat" />
    <p>Hello! I'm PingPwn, a CTF player from Greece. Lately I've been focusing on reverse engineering and binary exploitation.
       Feel free to reach out on discord @pingpwn &lt;3</p>
    <p><a href="#" data-action="back">Back</a></p>
  `;
  ul.parentElement.replaceChild(aboutText, ul);
  window._aboutText = aboutText;
}

function restoreMainMenu() {
  main.classList.remove('about-mode', 'vhs-mode');

  /* restore noise if we’re not in VHS mode */
  if (!frame) animate();

  /* put the original <ul> back if we were in About */
  if (window._aboutText && window._originalMenu) {
    window._aboutText.parentElement.replaceChild(window._originalMenu, window._aboutText);
    ul = window._originalMenu;
    window._aboutText = null;
    window._originalMenu = null;
    menu.querySelector('header').textContent = 'Main Menu';
  }

  /* stop VHS video & remove it if it was playing */
  const vid = document.getElementById('vhs');
  if (vid.classList.contains('vhs-video')) {
    vid.pause();
    vid.classList.remove('vhs-video');
    menu.style.display = '';        // show menu again
    canvas.style.display = '';      // show noise
  }
}

/* ---------- BLOG / VHS --------------------------------- */
function playVHS() {
  /* 1. Pause CRT noise & hide elements we don’t want */
  if (frame) { cancelAnimationFrame(frame); frame = null; }
  canvas.style.display = 'none';     // hide noise canvas
  menu.style.display   = 'none';     // hide blue box
  main.classList.add('vhs-mode');

  /* 2. Move hidden <video id="vhs"> into the CRT screen */
  const vid = document.getElementById('vhs');
  screen.appendChild(vid);          // makes scanlines overlay sit on top
  vid.classList.add('vhs-video');   // full-screen inside CRT

  /* 3. Autoplay with sound (allowed because this runs in the click handler) */
  vid.muted = false;                // want sound!
  vid.play().catch(() => {          // fallback: ask user to click
    vid.muted = true;
    vid.play();
  });
}

/* ========================================================
   BOOT ANIMATION & RGB DUPLICATE SPANS
   ======================================================== */
for (let i = 0; i < 4; i++)
  text.appendChild(text.firstElementChild.cloneNode(true));

window.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    main.classList.add('on');
    main.classList.remove('off');
    animate();
  }, 1000);
});

/* ========================================================
   CLICK-ONLY EVENT DELEGATION
   ======================================================== */
menu.addEventListener('click', (e) => {
  const a = e.target.closest('a');
  if (!a) return;

  const act = a.dataset.action;
  e.preventDefault();

  switch (act) {
    case 'about': showAbout(); break;
    case 'back' : restoreMainMenu(); break;
    case 'blog' : playVHS(); break;
    default:     window.open(a.href, '_blank', 'noopener'); /* external links */
  }
}, false);
