// Clickable-only menu (no keyboard selection)
// — cleaned up & simplified —

var main   = document.querySelector('main');
var canvas = document.getElementById('canvas');
var ctx    = canvas.getContext('2d');
var text   = document.querySelector('.text');
var ww     = window.innerWidth;
var menu   = document.querySelector('.menu');
var ul     = menu.querySelector('ul');
var frame;

// Set canvas size (keeps your original proportions)
canvas.width  = ww / 3;
canvas.height = (ww * 0.5625) / 3;

// Generate CRT noise
function snow(ctx) {
  var w = ctx.canvas.width,
      h = ctx.canvas.height,
      d = ctx.createImageData(w, h),
      b = new Uint32Array(d.data.buffer),
      len = b.length;

  for (var i = 0; i < len; i++) {
    b[i] = ((255 * Math.random()) | 0) << 24;
  }
  ctx.putImageData(d, 0, 0);
}

function animate() {
  snow(ctx);
  frame = requestAnimationFrame(animate);
}


function showAboutInfo() {
  if (!window._originalMenu) {
    window._originalMenu = ul; // keep the live element so we can restore it
  }

  // Switch the whole site into "about mode"
  document.querySelector('main').classList.add('about-mode');

  // Stop the CRT noise drawing
  if (window.frame) {
    cancelAnimationFrame(window.frame);
    window.frame = null;
  }

  // Swap the menu list for your About copy (box styling stays the same)
  const aboutText = document.createElement('div');
  aboutText.className = 'about-text';
  aboutText.innerHTML = `
    <img src="assets/lecat.png" width="200" alt="cat" />
    <p>
      Hello! I'm PingPwn, a CTF player from Greece. Lately I've been focusing on reverse engineering and binary exploitation.
      Feel free to reach out on discord @pingpwn &lt;3
    </p>
    <p><a href="#" data-action="back" title="Back">Back</a></p>
  `;
  ul.parentElement.replaceChild(aboutText, ul);
  window._aboutText = aboutText;
}

function restoreMenu() {
  // Restore the normal background
  document.querySelector('main').classList.remove('about-mode');

  // Bring the CRT noise back
  if (!window.frame) {
    animate();
  }

  // Restore menu list
  if (window._aboutText && window._originalMenu) {
    window._aboutText.parentElement.replaceChild(window._originalMenu, window._aboutText);
    ul = window._originalMenu;
    window._aboutText = null;
    window._originalMenu = null;
  }
}



// Duplicate the “AV-1” spans to keep your visual effect
for (var i = 0; i < 4; i++) {
  var span = text.firstElementChild.cloneNode(true);
  text.appendChild(span);
}

// Boot animation
window.addEventListener('DOMContentLoaded', function () {
  setTimeout(function () {
    main.classList.add('on');
    main.classList.remove('off');
    animate();
  }, 1000);
});

// CLICK-ONLY NAVIGATION (event delegation)
menu.addEventListener('click', function (e) {
  const a = e.target.closest('a');
  if (!a) return;

  const action = a.dataset.action;

  // In-page actions
  if (action === 'about') {
    e.preventDefault();
    showAboutInfo();
    return;
  }
  if (action === 'back') {
    e.preventDefault();
    restoreMenu();
    return;
  }

  // Otherwise let anchors navigate normally.
  // (External links already have target/_blank in HTML.)
}, false);
