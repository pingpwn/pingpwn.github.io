var main = document.querySelector('main'),
	canvas = document.getElementById('canvas'),
	ctx = canvas.getContext('2d'),
	text = document.querySelector('.text'),
	ww = window.innerWidth,
	menu = document.querySelector('.menu'),
	ul = menu.querySelector('ul'),
	idx = 0,
	count = ul.childElementCount - 1,
	toggle = true,
	frame;

// Set canvas size
canvas.width = ww / 3;
canvas.height = (ww * 0.5625) / 3;


const originalMenu = ul.cloneNode(true); // Deep copy the menu

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
};


function showAboutInfo() {
	const aboutText = document.createElement('div');
	window._originalMenu = originalMenu;
    aboutText.className = 'about-text'; 
    aboutText.innerHTML = `
        <img src="assets/lecat.png" width="200" >
		<p>
            Hello! 
			I'm PingPwn, a CTF player exploring weird machines. Lately I've been focusing on reverse engineering and binary exploitation. Feel free to reach out on discord @pingpwn <3
        </p>
    `;
	window._originalMenu = ul.cloneNode(true);
    const footer = document.querySelector('footer');
    const keys = footer.querySelectorAll('.key');
    window._originalKey = keys[0].cloneNode(true);

    
    const backKey = document.createElement('div');
    backKey.className = 'key';
    backKey.innerHTML = `Back: <span>1</span>`;

	keys[0].replaceWith(backKey);
    
	window._backKey = backKey;

    ul.parentElement.replaceChild(aboutText, ul);
    window._aboutText = aboutText;
}


// Glitch
for (i = 0; i < 4; i++) {
	var span = text.firstElementChild.cloneNode(true);
	text.appendChild(span);
}

window.addEventListener('DOMContentLoaded', function(e) {
	setTimeout(function() {
		main.classList.add('on');
		main.classList.remove('off');
		animate();
	}, 1000);
});

window.addEventListener('keydown', function(e) {
	if (e.key === '1' && window._aboutText && window._originalMenu) {
		e.preventDefault();
	
		// Restore menu
		window._aboutText.parentElement.replaceChild(window._originalMenu, window._aboutText);
		ul = window._originalMenu;
		window._aboutText = null;
		window._originalMenu = null;
	
		// Restore footer key
		if (window._originalKey && window._backKey) {
			window._backKey.replaceWith(window._originalKey);
			window._originalKey = null;
			window._backKey = null;
		}
	
		// Rebind menu navigation
		rebindMenuEvents();
	}
	


	var key = e.keyCode;
	var prev = idx;
	if (key == 38 || key == 40) {
		e.preventDefault();

		switch (key) {
			case 38:
				if (idx > 0) {
					idx--;
				}
				break;
			case 40:
				if (idx < count) {
					idx++;
				}
				break;
		}

		ul.children[prev].classList.remove('active');
		ul.children[idx].classList.add('active');
	}

    if (key === 49) {
        // Find the active menu item
        var activeItem = ul.children[idx];
        var link = activeItem.querySelector('a');

        if (link) {
			const href = link.getAttribute("href");
			
			// If it's the 'About' item (which has href="")
			if (href === "" || href === "#") {
				showAboutInfo();
			} else {
				window.location.href = link.href;
			}
		}
		
    }
	
	if (key === 50) { // '1' key
        window.location.href = "https://ckjcwf.ytmnd.com/";
	}

	if (key === 77) { // 'M' key
        menu.classList.remove('hidden');
	}
}, false);