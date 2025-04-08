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

    if (key === 50) {
        // Find the active menu item
        var activeItem = ul.children[idx];
        var link = activeItem.querySelector('a');

        if (link && link.href) {
                window.location.href = link.href;
        }
    }
	
	if (key === 49) { // '1' key
        window.location.href = "https://corndogoncorndog.com";
	}

	if (key === 77) { // 'M' key
        menu.classList.remove('hidden');
	}
}, false);