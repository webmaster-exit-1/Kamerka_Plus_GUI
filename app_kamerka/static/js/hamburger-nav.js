(function() {
    function setMenuState(button, overlay, isOpen) {
        overlay.classList.toggle('open', isOpen);
        overlay.hidden = !isOpen;
        button.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        button.innerHTML = isOpen ? '&times;' : '&#9776;';
    }

    document.addEventListener('DOMContentLoaded', function() {
        var button = document.getElementById('kamerka-hamburger-btn');
        var overlay = document.getElementById('kamerka-hamburger-overlay');
        if (!button || !overlay) {
            return;
        }

        setMenuState(button, overlay, false);

        button.addEventListener('click', function(event) {
            event.stopPropagation();
            setMenuState(button, overlay, overlay.hidden);
        });

        overlay.addEventListener('click', function(event) {
            event.stopPropagation();
        });

        document.addEventListener('click', function(event) {
            if (!overlay.hidden && !overlay.contains(event.target) && event.target !== button) {
                setMenuState(button, overlay, false);
            }
        });

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape' && !overlay.hidden) {
                setMenuState(button, overlay, false);
                button.focus();
            }
        });

        overlay.querySelectorAll('a').forEach(function(link) {
            link.addEventListener('click', function() {
                setMenuState(button, overlay, false);
            });
        });
    });
})();
