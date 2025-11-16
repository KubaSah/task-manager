// Global app JS (no inline handlers; CSP-friendly)
(function () {
    function ready(fn) {
        if (document.readyState !== 'loading') {
            fn();
        } else {
            document.addEventListener('DOMContentLoaded', fn, { once: true });
        }
    }

    ready(function () {
        var sidebar = document.querySelector('.sidebar');
        var toggleBtn = document.querySelector('.mobile-menu-toggle');

        if (toggleBtn && sidebar) {
            toggleBtn.addEventListener('click', function () {
                sidebar.classList.toggle('open');
            });
        }

        // Auto-close mobile menu when clicking a nav link
        document.querySelectorAll('.sidebar .nav a').forEach(function (link) {
            link.addEventListener('click', function () {
                if (sidebar) sidebar.classList.remove('open');
            });
        });

        // Close menu when clicking overlay area on small screens
        if (sidebar) {
            sidebar.addEventListener('click', function (e) {
                if (e.target === e.currentTarget && window.innerWidth <= 980) {
                    e.currentTarget.classList.remove('open');
                }
            });
        }

        // Handle data-confirm on forms (replaces inline onsubmit="return confirm(...)")
        document.querySelectorAll('form[data-confirm]').forEach(function (form) {
            form.addEventListener('submit', function (e) {
                var msg = form.getAttribute('data-confirm') || 'Czy na pewno?';
                if (!window.confirm(msg)) {
                    e.preventDefault();
                    e.stopPropagation();
                    return false;
                }
                return true;
            });
        });

        // Auto-submit for filters with .auto-submit class (replaces inline onchange="this.form.submit()")
        document.querySelectorAll('.auto-submit').forEach(function (element) {
            element.addEventListener('change', function () {
                this.form.submit();
            });
        });
    });
})();
