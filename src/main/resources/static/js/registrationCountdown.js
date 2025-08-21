(function () {
    document.addEventListener('DOMContentLoaded', function () {
        var countdown = document.getElementById('countdown');
        if (!countdown) return;

        var total = parseInt(countdown.dataset.redirectSeconds || '45', 10) || 45;

        var num = countdown.querySelector('#countdown-number');
        var bar = countdown.querySelector('#countdown-bar');

        var left = total;
        if (num) num.textContent = left;
        if (bar) bar.style.width = '100%';

        var timer = setInterval(function () {
            left = Math.max(0, left - 1);
            if (num) num.textContent = left;
            if (bar) bar.style.width = (total ? (left / total) * 100 : 0) + '%';
            if (left <= 0) clearInterval(timer);
        }, 1000);
    });
})();