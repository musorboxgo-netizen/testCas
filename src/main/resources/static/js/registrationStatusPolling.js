(function() {
    function getPushRegRequestId() {
        const el = document.querySelector('input[name="regRequestId"]');
        return el ? el.value : null;
    }

    function pollRegStatus() {
        const requestId = getPushRegRequestId();
        if (!requestId) {
            setTimeout(pollRegStatus, 2200);
            return;
        }
        fetch('/cas/inalogy/check/registration?requestId=' + encodeURIComponent(requestId), {cache: 'no-store'})
            .then(r => r.json())
            .then(data => {
                if (data.status === 'REGISTERED') {
                    document.getElementById('registration-form').submit();
                } else if (data.status === 'REJECTED') {
                    window.location.href = '/cas/login';
                } else if (data.status === 'EXPIRED') {
                    window.location.href = '/cas/login';
                } else {
                    setTimeout(pollRegStatus, 2200);
                }
            })
            .catch(() => setTimeout(pollRegStatus, 2200));
    }

    document.addEventListener('DOMContentLoaded', function() {
        const formEl = document.getElementById('countdown');
        const timeoutSec = formEl ? parseInt(formEl.dataset.redirectSeconds || '45', 10) : 45;

        setTimeout(() => { window.location.href = '/cas/login'; }, timeoutSec * 1000);

        pollRegStatus();
    });
})();