(function () {
    function getPushAuthPushId() {
        const el = document.querySelector('input[name="pushAuthPushId"]');
        return el ? el.value : null;
    }

    function pollPushStatus() {
        const pushId = getPushAuthPushId();
        if (!pushId) {
            setTimeout(pollPushStatus, 2200);
            return;
        }
        fetch('/cas/inalogy/check/login?pushId=' + encodeURIComponent(pushId), {cache: 'no-store'})
            .then(r => r.json())
            .then(data => {
                if (data.status === 'APPROVED') {
                    document.getElementById('push-approve-form').submit();
                } else if (data.status === 'REJECTED') {
                    window.location.href = '/cas/login';
                } else if (data.status === 'EXPIRED') {
                    window.location.href = '/cas/login';
                } else {
                    setTimeout(pollPushStatus, 2200);
                }
            })
            .catch(() => setTimeout(pollPushStatus, 2200));
    }

    document.addEventListener('DOMContentLoaded', function () {
        const formEl = document.getElementById('countdown');
        const timeoutSec = formEl ? parseInt(formEl.dataset.redirectSeconds || '45', 10) : 45;

        setTimeout(() => { window.location.href = '/cas/login'; }, timeoutSec * 1000);

        pollPushStatus();
    });
})();