(function() {
    // Здесь предполагается, что переменная pushAuthKeyId есть на странице как global JS (или в data-атрибуте)
    // Если её нет, надо добавить её в шаблон

    function getPushAuthKeyId() {
        // Пример: ищем скрытый input
        var el = document.querySelector('input[name="pushAuthKeyId"]');
        return el ? el.value : null;
    }

    function pollPushStatus() {
        var keyId = getPushAuthKeyId();
        if (!keyId) {
            setTimeout(pollPushStatus, 3000);
            return;
        }
        fetch('/cas/inalogy/check?keyId=' + encodeURIComponent(keyId), {cache: 'no-store'})
            .then(r => r.json())
            .then(data => {
                if (data.status === 'APPROVED') {
                    document.getElementById('push-approve-form').submit();
                } else if (data.status === 'REJECTED') {
                    window.location.href = '/cas/login?pushFailed=true';
                } else if (data.status === 'EXPIRED') {
                    window.location.href = '/cas/login?pushTimeout=true';
                } else {
                    setTimeout(pollPushStatus, 3000);
                }
            })
            .catch(() => setTimeout(pollPushStatus, 3000));
    }

    // Стартуем, когда документ готов
    document.addEventListener('DOMContentLoaded', function() {
        pollPushStatus();
    });
})();