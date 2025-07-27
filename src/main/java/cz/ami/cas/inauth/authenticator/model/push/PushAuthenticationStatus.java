package cz.ami.cas.inauth.authenticator.model.push;

public enum PushAuthenticationStatus {
    PENDING,    // Ожидает ответа
    APPROVED,   // Одобрено
    REJECTED,   // Отклонено
    EXPIRED,    // Истек срок действия
    NOT_FOUND   // Запрос не найден
}
