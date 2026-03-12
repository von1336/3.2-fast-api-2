# Домашнее задание 3.2 — FastAPI ч.2

Доработка проекта 3.1: авторизация по токену, пользователи, права.

- POST /login — JSON {username, password}, возвращает токен (срок 48 ч), 401 при неверных данных
- GET /user, GET /user/{user_id}, POST /user, PATCH /user/{user_id}, DELETE /user/{user_id}
- Группы пользователей: user, admin
- Неавторизованный: POST /user, GET /user/{id}, GET /advertisement/{id}, GET /advertisement?...
- user: + PATCH/DELETE себя, POST/PATCH/DELETE своих объявлений
- admin: любые действия. При недостатке прав — 403
